"""Broker progress record and consumer-group generation fence.

Offset progress stays independent of the worker output transaction, but
a checkpoint may only move over results this group has actually
verified.  Partition ownership carries a generation: once a newer agent
takes over, every write or checkpoint carrying an older generation is
rejected, so an old agent recovering from a timeout pause cannot change
instance results, network mounts or offsets any more.
"""
from . import message_intake as intake
from . import message_result as result

class FenceViolation(ValueError):
    pass

def ensure_schema(db):
    db.execute('CREATE TABLE IF NOT EXISTS offset_checkpoints (group_id TEXT,stream TEXT,partition_id INTEGER,offset_id INTEGER,epoch INTEGER,PRIMARY KEY(group_id,stream,partition_id))')
    db.execute('CREATE TABLE IF NOT EXISTS group_leases (group_id TEXT,stream TEXT,partition_id INTEGER,owner TEXT,epoch INTEGER,valid_until INTEGER,PRIMARY KEY(group_id,stream,partition_id))')

def take_partitions(db,group,stream,partitions,owner,epoch,valid_until):
    """Atomically take a set of partitions at a strictly higher generation."""
    ensure_schema(db)
    claimed=[]
    for partition in partitions:
        old=db.execute('SELECT owner,epoch FROM group_leases WHERE group_id=? AND stream=? AND partition_id=?',
                       (group,stream,partition)).fetchone()
        if old and epoch<old[1]:
            raise FenceViolation('stale_generation')
        if old and epoch==old[1]:
            claimed.append({'stream':stream,'partition':partition,'owner':old[0],'epoch':epoch,'replayed':True})
            continue
        claimed.append({'stream':stream,'partition':partition,'owner':owner,'epoch':epoch,'replayed':False})
    with db:
        for claim in claimed:
            db.execute('INSERT INTO group_leases VALUES (?,?,?,?,?,?) ON CONFLICT(group_id,stream,partition_id) DO UPDATE SET owner=excluded.owner,epoch=excluded.epoch,valid_until=excluded.valid_until',
                       (group,stream,claim['partition'],claim['owner'],epoch,valid_until))
    return claimed

def current_owner(db,group,stream,partition):
    ensure_schema(db)
    r=db.execute('SELECT owner,epoch,valid_until FROM group_leases WHERE group_id=? AND stream=? AND partition_id=?',
                 (group,stream,partition)).fetchone()
    if not r:return None
    return {'owner':r[0],'epoch':r[1],'valid_until':r[2]}

def require_fence(db,group,stream,partition,epoch,at=None):
    owner=current_owner(db,group,stream,partition)
    if not owner:raise FenceViolation('partition_not_owned')
    if epoch!=owner['epoch']:raise FenceViolation('stale_generation')
    if at is not None and owner['valid_until'] is not None and at>owner['valid_until']:
        raise FenceViolation('lease_expired')
    return owner

def expire_lease(db,group,stream,partition,at):
    ensure_schema(db)
    owner=current_owner(db,group,stream,partition)
    if not owner or owner['valid_until'] is None or at<owner['valid_until']:return False
    with db:
        # Mark the boundary as expired by pinning it below the current instant;
        # any fence check at/after expiry then fails on the time comparison.
        db.execute('UPDATE group_leases SET valid_until=? WHERE group_id=? AND stream=? AND partition_id=?',
                   (at-1,group,stream,partition))
    return True

def _verified_span(db,stream,partition,cur_offset,target):
    """Every offset up to the target must have intake and a stored result."""
    start=cur_offset+1
    for off in range(start,target+1):
        row=intake.locate(db,stream,partition,off)
        if not row:raise ValueError('offset_gap')
        if not result.get_result(db,intake.version_ref(row)):
            raise ValueError('unverified_offset')

def acknowledge(db,group,stream,partition,offset,epoch,verify=False,at=None):
    ensure_schema(db)
    old=db.execute('SELECT offset_id,epoch FROM offset_checkpoints WHERE group_id=? AND stream=? AND partition_id=?',
                   (group,stream,partition)).fetchone()
    cur=old[0] if old else -1
    owner=current_owner(db,group,stream,partition)
    if owner is not None:
        # A group that has taken this partition is fenced; unmanaged legacy
        # callers (no lease row yet) keep the original behavior.  Generation
        # staleness is rejected first so a late old agent can never progress
        # offsets even when the offset number itself is monotonic.
        if epoch!=owner['epoch']:raise FenceViolation('stale_generation')
        if at is not None and owner['valid_until'] is not None and at>owner['valid_until']:
            raise FenceViolation('lease_expired')
    if old and (epoch<old[1] or offset<cur):raise ValueError('stale_checkpoint')
    if verify:
        _verified_span(db,stream,partition,cur,offset)
    with db:
        db.execute('INSERT INTO offset_checkpoints VALUES (?,?,?,?,?) ON CONFLICT(group_id,stream,partition_id) DO UPDATE SET offset_id=excluded.offset_id,epoch=excluded.epoch',
                   (group,stream,partition,offset,epoch))
    return {'group':group,'stream':stream,'partition':partition,'offset':offset,'epoch':epoch}

def checkpoint(db,group,stream,partition):
    ensure_schema(db)
    r=db.execute('SELECT offset_id,epoch FROM offset_checkpoints WHERE group_id=? AND stream=? AND partition_id=?',
                 (group,stream,partition)).fetchone()
    return {'offset':r[0],'epoch':r[1]} if r else {'offset':-1,'epoch':None}
