"""Worker output path.

Results are keyed by the *message version* (tenant, stream, partition,
offset, producer sequence and digest), never by the display business
key: the same key may legitimately exist in another tenant or stream.
Writes are fenced by the consumer-group generation so an agent that
lost the partition (even after a pause) cannot publish instance or
network results any more.  Already-persisted real results are reused
on redelivery instead of re-running the external action.
"""
import json
from . import message_intake as intake
from .offset_checkpoint import require_fence

class ResultConflict(ValueError):
    pass

def ensure_schema(db):
    intake.ensure_schema(db)
    db.execute('CREATE TABLE IF NOT EXISTS message_results (tenant TEXT,stream TEXT,partition_id INTEGER,offset_id INTEGER,producer TEXT,sequence_id INTEGER,digest TEXT,business_key TEXT,worker TEXT,epoch INTEGER,result TEXT,PRIMARY KEY(tenant,stream,partition_id,offset_id))')
    cols={r[1] for r in db.execute('PRAGMA table_info(message_results)')}
    # Legacy tables were keyed by business_key and lack the version identity
    # columns (tenant/producer/digest); rebuild them against intake versions.
    if {'tenant','producer','digest'} - cols:
        db.execute('ALTER TABLE message_results RENAME TO message_results_legacy')
        db.execute('CREATE TABLE message_results (tenant TEXT,stream TEXT,partition_id INTEGER,offset_id INTEGER,producer TEXT,sequence_id INTEGER,digest TEXT,business_key TEXT,worker TEXT,epoch INTEGER,result TEXT,PRIMARY KEY(tenant,stream,partition_id,offset_id))')
        for old in db.execute('SELECT stream,partition_id,offset_id,business_key,worker,epoch,result FROM message_results_legacy'):
            row=intake.locate(db,old[0],old[1],old[2])
            db.execute('INSERT INTO message_results VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                       (row['tenant'] if row else None,old[0],old[1],old[2],
                        row['producer'] if row else None,row['sequence_id'] if row else None,
                        row['digest'] if row else None,old[3],old[4],old[5],old[6]))
        db.execute('DROP TABLE message_results_legacy')

def _output(row):
    return {'key':row['business_key'],'parent':row['parent_key'],
            'value':json.loads(row['payload']).get('value')}

def _found(db,row):
    f=db.execute('SELECT result FROM message_results WHERE tenant IS ? AND stream=? AND partition_id=? AND offset_id=?',
                 (row['tenant'],row['stream'],row['partition_id'],row['offset_id'])).fetchone()
    return f[0] if f else None

def store_result(db,row,worker,epoch,group=None,at=None):
    """Persist a result for an intake row, reusing an identical prior one."""
    ensure_schema(db)
    if group is not None:
        require_fence(db,group,row['stream'],row['partition_id'],epoch,at)
    output=_output(row)
    encoded=json.dumps(output,sort_keys=True)
    existing=_found(db,row)
    if existing is not None:
        if existing!=encoded:raise ResultConflict('result_conflict')
        return 'replayed'
    with db:
        db.execute('INSERT INTO message_results VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                   (row['tenant'],row['stream'],row['partition_id'],row['offset_id'],
                    row['producer'],row['sequence_id'],row['digest'],row['business_key'],
                    worker,epoch,encoded))
    return 'finished'

def finish(db,stream,partition,offset,worker,epoch,group=None,tenant=None,at=None):
    ensure_schema(db)
    row=intake.locate(db,stream,partition,offset,tenant)
    if not row:raise ValueError('missing_intake')
    return store_result(db,row,worker,epoch,group,at)

def get_result(db,ref):
    """Result lookup by concrete message version (the only safe lookup)."""
    ensure_schema(db)
    ref=intake.as_ref(ref)
    r=db.execute('SELECT business_key,worker,epoch,result FROM message_results WHERE tenant IS ? AND stream=? AND partition_id=? AND offset_id=? AND producer=? AND sequence_id=? AND digest=?',
                 (ref['tenant'],ref['stream'],ref['partition'],ref['offset'],ref['producer'],ref['sequence'],ref['digest'])).fetchone()
    if not r:return None
    return {'business_key':r[0],'worker':r[1],'epoch':r[2],'result':json.loads(r[3])}

def find_by_key(db,business_key,tenant=None,stream=None):
    """All results carrying a display key; the key alone is not identity."""
    ensure_schema(db)
    q='SELECT tenant,stream,partition_id,offset_id,producer,sequence_id,digest,business_key,worker,epoch,result FROM message_results WHERE business_key=?'
    a=[business_key]
    if tenant is not None:q+=' AND tenant=?';a.append(tenant)
    if stream is not None:q+=' AND stream=?';a.append(stream)
    return [{'tenant':r[0],'stream':r[1],'partition':r[2],'offset':r[3],
             'producer':r[4],'sequence':r[5],'digest':r[6],'business_key':r[7],
             'worker':r[8],'epoch':r[9],'result':json.loads(r[10])}
            for r in db.execute(q,a)]
