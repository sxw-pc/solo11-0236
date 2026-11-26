from .store import one,many,event
from . import hardware_custody as hw

def _at(r):
    try:return int(r.get('at',0) or 0)
    except (TypeError,ValueError):return 0

def bind(db,r):
    if not r['id'].startswith(r['namespace']+'/'):
        return event(db,'bind',r['id'],'wrong_namespace',{})
    old=one(db,'SELECT * FROM identities WHERE id=?',(r['id'],))
    if old:return event(db,'bind',r['id'],'idempotent' if old['service']==r['service'] else 'conflict',{})
    db.execute('INSERT INTO identities VALUES(?,?,?,?)',(r['id'],r['namespace'],r['service'],'active'))
    return event(db,'bind',r['id'],'bound',{})
def issue(db,r):
    identity=one(db,'SELECT * FROM identities WHERE id=?',(r['identity'],))
    if not identity or identity['status']!='active':return event(db,'issue',r['id'],'identity_unavailable',{})
    if r['not_before']>=r['expires']:return event(db,'issue',r['id'],'invalid_window',{})
    old=one(db,'SELECT * FROM certificates WHERE id=?',(r['id'],))
    if old:return event(db,'issue',r['id'],'idempotent' if old['identity']==r['identity'] else 'conflict',{})
    latest=one(db,'SELECT MAX(generation) g FROM certificates WHERE identity=?',(r['identity'],))['g'] or 0
    if r['generation']!=latest+1:return event(db,'issue',r['id'],'wrong_generation',{'expected':latest+1})
    db.execute('INSERT INTO certificates VALUES(?,?,?,?,?,?,?)',(r['id'],r['identity'],r['generation'],r['root'],r['not_before'],r['expires'],'active'))
    serial=hw.pick(r,'module_serial','serial','module','hardware_serial')
    fp=hw.pick(r,'key_fingerprint','fingerprint','public_key_fingerprint','key_id')
    if serial or fp:
        hw.bind_certificate(db,r['id'],serial,fp,'identity.issue',_at(r),r['identity'],hw._evidence(r))
    return event(db,'issue',r['id'],'issued',{'generation':r['generation']})
def revoke(db,r):
    cert=one(db,'SELECT * FROM certificates WHERE id=?',(r['id'],))
    if not cert:return event(db,'revoke',r['id'],'missing',{})
    if cert['status']=='revoked':
        # Preserve the historical decision vocabulary while making replays
        # observable; revocation itself remains a stable terminal state.
        return event(db,'revoke',r['id'],'revoked',{'generation':cert['generation'],'already_revoked':True})
    db.execute('UPDATE certificates SET status=? WHERE id=?',('revoked',r['id']))
    return event(db,'revoke',r['id'],'revoked',{'generation':cert['generation']})
def replica(db,r):
    identity=one(db,'SELECT * FROM identities WHERE id=?',(r['identity'],))
    cert=one(db,'SELECT * FROM certificates WHERE id=?',(r['cert'],))
    if not identity or not cert or cert['identity']!=r['identity']:
        return event(db,'replica',r['id'],'identity_mismatch',{})
    at=_at(r)
    previous=one(db,'SELECT cert,active FROM replicas WHERE id=?',(r['id'],))
    db.execute('INSERT OR REPLACE INTO replicas VALUES(?,?,?,?)',(r['id'],r['identity'],int(r['active']),r['cert']))
    # Preserve every certificate that actually served this logical replica.
    # The replicas row itself is overwritten by design, so recall key revocation
    # must not depend on reading only its current value.
    latest_hist=one(db,'SELECT cert,active FROM replica_history WHERE replica=? ORDER BY seq DESC LIMIT 1',(r['id'],))
    if not latest_hist or latest_hist['cert']!=r['cert'] or int(latest_hist['active'])!=int(r['active']):
        db.execute('INSERT INTO replica_history(replica,identity,cert,active,at,kind,evidence) VALUES(?,?,?,?,?,?,?)',
                   (r['id'],r['identity'],r['cert'],int(r['active']),at,'replica_write',
                    __import__('json').dumps(hw._evidence(r),sort_keys=True,ensure_ascii=False,default=str)))
    hw.record_replica_binding(db,r['id'],r['identity'],r['cert'],int(r['active']),at,r)
    warning=hw.hardware_block_for_replica(db,r['id'],at) if int(r['active']) else None
    ev={}
    if warning:ev['hardware_warning']=warning
    return event(db,'replica',r['id'],'active' if r['active'] else 'stopped',ev)
def retire(db,r):
    identity=one(db,'SELECT * FROM identities WHERE id=?',(r['identity'],))
    if not identity:return event(db,'retire',r['identity'],'missing',{})
    active=many(db,'SELECT id FROM replicas WHERE identity=? AND active=1',(r['identity'],))
    calls=many(db,'SELECT id FROM handshakes WHERE (caller=? OR callee=?) AND status=?',(r['identity'],r['identity'],'open'))
    if active or calls:return event(db,'retire',r['identity'],'blocked',{'replicas':active,'calls':calls})
    db.execute('INSERT OR REPLACE INTO retirements VALUES(?,?,?)',(r['identity'],r['at'],r['reason']))
    db.execute('UPDATE identities SET status=? WHERE id=?',('retired',r['identity']))
    return event(db,'retire',r['identity'],'retired',{})
