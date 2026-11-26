from .store import one,many,event,append_checkpoint,quarantined,unsealed_issue_blocker
def bind(db,r):
    if not r['id'].startswith(r['namespace']+'/'):
        return event(db,'bind',r['id'],'wrong_namespace',{})
    old=one(db,'SELECT * FROM identities WHERE id=?',(r['id'],))
    if old:return event(db,'bind',r['id'],'idempotent' if old['service']==r['service'] else 'conflict',{})
    db.execute('INSERT INTO identities VALUES(?,?,?,?)',(r['id'],r['namespace'],r['service'],'active'))
    return event(db,'bind',r['id'],'bound',{})
def issue(db,r):
    if quarantined(db,[r['identity']]):return event(db,'issue',r['id'],'quarantined',{})
    identity=one(db,'SELECT * FROM identities WHERE id=?',(r['identity'],))
    if not identity or identity['status']!='active':return event(db,'issue',r['id'],'identity_unavailable',{})
    if r['not_before']>=r['expires']:return event(db,'issue',r['id'],'invalid_window',{})
    old=one(db,'SELECT * FROM certificates WHERE id=?',(r['id'],))
    if old:return event(db,'issue',r['id'],'idempotent' if old['identity']==r['identity'] else 'conflict',{})
    latest=one(db,'SELECT MAX(generation) g FROM certificates WHERE identity=?',(r['identity'],))['g'] or 0
    if r['generation']!=latest+1:return event(db,'issue',r['id'],'wrong_generation',{'expected':latest+1})
    db.execute('INSERT INTO certificates VALUES(?,?,?,?,?,?,?)',(r['id'],r['identity'],r['generation'],r['root'],r['not_before'],r['expires'],'active'))
    ev=event(db,'issue',r['id'],'issued',{'identity':r['identity'],'generation':r['generation'],'root':r['root'],'not_before':r['not_before'],'expires':r['expires']})
    cp=append_checkpoint(db,r['identity'],'issue',r['id'],ev['evidence'],ev['seq'])
    ev['checkpoint']={'subject':r['identity'],'num':cp['num'],'digest':cp['digest']}
    return ev
def revoke(db,r):
    cert=one(db,'SELECT * FROM certificates WHERE id=?',(r['id'],))
    if not cert:return event(db,'revoke',r['id'],'missing',{})
    identity=cert['identity']
    if quarantined(db,[identity]):return event(db,'revoke',r['id'],'quarantined',{})
    blocker=unsealed_issue_blocker(db,identity,cert['generation'])
    if blocker:
        # Keep the original certificate state untouched and name the blocking predecessor.
        return event(db,'revoke',r['id'],'unsealed_issuance_block',{'blocking_checkpoint':blocker,'cert_status':cert['status']})
    db.execute('UPDATE certificates SET status=? WHERE id=?',('revoked',r['id']))
    ev=event(db,'revoke',r['id'],'revoked',{'identity':identity,'generation':cert['generation']})
    cp=append_checkpoint(db,identity,'revoke',r['id'],ev['evidence'],ev['seq'])
    ev['checkpoint']={'subject':identity,'num':cp['num'],'digest':cp['digest']}
    return ev
def replica(db,r):
    if quarantined(db,[r['identity']]):return event(db,'replica',r['id'],'quarantined',{})
    identity=one(db,'SELECT * FROM identities WHERE id=?',(r['identity'],))
    cert=one(db,'SELECT * FROM certificates WHERE id=?',(r['cert'],))
    if not identity or not cert or cert['identity']!=r['identity']:
        return event(db,'replica',r['id'],'identity_mismatch',{})
    previous=one(db,'SELECT * FROM replicas WHERE id=?',(r['id'],))
    same_state=bool(previous and previous['cert']==r['cert'] and bool(previous['active'])==bool(r['active']))
    db.execute('INSERT OR REPLACE INTO replicas VALUES(?,?,?,?)',(r['id'],r['identity'],int(r['active']),r['cert']))
    ev=event(db,'replica',r['id'],'active' if r['active'] else 'stopped',{})
    if same_state:
        # Repeated identical replica line: no new generation is held, so no checkpoint.
        ev['evidence']={'idempotent':True}
        return ev
    ev['evidence']={'identity':r['identity'],'cert':r['cert'],'active':int(bool(r['active'])),'previous_cert':previous['cert'] if previous else None}
    cp=append_checkpoint(db,r['identity'],'replica',r['id'],ev['evidence'],ev['seq'])
    ev['checkpoint']={'subject':r['identity'],'num':cp['num'],'digest':cp['digest']}
    return ev
def retire(db,r):
    identity=one(db,'SELECT * FROM identities WHERE id=?',(r['identity'],))
    if not identity:return event(db,'retire',r['identity'],'missing',{})
    active=many(db,'SELECT id FROM replicas WHERE identity=? AND active=1',(r['identity'],))
    calls=many(db,'SELECT id FROM handshakes WHERE (caller=? OR callee=?) AND status=?',(r['identity'],r['identity'],'open'))
    if active or calls:return event(db,'retire',r['identity'],'blocked',{'replicas':active,'calls':calls})
    db.execute('INSERT OR REPLACE INTO retirements VALUES(?,?,?)',(r['identity'],r['at'],r['reason']))
    db.execute('UPDATE identities SET status=? WHERE id=?',('retired',r['identity']))
    return event(db,'retire',r['identity'],'retired',{})
