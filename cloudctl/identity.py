from .store import one,many,event
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
    return event(db,'issue',r['id'],'issued',{'generation':r['generation']})
def revoke(db,r):
    cert=one(db,'SELECT * FROM certificates WHERE id=?',(r['id'],))
    if not cert:return event(db,'revoke',r['id'],'missing',{})
    db.execute('UPDATE certificates SET status=? WHERE id=?',('revoked',r['id']))
    return event(db,'revoke',r['id'],'revoked',{'generation':cert['generation']})
def replica(db,r):
    identity=one(db,'SELECT * FROM identities WHERE id=?',(r['identity'],))
    cert=one(db,'SELECT * FROM certificates WHERE id=?',(r['cert'],))
    if not identity or not cert or cert['identity']!=r['identity']:
        return event(db,'replica',r['id'],'identity_mismatch',{})
    db.execute('INSERT OR REPLACE INTO replicas VALUES(?,?,?,?)',(r['id'],r['identity'],int(r['active']),r['cert']))
    return event(db,'replica',r['id'],'active' if r['active'] else 'stopped',{})
def retire(db,r):
    identity=one(db,'SELECT * FROM identities WHERE id=?',(r['identity'],))
    if not identity:return event(db,'retire',r['identity'],'missing',{})
    active=many(db,'SELECT id FROM replicas WHERE identity=? AND active=1',(r['identity'],))
    calls=many(db,'SELECT id FROM handshakes WHERE (caller=? OR callee=?) AND status=?',(r['identity'],r['identity'],'open'))
    if active or calls:return event(db,'retire',r['identity'],'blocked',{'replicas':active,'calls':calls})
    db.execute('INSERT OR REPLACE INTO retirements VALUES(?,?,?)',(r['identity'],r['at'],r['reason']))
    db.execute('UPDATE identities SET status=? WHERE id=?',('retired',r['identity']))
    return event(db,'retire',r['identity'],'retired',{})
