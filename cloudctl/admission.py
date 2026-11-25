import json
from .store import one,many,event
def authorize(db,r):
    if r['expires']<=r['at']:return event(db,'authorize',r['caller'],'invalid_window',{})
    db.execute('INSERT OR REPLACE INTO call_policies VALUES(?,?,?,?)',(r['caller'],r['callee'],r['purpose'],r['expires']))
    return event(db,'authorize',r['caller'],'authorized',{'callee':r['callee'],'purpose':r['purpose']})
def handshake(db,r):
    old=one(db,'SELECT * FROM handshakes WHERE id=?',(r['id'],))
    if old:return event(db,'handshake',r['id'],'idempotent',{'old':old['status']})
    caller=one(db,'SELECT * FROM certificates WHERE id=?',(r['caller_cert'],))
    callee=one(db,'SELECT * FROM certificates WHERE id=?',(r['callee_cert'],))
    bundle=one(db,'SELECT * FROM bundles WHERE id=? AND status=?',(r['bundle'],'active'))
    reason='allowed'
    if not caller or not callee or not bundle:reason='missing_trust'
    elif not (bundle['start']<=r['at']<bundle['expires']):reason='bundle_outside_window'
    elif caller['status']!='active' or callee['status']!='active':reason='revoked'
    elif not (caller['not_before']<=r['at']<caller['expires'] and callee['not_before']<=r['at']<callee['expires']):reason='expired'
    elif caller['root'] not in json.loads(bundle['roots']) or callee['root'] not in json.loads(bundle['roots']):reason='untrusted_root'
    elif not one(db,'SELECT * FROM call_policies WHERE caller=? AND callee=? AND purpose=? AND expires>?',(caller['identity'],callee['identity'],r['purpose'],r['at'])):reason='no_call_policy'
    else:
        caller_rep=one(db,'SELECT id FROM replicas WHERE id=? AND cert=? AND active=1',(r['caller_replica'],r['caller_cert']))
        callee_rep=one(db,'SELECT id FROM replicas WHERE id=? AND cert=? AND active=1',(r['callee_replica'],r['callee_cert']))
        if not caller_rep or not callee_rep:reason='replica_mismatch'
        elif not one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=? AND generation=? AND status=? AND at<=?',(r['bundle'],r['caller_replica'],caller['generation'],'confirmed',r['at'])) or not one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=? AND generation=? AND status=? AND at<=?',(r['bundle'],r['callee_replica'],callee['generation'],'confirmed',r['at'])):reason='unconfirmed_bundle'
    db.execute('INSERT INTO handshakes VALUES(?,?,?,?,?,?)',(r['id'],caller['identity'] if caller else '',callee['identity'] if callee else '',r['at'],'open' if reason=='allowed' else 'denied',reason))
    db.execute('INSERT INTO admissions VALUES(?,?,?,?)',(r['id'],r['id'],reason,r['at']))
    return event(db,'handshake',r['id'],reason,{'bundle':r['bundle'],'at':r['at']})
def close(db,r):
    call=one(db,'SELECT * FROM handshakes WHERE id=?',(r['id'],))
    if not call:return event(db,'close',r['id'],'missing',{})
    db.execute('UPDATE handshakes SET status=? WHERE id=?',('closed',r['id']))
    return event(db,'close',r['id'],'closed',{})
def expiry(db,r):
    replicas=many(db,'SELECT r.id,c.expires FROM replicas r JOIN certificates c ON c.id=r.cert WHERE r.active=1')
    at_risk=[x['id'] for x in replicas if x['expires']<=r['at']+r['horizon']]
    return event(db,'expiry',r['service'],'at_risk' if at_risk else 'healthy',{'replicas':at_risk})
