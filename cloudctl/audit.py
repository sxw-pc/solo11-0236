from .store import one,many,event
def inspect(db,r):
    service=r['service'];at=r['at']
    identities=many(db,'SELECT id FROM identities WHERE service=? AND status=?',(service,'active'))
    replicas=[rep for ident in identities for rep in many(db,'SELECT * FROM replicas WHERE identity=? AND active=1',(ident['id'],))]
    invalid=[]
    for rep in replicas:
        cert=one(db,'SELECT * FROM certificates WHERE id=?',(rep['cert'],))
        if not cert or cert['status']!='active' or not cert['not_before']<=at<cert['expires']:
            invalid.append(rep['id'])
    open_calls=many(db,'SELECT id FROM handshakes WHERE status=? AND (caller IN (SELECT id FROM identities WHERE service=?) OR callee IN (SELECT id FROM identities WHERE service=?))',('open',service,service))
    decision='unavailable' if not replicas else 'at_risk' if invalid else 'healthy'
    return event(db,'audit',service,decision,{'replicas':[x['id'] for x in replicas],'invalid':invalid,'open_calls':[x['id'] for x in open_calls]})
