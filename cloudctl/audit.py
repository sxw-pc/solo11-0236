from .store import one,many,event
from . import physical_erasure as pe
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
    # retired identities still carry data-custody obligations that the control plane must be able to account for
    custody=[]
    for ident in many(db,'SELECT id FROM identities WHERE service=? AND status=?',(service,'retired')):
        case=one(db,'SELECT * FROM custody_cases WHERE identity=?',(ident['id'],))
        if not case:continue
        tenants=pe.tenant_status(db,ident['id'],at)
        custody.append({'identity':ident['id'],'state':case['state'],'mode':case['mode'],
                        'recoverable_controllers':sorted({c for t in tenants.values() for c in t['controllers_of_recoverable_copies']}),
                        'irrecoverable_customer_data':sorted({o for t in tenants.values() for o in t['irrecoverable_objects']}),
                        'court_deliveries':[d['id'] for d in many(db,'SELECT id FROM court_deliveries WHERE identity=?',(ident['id'],))],
                        'certificates':[c['id'] for c in many(db,'SELECT id FROM destruction_certificates WHERE identity=?',(ident['id'],))],
                        'quarantined_copies':pe.quarantined_copies(db,ident['id'])})
    return event(db,'audit',service,decision,{'replicas':[x['id'] for x in replicas],'invalid':invalid,'open_calls':[x['id'] for x in open_calls],'custody':custody})
