from .store import one,many,event
from . import hardware_custody as hw
def inspect(db,r):
    service=r['service'];at=r['at']
    identities=many(db,'SELECT id FROM identities WHERE service=? AND status=?',(service,'active'))
    replicas=[rep for ident in identities for rep in many(db,'SELECT * FROM replicas WHERE identity=? AND active=1',(ident['id'],))]
    invalid=[];hardware_blocks={}
    for rep in replicas:
        cert=one(db,'SELECT * FROM certificates WHERE id=?',(rep['cert'],))
        if not cert or cert['status']!='active' or not cert['not_before']<=at<cert['expires']:
            invalid.append(rep['id'])
        block=hw.hardware_block_for_replica(db,rep['id'],at)
        if block:hardware_blocks[rep['id']]=block
    open_calls=many(db,"""SELECT h.id FROM handshakes h WHERE h.status='open' AND
                          (h.caller IN (SELECT id FROM identities WHERE service=?) OR
                           h.callee IN (SELECT id FROM identities WHERE service=?))""",(service,service))
    holds=many(db,"SELECT scope,ref,reason,batch_id FROM hw_quarantines WHERE status='active'")
    active_ids={x['id'] for x in replicas}
    active_chassis={one(db,'SELECT chassis_id FROM replica_hardware WHERE replica=?',(x['id'],))['chassis_id']
                    for x in replicas if one(db,'SELECT chassis_id FROM replica_hardware WHERE replica=?',(x['id'],))}
    risk_holds=[h for h in holds if (h['scope']=='replica' and h['ref'] in active_ids)
                or (h['scope']=='chassis' and h['ref'] in active_chassis)]
    dirty_modules=many(db,"""SELECT m.serial,m.chassis_id,m.replica_id,m.status,m.batch_id
                             FROM hw_modules m JOIN hw_batches b ON b.id=m.batch_id
                             WHERE b.status='confirmed' AND m.status NOT IN ('destroyed','vendor_disposed','returned_to_vendor','replaced_clean','vendor_received')
                               AND COALESCE(m.clean_source,0)=0""")
    decision='unavailable' if not replicas else 'at_risk' if invalid or hardware_blocks or risk_holds else 'healthy'
    return event(db,'audit',service,decision,{
        'replicas':[x['id'] for x in replicas],'invalid':invalid,
        'hardware_blocks':hardware_blocks,'active_holds':holds,'service_affecting_holds':risk_holds,
        'recalled_modules_in_production':dirty_modules,
        'open_calls':[x['id'] for x in open_calls]})
