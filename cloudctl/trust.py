import json
from .store import one,many,event
def publish(db,r):
    if r['start']>=r['expires'] or len(set(r['roots']))!=len(r['roots']):
        return event(db,'publish',r['id'],'invalid_bundle',{})
    old=one(db,'SELECT * FROM bundles WHERE id=?',(r['id'],))
    if old:return event(db,'publish',r['id'],'idempotent',{})
    db.execute('INSERT INTO bundles VALUES(?,?,?,?,?)',(r['id'],json.dumps(r['roots']),r['start'],r['expires'],'active'))
    return event(db,'publish',r['id'],'published',{'roots':r['roots']})
def acknowledge(db,r):
    bundle=one(db,'SELECT * FROM bundles WHERE id=?',(r['bundle'],))
    replica=one(db,'SELECT * FROM replicas WHERE id=?',(r['replica'],))
    at=r.get('at',bundle['start'] if bundle else 0)
    if not bundle or bundle['status']!='active' or not bundle['start']<=at<bundle['expires']:
        return event(db,'ack',r['bundle'],'bundle_unavailable',{'at':at})
    if not replica or not replica['active']:
        return event(db,'ack',r['bundle'],'replica_unavailable',{})
    cert=one(db,'SELECT * FROM certificates WHERE id=?',(replica['cert'],))
    if not cert or cert['status']!='active' or not cert['not_before']<=at<cert['expires'] or cert['root'] not in json.loads(bundle['roots']):
        return event(db,'ack',r['bundle'],'untrusted_replica',{})
    if r['generation']!=cert['generation']:
        return event(db,'ack',r['bundle'],'wrong_replica_generation',{'current':cert['generation']})
    previous=one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=?',(r['bundle'],r['replica']))
    if previous and r['generation']<previous['generation']:
        return event(db,'ack',r['bundle'],'stale_receipt',{})
    db.execute('INSERT OR REPLACE INTO receipts VALUES(?,?,?,?,?)',(r['bundle'],r['replica'],r['generation'],'confirmed',at))
    db.execute('INSERT OR REPLACE INTO deliveries VALUES(?,?,?,?,?,?)',(r['bundle'],r['replica'],r['generation'],'confirmed',(one(db,'SELECT attempts FROM deliveries WHERE bundle=? AND replica=?',(r['bundle'],r['replica'])) or {}).get('attempts',0),'') )
    return event(db,'ack',r['bundle'],'confirmed',{'replica':r['replica']})
def coverage(db,r):
    bundle=one(db,'SELECT * FROM bundles WHERE id=?',(r['bundle'],))
    at=r.get('at',bundle['start'] if bundle else 0)
    if not bundle or bundle['status']!='active' or not bundle['start']<=at<bundle['expires']:
        return event(db,'coverage',r['bundle'],'bundle_unavailable',{'at':at})
    identities=many(db,'SELECT id FROM identities WHERE service=? AND status=?',(r['service'],'active'))
    replicas=[x for ident in identities for x in many(db,'SELECT * FROM replicas WHERE identity=? AND active=1',(ident['id'],))]
    missing=[]
    for rep in replicas:
        cert=one(db,'SELECT * FROM certificates WHERE id=?',(rep['cert'],))
        receipt=one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=? AND status=?',(r['bundle'],rep['id'],'confirmed'))
        if not cert or cert['status']!='active' or not cert['not_before']<=at<cert['expires'] or cert['root'] not in json.loads(bundle['roots']) or not receipt or receipt['generation']!=cert['generation'] or receipt['at']>at:
            missing.append(rep['id'])
    return event(db,'coverage',r['bundle'],'complete' if replicas and not missing else 'partial',{'missing':missing})
def retry(db,r):
    bundle=one(db,'SELECT * FROM bundles WHERE id=? AND status=?',(r['bundle'],'active'))
    if not bundle:return event(db,'retry',r['bundle'],'bundle_unavailable',{})
    at=r.get('at',bundle['start'])
    if not bundle['start']<=at<bundle['expires']:return event(db,'retry',r['bundle'],'bundle_outside_window',{})
    replicas=many(db,'SELECT r.id,c.generation,c.root FROM replicas r JOIN certificates c ON c.id=r.cert WHERE r.active=1 AND c.status=? AND c.not_before<=? AND c.expires>?',('active',at,at))
    missing=[]
    for rep in replicas:
        receipt=one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=?',(r['bundle'],rep['id']))
        if rep['root'] not in json.loads(bundle['roots']):continue
        if receipt and receipt['generation']==rep['generation']:continue
        missing.append(rep['id'])
        old=one(db,'SELECT attempts FROM deliveries WHERE bundle=? AND replica=?',(r['bundle'],rep['id']))
        db.execute('INSERT OR REPLACE INTO deliveries VALUES(?,?,?,?,?,?)',(r['bundle'],rep['id'],rep['generation'],'retry_pending',(old['attempts'] if old else 0)+1,'confirmation_missing'))
    return event(db,'retry',r['bundle'],'pending' if missing else 'complete',{'retry_replicas':missing})
def withdraw(db,r):
    bundle=one(db,'SELECT * FROM bundles WHERE id=?',(r['id'],))
    if not bundle:return event(db,'withdraw',r['id'],'missing',{})
    dependent=[]
    replicas=many(db,'SELECT r.id,c.root,c.generation FROM replicas r JOIN certificates c ON c.id=r.cert WHERE r.active=1 AND c.status=? AND c.not_before<=? AND c.expires>?',('active',r['at'],r['at']))
    for rep in replicas:
        receipt=one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=? AND generation=?',(r['id'],rep['id'],rep['generation']))
        if not receipt or rep['root'] not in json.loads(bundle['roots']):continue
        other=many(db,'SELECT b.*,a.generation AS acknowledged FROM bundles b JOIN receipts a ON a.bundle=b.id WHERE b.id<>? AND a.replica=? AND a.status=? AND b.status=?',(r['id'],rep['id'],'confirmed','active'))
        safe=any(rep['root'] in json.loads(b['roots']) and b['start']<=r['at']<b['expires'] and b['acknowledged']==rep['generation'] for b in other)
        if not safe:dependent.append(rep['id'])
    if dependent:return event(db,'withdraw',r['id'],'dependent_replicas_block',{'replicas':dependent})
    db.execute('UPDATE bundles SET status=? WHERE id=?',('withdrawn',r['id']))
    return event(db,'withdraw',r['id'],'withdrawn',{'migrated_replicas':len(replicas)})
