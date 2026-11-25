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
    if not bundle or not replica or not replica['active']:
        return event(db,'ack',r['bundle'],'replica_unavailable',{})
    previous=one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=?',(r['bundle'],r['replica']))
    if previous and r['generation']<previous['generation']:
        return event(db,'ack',r['bundle'],'stale_receipt',{})
    db.execute('INSERT OR REPLACE INTO receipts VALUES(?,?,?,?)',(r['bundle'],r['replica'],r['generation'],'confirmed'))
    return event(db,'ack',r['bundle'],'confirmed',{'replica':r['replica']})
def coverage(db,r):
    identities=many(db,'SELECT id FROM identities WHERE service=? AND status=?',(r['service'],'active'))
    replicas=[x for ident in identities for x in many(db,'SELECT id FROM replicas WHERE identity=? AND active=1',(ident['id'],))]
    missing=[x['id'] for x in replicas if not one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=? AND status=?',(r['bundle'],x['id'],'confirmed'))]
    return event(db,'coverage',r['bundle'],'complete' if replicas and not missing else 'partial',{'missing':missing})
def retry(db,r):
    bundle=one(db,'SELECT * FROM bundles WHERE id=? AND status=?',(r['bundle'],'active'))
    if not bundle:return event(db,'retry',r['bundle'],'bundle_unavailable',{})
    replicas=many(db,'SELECT id FROM replicas WHERE active=1')
    missing=[x['id'] for x in replicas if not one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=?',(r['bundle'],x['id']))]
    return event(db,'retry',r['bundle'],'pending' if missing else 'complete',{'retry_replicas':missing})
def withdraw(db,r):
    bundle=one(db,'SELECT * FROM bundles WHERE id=?',(r['id'],))
    if not bundle:return event(db,'withdraw',r['id'],'missing',{})
    if r['at']<bundle['expires']:
        active=many(db,'SELECT id FROM replicas WHERE active=1')
        if active:return event(db,'withdraw',r['id'],'active_replicas_block',{'count':len(active)})
    db.execute('UPDATE bundles SET status=? WHERE id=?',('withdrawn',r['id']))
    return event(db,'withdraw',r['id'],'withdrawn',{})
