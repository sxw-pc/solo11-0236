import json
from .store import one,many,event,append_checkpoint,quarantined,verify,seal as do_seal,latest_seal,issuance_head_num
def _roots(bundle):return json.loads(bundle['roots'])
def publish(db,r):
    if quarantined(db,[r['id']]):return event(db,'publish',r['id'],'quarantined',{})
    if r['start']>=r['expires'] or len(set(r['roots']))!=len(r['roots']):
        return event(db,'publish',r['id'],'invalid_bundle',{})
    old=one(db,'SELECT * FROM bundles WHERE id=?',(r['id'],))
    if old:return event(db,'publish',r['id'],'idempotent',{})
    db.execute('INSERT INTO bundles VALUES(?,?,?,?,?)',(r['id'],json.dumps(r['roots']),r['start'],r['expires'],'active'))
    ev=event(db,'publish',r['id'],'published',{'roots':r['roots'],'start':r['start'],'expires':r['expires']})
    cp=append_checkpoint(db,r['id'],'publish',r['id'],ev['evidence'],ev['seq'])
    ev['checkpoint']={'subject':r['id'],'num':cp['num'],'digest':cp['digest']}
    return ev
def acknowledge(db,r):
    bundle=one(db,'SELECT * FROM bundles WHERE id=?',(r['bundle'],))
    replica=one(db,'SELECT * FROM replicas WHERE id=?',(r['replica'],))
    at=r.get('at',bundle['start'] if bundle else 0)
    if quarantined(db,[r['bundle'],replica['identity'] if replica else None]):
        return event(db,'ack',r['bundle'],'quarantined',{'at':at})
    if not bundle or bundle['status']!='active' or not bundle['start']<=at<bundle['expires']:
        return event(db,'ack',r['bundle'],'bundle_unavailable',{'at':at})
    if not replica or not replica['active']:
        return event(db,'ack',r['bundle'],'replica_unavailable',{})
    cert=one(db,'SELECT * FROM certificates WHERE id=?',(replica['cert'],))
    if not cert or cert['status']!='active' or not cert['not_before']<=at<cert['expires'] or cert['root'] not in _roots(bundle):
        return event(db,'ack',r['bundle'],'untrusted_replica',{})
    if r['generation']!=cert['generation']:
        return event(db,'ack',r['bundle'],'wrong_replica_generation',{'current':cert['generation']})
    # Receipts are per (bundle,replica,generation): historical generations stay
    # on record instead of being overwritten by the latest received line.
    prior=one(db,'SELECT MAX(generation) g FROM receipts WHERE bundle=? AND replica=?',(r['bundle'],r['replica']))
    if prior and prior['g'] and r['generation']<prior['g']:
        return event(db,'ack',r['bundle'],'stale_receipt',{'latest_generation':prior['g']})
    same=one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=? AND generation=?',(r['bundle'],r['replica'],r['generation']))
    if same:
        # Same-number retry: read back the committed record; conflicting content never overwrites.
        if same['at']==at and same['status']=='confirmed':
            return event(db,'ack',r['bundle'],'idempotent',{'replica':r['replica'],'generation':r['generation'],'received_at':at})
        return event(db,'ack',r['bundle'],'receipt_conflict',{'committed':same,'attempted_at':at})
    db.execute('INSERT INTO receipts VALUES(?,?,?,?,?)',(r['bundle'],r['replica'],r['generation'],'confirmed',at))
    db.execute('INSERT OR REPLACE INTO deliveries VALUES(?,?,?,?,?,?)',(r['bundle'],r['replica'],r['generation'],'confirmed',(one(db,'SELECT attempts FROM deliveries WHERE bundle=? AND replica=?',(r['bundle'],r['replica'])) or {}).get('attempts',0),'') )
    return event(db,'ack',r['bundle'],'confirmed',{'replica':r['replica'],'generation':r['generation'],'received_at':at})
def coverage(db,r):
    bundle=one(db,'SELECT * FROM bundles WHERE id=?',(r['bundle'],))
    at=r.get('at',bundle['start'] if bundle else 0)
    if quarantined(db,[r['bundle']]):
        return event(db,'coverage',r['bundle'],'quarantined',{'at':at})
    if not bundle or bundle['status']!='active' or not bundle['start']<=at<bundle['expires']:
        return event(db,'coverage',r['bundle'],'bundle_unavailable',{'at':at})
    identities=many(db,'SELECT id FROM identities WHERE service=? AND status=?',(r['service'],'active'))
    subject_ids=[i['id'] for i in identities]
    if quarantined(db,[r['bundle']]+subject_ids):
        return event(db,'coverage',r['bundle'],'quarantined',{'at':at})
    replicas=[x for ident in identities for x in many(db,'SELECT * FROM replicas WHERE identity=? AND active=1',(ident['id'],))]
    missing=[]
    for rep in replicas:
        cert=one(db,'SELECT * FROM certificates WHERE id=?',(rep['cert'],))
        if not cert:
            missing.append(rep['id']);continue
        receipt=one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=? AND generation=? AND status=?',(r['bundle'],rep['id'],cert['generation'],'confirmed'))
        if not cert or cert['status']!='active' or not cert['not_before']<=at<cert['expires'] or cert['root'] not in _roots(bundle) or not receipt or receipt['at']>at:
            missing.append(rep['id'])
    return event(db,'coverage',r['bundle'],'complete' if replicas and not missing else 'partial',{'missing':missing})
def retry(db,r):
    bundle=one(db,'SELECT * FROM bundles WHERE id=? AND status=?',(r['bundle'],'active'))
    if not bundle:
        old=one(db,'SELECT * FROM bundles WHERE id=?',(r['bundle'],))
        if old and old['status']=='withdrawn':return _retry_withdrawn(db,r,old)
        return event(db,'retry',r['bundle'],'bundle_unavailable',{})
    at=r.get('at',bundle['start'])
    subjects=[r['bundle']]+[x['identity'] for x in many(db,'SELECT DISTINCT identity FROM replicas')]
    if quarantined(db,subjects):return event(db,'retry',r['bundle'],'quarantined',{'at':at})
    if not bundle['start']<=at<bundle['expires']:return event(db,'retry',r['bundle'],'bundle_outside_window',{})
    replicas=many(db,'SELECT r.id,r.identity,c.generation,c.root FROM replicas r JOIN certificates c ON c.id=r.cert WHERE r.active=1 AND c.status=? AND c.not_before<=? AND c.expires>?',('active',at,at))
    missing=[]
    for rep in replicas:
        receipt=one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=? AND generation=?',(r['bundle'],rep['id'],rep['generation']))
        if rep['root'] not in _roots(bundle):continue
        if receipt and receipt['generation']==rep['generation']:continue
        missing.append(rep['id'])
        old=one(db,'SELECT attempts FROM deliveries WHERE bundle=? AND replica=?',(r['bundle'],rep['id']))
        db.execute('INSERT OR REPLACE INTO deliveries VALUES(?,?,?,?,?,?)',(r['bundle'],rep['id'],rep['generation'],'retry_pending',(old['attempts'] if old else 0)+1,'confirmation_missing'))
    return event(db,'retry',r['bundle'],'pending' if missing else 'complete',{'retry_replicas':missing})
def _retry_withdrawn(db,r,bundle):
    """Retries against a withdrawn bundle never resend blindly: each subject is
    explained by its recorded migration basis (sealed chain or live receipt),
    and retained receipts are classified as historical generations."""
    at=r.get('at',0)
    if quarantined(db,[r['bundle']]):return event(db,'retry',r['bundle'],'quarantined',{'at':at})
    migrations=many(db,'SELECT * FROM migrations WHERE bundle=?',(r['bundle'],))
    if not migrations:
        return event(db,'retry',r['bundle'],'withdrawn_without_migration',{})
    sealed=[m['subject'] for m in migrations if m['basis']=='sealed_chain']
    receipt=[m['subject'] for m in migrations if m['basis']=='live_receipt']
    historical=[]
    for row in many(db,'SELECT * FROM receipts WHERE bundle=? ORDER BY replica,generation',(r['bundle'],)):
        ident=one(db,'SELECT identity FROM replicas WHERE id=?',(row['replica'],))
        historical.append({'replica':row['replica'],'identity':ident['identity'] if ident else None,'generation':row['generation'],'received_at':row['at']})
    decision='sealed_migration' if sealed and not receipt else 'historical_receipt' if receipt and not sealed else 'mixed_migration'
    return event(db,'retry',r['bundle'],decision,{'sealed_subjects':sealed,'receipt_subjects':receipt,'historical_receipts':historical,'at':at})
def _sealed_migration_ok(db,bundle,at):
    """Method 1: the latest global seal covers every committed issuance
    checkpoint of every identity and snapshotted this bundle with its roots."""
    s=latest_seal(db)
    if not s:return None
    v=verify(db)
    if not v['ok']:return None
    snapshot=json.loads(s['bundle_snapshot']);heads=json.loads(s['heads'])
    snap=snapshot.get(bundle['id'])
    if not snap or snap['roots']!=_roots(bundle) or snap['head']!=heads.get(bundle['id'],0):
        return None
    covered={}
    for ident in many(db,'SELECT id FROM identities'):
        ih=issuance_head_num(db,ident['id'])
        if ih and heads.get(ident['id'],0)<ih:return None
        if ih:covered[ident['id']]={'sealed_head':heads[ident['id']],'last_issuance':ih}
    return {'seal':s['seq'],'at':s['at'],'covered':covered,'snapshot':snap}
def _receipt_migration(db,bundle,at):
    """Method 2: each dependent identity actually holds same-generation
    confirmation for its old-root certificate on another *active* bundle.
    Old-generation receipts on the withdrawn bundle are preserved as history."""
    roots=_roots(bundle)
    ph=','.join('?'*len(roots))
    rows=many(db,'SELECT DISTINCT r.identity,c.id AS cert_id,c.generation AS generation,c.root AS root FROM replicas r JOIN certificates c ON c.id=r.cert WHERE r.active=1 AND c.status=? AND c.not_before<=? AND c.expires>? AND c.root IN (%s)'%ph,('active',at,at,*roots))
    deps=[];evidence={}
    for row in rows:
        if row['identity'] not in deps:deps.append(row['identity'])
    for identity in deps:
        other=many(db,"""SELECT b.id AS bundle,b.roots AS roots,b.start AS start,b.expires AS expires,b.status AS bstatus,a.generation AS gen,a.at AS at,a.status AS astatus
            FROM receipts a JOIN bundles b ON b.id=a.bundle
            WHERE a.status='confirmed' AND b.id<>? AND b.status='active' AND a.replica IN (SELECT id FROM replicas WHERE identity=?)""",(bundle['id'],identity))
        safe=[o for o in other if cert_root_covered(db,identity,o['gen'],json.loads(o['roots'])) and o['start']<=at<o['expires']]
        if not safe:return None
        chosen=sorted(safe,key=lambda o:(o['at'],o['bundle']))[0]
        old_rows=many(db,'SELECT * FROM receipts WHERE bundle=? AND replica IN (SELECT id FROM replicas WHERE identity=?) ORDER BY generation',(bundle['id'],identity))
        evidence[identity]={'live_bundle':chosen['bundle'],'generation':chosen['gen'],'received_at':chosen['at'],'old_bundle_receipts':[{'replica':x['replica'],'generation':x['generation'],'at':x['at']} for x in old_rows]}
    return {'subjects':sorted(deps),'evidence':evidence} if deps else None
def cert_root_covered(db,identity,generation,roots):
    cert=one(db,'SELECT * FROM certificates WHERE identity=? AND generation=?',(identity,generation))
    return bool(cert and cert['root'] in roots)
def withdraw(db,r):
    bundle=one(db,'SELECT * FROM bundles WHERE id=?',(r['id'],))
    if not bundle:return event(db,'withdraw',r['id'],'missing',{})
    subjects={r['id']}
    for rep in many(db,'SELECT identity FROM replicas'):subjects.add(rep['identity'])
    if quarantined(db,list(subjects)):return event(db,'withdraw',r['id'],'quarantined',{})
    already=many(db,'SELECT * FROM migrations WHERE bundle=?',(r['id'],))
    if bundle['status']=='withdrawn' and already:
        return event(db,'withdraw',r['id'],'idempotent',{'migrations':[{'subject':m['subject'],'basis':m['basis'],'ref':m['ref']} for m in already]})
    dependent=[]
    replicas=many(db,'SELECT r.id,r.identity,c.id AS cert_id,c.root,c.generation FROM replicas r JOIN certificates c ON c.id=r.cert WHERE r.active=1 AND c.status=? AND c.not_before<=? AND c.expires>?',('active',r['at'],r['at']))
    dep_identities=[]
    for rep in replicas:
        receipt=one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=? AND generation=?',(r['id'],rep['id'],rep['generation']))
        if not receipt or rep['root'] not in _roots(bundle):continue
        other=many(db,'SELECT b.*,a.generation AS acknowledged FROM bundles b JOIN receipts a ON a.bundle=b.id WHERE b.id<>? AND a.replica=? AND a.status=? AND b.status=?',(r['id'],rep['id'],'confirmed','active'))
        safe=any(rep['root'] in json.loads(b['roots']) and b['start']<=r['at']<b['expires'] and b['acknowledged']==rep['generation'] for b in other)
        if not safe:
            dependent.append(rep['id'])
            if rep['identity'] not in dep_identities:dep_identities.append(rep['identity'])
    if dependent:return event(db,'withdraw',r['id'],'dependent_replicas_block',{'replicas':dependent})
    # Both exit paths are evidenced; neither may substitute "published" for received.
    sealed=_sealed_migration_ok(db,bundle,r['at'])
    receipt_basis=_receipt_migration(db,bundle,r['at'])
    if not sealed and not receipt_basis:
        return event(db,'withdraw',r['id'],'migration_evidence_missing',{'dependent_identities':dep_identities})
    basis='sealed_chain' if sealed else 'live_receipt'
    ref='seal-%d'%sealed['seal'] if sealed else receipt_basis['evidence'][receipt_basis['subjects'][0]]['live_bundle']
    mig_refs={}
    if sealed:
        for identity,info in sealed['covered'].items():
            db.execute('INSERT OR IGNORE INTO migrations VALUES(?,?,?,?,?,?,?)',(r['id'],identity,'sealed_chain','seal-%d'%sealed['seal'],r['at'],sealed['seal'],json.dumps(info,sort_keys=True)))
            mig_refs[identity]={'basis':'sealed_chain','ref':'seal-%d'%sealed['seal'],'sealed_head':info['sealed_head'],'last_issuance':info['last_issuance']}
    else:
        for identity,info in receipt_basis['evidence'].items():
            db.execute('INSERT OR IGNORE INTO migrations VALUES(?,?,?,?,?,?,?)',(r['id'],identity,'live_receipt',info['live_bundle'],r['at'],None,json.dumps(info,sort_keys=True)))
            mig_refs[identity]={'basis':'live_receipt','ref':info['live_bundle'],'generation':info['generation'],'received_at':info['received_at']}
    db.execute('UPDATE bundles SET status=? WHERE id=?',('withdrawn',r['id']))
    ev=event(db,'withdraw',r['id'],'withdrawn',{'basis':basis,'ref':ref,'migrated_identities':sorted(mig_refs),'migrations':mig_refs,'snapshot':sealed['snapshot'] if sealed else None})
    cp=append_checkpoint(db,r['id'],'withdraw',r['id'],ev['evidence'],ev['seq'])
    ev['checkpoint']={'subject':r['id'],'num':cp['num'],'digest':cp['digest']}
    return ev
def sealing(db,r):
    return do_seal(db,r)
def chain_verify(db,r):
    v=verify(db)
    return event(db,'chain_verify','global','verified' if v['ok'] else 'faults',{'heads':v['heads'],'faults':v['faults']})
