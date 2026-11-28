"""Per-arch production release batches with node runtime evidence.

A batch binds three things together for one rollout: the verified sub-image
digest each architecture is allowed to run, every node's pull/runtime receipt,
and the independent handshake probe that must pass before an old proxy replica
is deactivated.  All evidence is insert-only: a halt pauses nodes that have not
checked out yet and records recall obligations for those that have, but never
rewrites a checked-out manifest or erases old calls.  Power-loss retries reuse
the same batch id and the same single per-node startup identity.
"""
import json
from .store import one,many,event
from . import image_promote

def ensure(db):
    image_promote.ensure(db)
    for ddl in (
        'CREATE TABLE IF NOT EXISTS release_batches(batch TEXT PRIMARY KEY,tag TEXT,manifest_digest TEXT,mode TEXT,status TEXT,at INTEGER,detail_json TEXT)',
        'CREATE TABLE IF NOT EXISTS release_orders(batch TEXT,node TEXT,arch TEXT,identity TEXT,old_replica TEXT,new_replica TEXT,target_digest TEXT,retained INTEGER,startup_id TEXT,status TEXT,checked_digest TEXT,at INTEGER,PRIMARY KEY(batch,node))',
        'CREATE TABLE IF NOT EXISTS release_checkouts(batch TEXT,node TEXT,startup_id TEXT,digest TEXT,at INTEGER,PRIMARY KEY(batch,node))',
        'CREATE TABLE IF NOT EXISTS release_receipts(batch TEXT,node TEXT,startup_id TEXT,identity TEXT,replica TEXT,generation INTEGER,arch TEXT,digest TEXT,status TEXT,at INTEGER,PRIMARY KEY(batch,node))',
        'CREATE TABLE IF NOT EXISTS release_probes(batch TEXT,node TEXT,handshake TEXT,at INTEGER,PRIMARY KEY(batch,node))',
        'CREATE TABLE IF NOT EXISTS release_recalls(batch TEXT,node TEXT,digest TEXT,reason TEXT,status TEXT,at INTEGER,PRIMARY KEY(batch,node))',
        'CREATE TABLE IF NOT EXISTS feature_gates(purpose TEXT PRIMARY KEY,digests_json TEXT)'):
        db.execute(ddl)

def _order(db,batch,node):
    return one(db,'SELECT * FROM release_orders WHERE batch=? AND node=?',(batch,node))

def _batch(db,batch):
    return one(db,'SELECT * FROM release_batches WHERE batch=?',(batch,))

def plan(db,r):
    """Create a release batch and one immutable order per node."""
    ensure(db)
    if r.get('mode') not in ('full','partial'):
        return event(db,'release.plan',r.get('batch',''),'invalid_mode',{})
    nodes=r.get('nodes')
    allowed={'node','arch','identity','old_replica','new_replica','old_digest'}
    if not isinstance(nodes,list) or not nodes or any(set(n)-allowed for n in nodes):
        return event(db,'release.plan',r.get('batch',''),'invalid_nodes',{})
    existing=_batch(db,r['batch'])
    if existing:
        same=existing['tag']==r['tag'] and existing['manifest_digest']==r['manifest_digest'] and existing['mode']==r['mode']
        return event(db,'release.plan',r['batch'],'idempotent' if same else 'batch_conflict',{'status':existing['status']})
    manifest=many(db,'SELECT arch,sub_digest FROM image_manifests WHERE tag=? AND manifest_digest=?',(r['tag'],r['manifest_digest']))
    if not manifest:return event(db,'release.plan',r['batch'],'manifest_unknown',{'manifest':r['manifest_digest']})
    target={m['arch']:m['sub_digest'] for m in manifest}
    plan_rows=[];blocked=[]
    for n in nodes:
        if n['arch'] not in target:
            blocked.append({'node':n['node'],'reasons':['arch_not_in_manifest']});continue
        digest=target[n['arch']]
        retained=0
        ok,reasons=image_promote.verify_digest(db,digest)
        if ok:
            status='pending'
        elif r['mode']=='full':
            blocked.append({'node':n['node'],'reasons':['arch_unverified:'+n['arch']]+reasons});continue
        else:
            # Partial rollout: keep an independently verified old sub-image serving.
            if not n.get('old_digest'):
                blocked.append({'node':n['node'],'reasons':['retained_digest_missing']+reasons});continue
            ok_old,reasons_old=image_promote.verify_digest(db,n['old_digest'])
            if not ok_old:
                blocked.append({'node':n['node'],'reasons':['retained_unverified']+reasons_old});continue
            digest=n['old_digest'];retained=1;status='retained'
        plan_rows.append((r['batch'],n['node'],n['arch'],n['identity'],n['old_replica'],n['new_replica'],digest,retained,r['batch']+':'+n['node']+':start-1',status,'',r['at']))
    if blocked:
        return event(db,'release.plan',r['batch'],'blocked',{'blocked':blocked})
    db.execute('INSERT INTO release_batches VALUES(?,?,?,?,?,?,?)',(r['batch'],r['tag'],r['manifest_digest'],r['mode'],'active',r['at'],json.dumps([n['node'] for n in nodes])))
    db.executemany('INSERT INTO release_orders VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',plan_rows)
    return event(db,'release.plan',r['batch'],'planned',{'mode':r['mode'],'nodes':[{'node':x[1],'arch':x[2],'target_digest':x[6],'retained':bool(x[7]),'startup_id':x[8],'status':x[9]} for x in plan_rows]})

def checkout(db,r):
    """Node evidence: the actual sub-digest it pulled under its startup id."""
    ensure(db)
    b=_batch(db,r['batch'])
    if not b:return event(db,'release.checkout',r.get('node',''),'batch_unknown',{})
    o=_order(db,r['batch'],r['node'])
    if not o:return event(db,'release.checkout',r['node'],'node_unknown',{})
    if o['retained']:return event(db,'release.checkout',r['node'],'retained_node',{})
    if b['status']=='halted' and o['status']=='pending':
        return event(db,'release.checkout',r['node'],'batch_halted',{})
    if r['startup_id']!=o['startup_id']:
        return event(db,'release.checkout',r['node'],'startup_identity_mismatch',{})
    if r['arch']!=o['arch'] or r['digest']!=o['target_digest']:
        return event(db,'release.checkout',r['node'],'pull_mismatch',{'expected_arch':o['arch'],'expected_digest':o['target_digest'],'got_arch':r['arch'],'got_digest':r['digest']})
    old=one(db,'SELECT * FROM release_checkouts WHERE batch=? AND node=?',(r['batch'],r['node']))
    if old:
        if old['startup_id']==r['startup_id'] and old['digest']==r['digest']:
            return event(db,'release.checkout',r['node'],'idempotent',{'startup_id':r['startup_id']})
        return event(db,'release.checkout',r['node'],'checkout_conflict',{})
    db.execute('INSERT INTO release_checkouts VALUES(?,?,?,?,?)',(r['batch'],r['node'],r['startup_id'],r['digest'],r['at']))
    db.execute('UPDATE release_orders SET status=?,checked_digest=? WHERE batch=? AND node=?',('checked_out',r['digest'],r['batch'],r['node']))
    return event(db,'release.checkout',r['node'],'checked_out',{'startup_id':r['startup_id'],'digest':r['digest']})

def receipt(db,r):
    """Node runtime receipt: arch, pulled sub-digest, startup generation, identity."""
    ensure(db)
    b=_batch(db,r['batch'])
    if not b:return event(db,'release.receipt',r.get('node',''),'batch_unknown',{})
    o=_order(db,r['batch'],r['node'])
    if not o:return event(db,'release.receipt',r['node'],'node_unknown',{})
    if o['retained']:return event(db,'release.receipt',r['node'],'retained_node',{})
    co=one(db,'SELECT * FROM release_checkouts WHERE batch=? AND node=?',(r['batch'],r['node']))
    if not co:
        if b['status']=='halted':return event(db,'release.receipt',r['node'],'batch_halted',{})
        return event(db,'release.receipt',r['node'],'not_checked_out',{})
    if r['startup_id']!=o['startup_id']:
        return event(db,'release.receipt',r['node'],'startup_identity_mismatch',{})
    if r['arch']!=o['arch'] or r['digest']!=o['target_digest'] or r['digest']!=co['digest']:
        return event(db,'release.receipt',r['node'],'receipt_mismatch',{})
    if r['identity']!=o['identity']:
        return event(db,'release.receipt',r['node'],'identity_mismatch',{})
    old=one(db,'SELECT * FROM release_receipts WHERE batch=? AND node=?',(r['batch'],r['node']))
    if old:
        if old['startup_id']==r['startup_id'] and old['generation']==int(r['generation']) and old['digest']==r['digest'] and old['replica']==r['replica']:
            return event(db,'release.receipt',r['node'],'idempotent',{'startup_id':r['startup_id']})
        return event(db,'release.receipt',r['node'],'receipt_conflict',{})
    rep=one(db,'SELECT * FROM replicas WHERE id=? AND identity=? AND active=1',(r['replica'],r['identity']))
    if not rep:return event(db,'release.receipt',r['node'],'replica_not_ready',{})
    cert=one(db,'SELECT * FROM certificates WHERE id=?',(rep['cert'],))
    if not cert or cert['generation']!=int(r['generation']):
        return event(db,'release.receipt',r['node'],'wrong_generation',{})
    db.execute('INSERT INTO release_receipts VALUES(?,?,?,?,?,?,?,?,?,?)',(r['batch'],r['node'],r['startup_id'],r['identity'],r['replica'],int(r['generation']),r['arch'],r['digest'],'confirmed',r['at']))
    db.execute('UPDATE release_orders SET status=? WHERE batch=? AND node=?',('running',r['batch'],r['node']))
    return event(db,'release.receipt',r['node'],'confirmed',{'startup_id':r['startup_id'],'arch':r['arch'],'digest':r['digest'],'generation':int(r['generation'])})

def probe(db,r):
    """Record that the replacement passed its own independent handshake probe."""
    ensure(db)
    o=_order(db,r['batch'],r.get('node',''))
    if not o:return event(db,'release.probe',r.get('node',''),'node_unknown',{})
    if _batch(db,r['batch'])['status']=='halted':return event(db,'release.probe',r['node'],'batch_halted',{})
    if not one(db,'SELECT 1 FROM release_receipts WHERE batch=? AND node=? AND status=?',(r['batch'],r['node'],'confirmed')):
        return event(db,'release.probe',r['node'],'receipt_missing',{})
    hs=one(db,'SELECT * FROM handshakes WHERE id=?',(r['handshake'],))
    if not hs or hs['status']!='open' or hs['reason']!='allowed' or hs['callee_replica']!=o['new_replica'] or hs['purpose']!='rollout-probe':
        return event(db,'release.probe',r['node'],'probe_failed',{})
    old=one(db,'SELECT handshake FROM release_probes WHERE batch=? AND node=?',(r['batch'],r['node']))
    if old:
        return event(db,'release.probe',r['node'],'idempotent' if old['handshake']==r['handshake'] else 'probe_conflict',{})
    db.execute('INSERT INTO release_probes VALUES(?,?,?,?)',(r['batch'],r['node'],r['handshake'],r['at']))
    return event(db,'release.probe',r['node'],'probed',{'handshake':r['handshake'],'replica':o['new_replica']})

def switch(db,r):
    """Deactivate the old replica only after receipt plus independent probe."""
    ensure(db)
    b=_batch(db,r['batch'])
    if not b:return event(db,'release.switch',r.get('node',''),'batch_unknown',{})
    o=_order(db,r['batch'],r['node'])
    if not o:return event(db,'release.switch',r['node'],'node_unknown',{})
    if o['retained']:return event(db,'release.switch',r['node'],'retained_node',{})
    if b['status']=='halted':return event(db,'release.switch',r['node'],'batch_halted',{})
    if not one(db,'SELECT 1 FROM release_receipts WHERE batch=? AND node=? AND status=?',(r['batch'],r['node'],'confirmed')):
        return event(db,'release.switch',r['node'],'receipt_missing',{})
    if not one(db,'SELECT 1 FROM release_probes WHERE batch=? AND node=?',(r['batch'],r['node'])):
        return event(db,'release.switch',r['node'],'probe_missing',{})
    if o['status']=='switched':
        return event(db,'release.switch',r['node'],'idempotent',{})
    db.execute('UPDATE replicas SET active=0 WHERE id=? AND identity=?',(o['old_replica'],o['identity']))
    db.execute('UPDATE release_orders SET status=? WHERE batch=? AND node=?',('switched',r['batch'],r['node']))
    # A verified replacement on this node discharges recall duties from any
    # earlier batch; the original recall evidence row is kept, only closed.
    due=many(db,'SELECT batch,node FROM release_recalls WHERE node=? AND status=?',(r['node'],'due'))
    for d in due:
        db.execute('UPDATE release_recalls SET status=? WHERE batch=? AND node=?',('discharged',d['batch'],d['node']))
    return event(db,'release.switch',r['node'],'switched',{'old_replica':o['old_replica'],'new_replica':o['new_replica'],'recalls_discharged':len(due)})

def halt(db,r):
    """Pause unfinished nodes; checked-out nodes keep evidence, get recall duty."""
    ensure(db)
    b=_batch(db,r['batch'])
    if not b:return event(db,'release.halt',r.get('batch',''),'batch_unknown',{})
    if b['status']=='halted':return event(db,'release.halt',r['batch'],'idempotent',{})
    paused=[];recalls=[]
    for o in many(db,'SELECT * FROM release_orders WHERE batch=?',(r['batch'],)):
        if o['retained'] or o['status']=='switched':continue
        checked=one(db,'SELECT 1 FROM release_checkouts WHERE batch=? AND node=?',(r['batch'],o['node']))
        if not checked:
            # Nothing was pulled on this node: pause it, no evidence to recall.
            db.execute('UPDATE release_orders SET status=? WHERE batch=? AND node=?',('paused',r['batch'],o['node']))
            paused.append(o['node'])
            continue
        # Bytes already left the registry: keep the checkout immutably and
        # open a recall obligation instead of rewriting or deleting it.
        db.execute('INSERT OR IGNORE INTO release_recalls VALUES(?,?,?,?,?,?)',(r['batch'],o['node'],o['checked_digest'] or o['target_digest'],r.get('reason','signature_invalid'),'due',r['at']))
        recalls.append(o['node'])
    db.execute('UPDATE release_batches SET status=? WHERE batch=?',('halted',r['batch']))
    return event(db,'release.halt',r['batch'],'halted',{'paused':paused,'recalls':recalls})

def gate(db,r):
    """Restrict a call purpose to replicas running one of the listed digests."""
    ensure(db)
    if not r.get('purpose') or not isinstance(r.get('digests'),list) or not r['digests']:
        return event(db,'release.gate',r.get('purpose',''),'invalid_gate',{})
    db.execute('INSERT OR REPLACE INTO feature_gates VALUES(?,?)',(r['purpose'],json.dumps(r['digests'],sort_keys=True)))
    return event(db,'release.gate',r['purpose'],'gated',{'digests':r['digests']})
