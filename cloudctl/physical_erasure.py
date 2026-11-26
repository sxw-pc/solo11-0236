import json
from .store import one,many,event,digest,step

# ---------- shared physical / legal fact helpers ----------
def active_orders(db,identity,at,kind=None):
    rows=many(db,'SELECT * FROM legal_orders WHERE identity=? AND superseded=0 AND issued_at<=? AND expires>? ORDER BY version',(identity,at,at))
    if kind:rows=[r for r in rows if r['kind']==kind]
    return rows

def order_scope(order):
    return set(json.loads(order['scope']))

def order_fingerprint(db,identity,at):
    rows=active_orders(db,identity,at)
    return digest([[r['id'],r['version'],r['kind'],r['subject'],sorted(order_scope(r)),r['expires'],r['require_original_ciphertext']] for r in rows])

def key_usable(db,key_id):
    if not key_id:return False
    key=one(db,'SELECT * FROM data_keys WHERE id=?',(key_id,))
    if not key or key['status']!='active':return False
    shares=many(db,'SELECT * FROM key_shares WHERE key_id=?',(key_id,))
    if not shares:return False
    return all(s['present']==1 for s in shares)

def copy_live_block(db,copy_id,block_id):
    copy=one(db,'SELECT * FROM volume_copies WHERE id=?',(copy_id,))
    if not copy:return False
    if copy['status']=='erased':return False
    row=one(db,'SELECT * FROM copy_block_erasure WHERE copy_id=? AND block_id=?',(copy_id,block_id))
    return row is None

def live_occurrences(db,object_id,identity):
    """Every still-readable physical location of an object (quarantined copies still hold bytes)."""
    out=[]
    for ob in many(db,'SELECT * FROM object_blocks WHERE object_id=? AND identity=? AND reachable=1',(object_id,identity)):
        for copy in many(db,'SELECT * FROM volume_copies WHERE volume=?',(ob['volume'],)):
            if copy_live_block(db,copy['id'],ob['block_id']):
                out.append({'copy':copy['id'],'volume':ob['volume'],'block':ob['block_id'],
                            'controller':copy['controller'],'copy_status':copy['status'],
                            'key_id':ob['key_id'],'key_usable':key_usable(db,ob['key_id'])})
    return out

def object_recoverable(db,object_id,identity):
    return any(o['key_usable'] for o in live_occurrences(db,object_id,identity))

def quarantined_copies(db,identity):
    return [r['id'] for r in many(db,"SELECT id FROM volume_copies WHERE status='quarantined' AND volume IN (SELECT id FROM physical_volumes WHERE identity=?)",(identity,))]

def object_tenants(db,identity):
    return {r['tenant'] for r in many(db,'SELECT DISTINCT tenant FROM data_objects WHERE identity=?',(identity,))}

def tenant_status(db,identity,at):
    """Per-tenant recoverability of plaintext across every backup/cache/key-share/offline copy."""
    result={}
    for tenant in sorted(object_tenants(db,identity)):
        objs=[r['id'] for r in many(db,'SELECT id FROM data_objects WHERE identity=? AND tenant=?',(identity,tenant))]
        recoverable=[];irrecoverable=[];controllers=set()
        for oid in objs:
            locs=live_occurrences(db,oid,identity)
            if any(loc['key_usable'] for loc in locs):
                recoverable.append(oid)
                for loc in locs:
                    if loc['key_usable']:controllers.add(loc['controller'])
            else:
                irrecoverable.append(oid)
        result[tenant]={'recoverable_objects':sorted(recoverable),'irrecoverable_objects':sorted(irrecoverable),
                        'controllers_of_recoverable_copies':sorted(controllers)}
    return result

def holds_relying_on_key(db,key_id,identity,at):
    out=[]
    if not key_id or not identity:return out
    for order in active_orders(db,identity,at,'preservation'):
        covered=bool(deliveries_for_order(db,order))
        for oid in order_scope(order):
            for loc in live_occurrences(db,oid,identity):
                if loc['key_id']==key_id and loc['key_usable'] and not covered:
                    out.append({'order':order['id'],'object':oid})
    return out

def deliveries_for_order(db,order):
    return many(db,'SELECT * FROM court_deliveries WHERE order_id=? AND order_version=?',(order['id'],order['version']))

# ---------- physical operations ----------
def erase_object(db,r):
    """Object-number erase receipt: directory-level only, never proves physical unrecoverability."""
    ident=r['identity']
    existing=one(db,'SELECT id FROM erasure_receipts WHERE id=?',(r['receipt'],))
    if existing:return event(db,'erasure',r['receipt'],'idempotent',{})
    obj=one(db,'SELECT * FROM data_objects WHERE id=? AND identity=?',(r['object'],ident))
    if not obj:return event(db,'erasure',r['receipt'],'missing_object',{})
    copy=one(db,'SELECT * FROM volume_copies WHERE id=?',(r['copy'],))
    if not copy:return event(db,'erasure',r['receipt'],'missing_copy',{})
    h=digest({'receipt':r['receipt'],'copy':r['copy'],'object':r['object'],'kind':'object'})
    db.execute('INSERT INTO erasure_receipts VALUES(?,?,?,?,?,?,?,?,?)',
               (r['receipt'],ident,r['copy'],copy['volume'],r.get('scope','object'),None,r['object'],r['at'],h))
    step(db,ident,'erasure.erase_object',r['at'],{'receipt':r['receipt'],'copy':r['copy'],'object':r['object']})
    return event(db,'erasure',r['receipt'],'object_erased',{'object':r['object'],'copy':r['copy'],'receipt_hash':h})

def erase_copy(db,r):
    """Physical erase of whole copy, or individual blocks. Stored receipts are the storage-vendor's actual wipe evidence."""
    ident=r['identity']
    existing=one(db,'SELECT id FROM erasure_receipts WHERE id=?',(r['receipt'],))
    if existing:return event(db,'erasure',r['receipt'],'idempotent',{})
    copy=one(db,'SELECT * FROM volume_copies WHERE id=?',(r['copy'],))
    if not copy:return event(db,'erasure',r['receipt'],'missing_copy',{})
    if copy['volume'] not in [v['id'] for v in many(db,'SELECT id FROM physical_volumes WHERE identity=?',(ident,))]:
        return event(db,'erasure',r['receipt'],'wrong_identity',{})
    blocks=r.get('blocks')
    # physical erasure cannot remove blocks still under an undelivered preservation hold on this copy
    target_blocks=set(blocks) if blocks else None
    conflicts=[]
    for order in active_orders(db,ident,r['at'],'preservation'):
        if deliveries_for_order(db,order):continue
        for oid in order_scope(order):
            for loc in live_occurrences(db,oid,ident):
                if loc['copy']==r['copy'] and loc['key_usable'] and (target_blocks is None or loc['block'] in target_blocks):
                    conflicts.append({'order':order['id'],'object':oid,'block':loc['block']})
    if conflicts:
        db.execute('UPDATE volume_copies SET status=? WHERE id=?',('quarantined',r['copy']))
        step(db,ident,'erasure.erase_copy',r['at'],{'copy':r['copy'],'result':'quarantined','conflicts':conflicts})
        return event(db,'erasure',r['receipt'],'hold_conflict_quarantined',{'copy':r['copy'],'conflicts':conflicts})
    provided=r.get('receipt_hash')
    h=provided or digest({'receipt':r['receipt'],'copy':r['copy'],'blocks':sorted(blocks) if blocks else 'volume','kind':'physical'})
    if provided and provided!=digest({'receipt':r['receipt'],'copy':r['copy'],'blocks':sorted(blocks) if blocks else 'volume','kind':'physical'}):
        return event(db,'erasure',r['receipt'],'receipt_hash_mismatch',{})
    if blocks:
        for bid in blocks:
            block=one(db,'SELECT * FROM physical_blocks WHERE id=? AND volume=?',(bid,copy['volume']))
            if not block:return event(db,'erasure',r['receipt'],'missing_block',{'block':bid})
        for bid in blocks:
            db.execute('INSERT OR REPLACE INTO copy_block_erasure VALUES(?,?,?)',(r['copy'],bid,r['receipt']))
    else:
        db.execute('UPDATE volume_copies SET status=? WHERE id=?',('erased',r['copy']))
    db.execute('INSERT INTO erasure_receipts VALUES(?,?,?,?,?,?,?,?,?)',
               (r['receipt'],ident,r['copy'],copy['volume'],r.get('scope','copy' if blocks else 'volume'),
                json.dumps(sorted(blocks)) if blocks else None,None,r['at'],h))
    step(db,ident,'erasure.erase_copy',r['at'],{'receipt':r['receipt'],'copy':r['copy'],'blocks':sorted(blocks) if blocks else 'volume'})
    return event(db,'erasure',r['receipt'],'copy_erased',{'copy':r['copy'],'blocks':sorted(blocks) if blocks else 'volume','receipt_hash':h})

def verify_copy(db,r):
    """Independent verification of a copy against recorded block digests; failed copies are quarantined, not counted done."""
    copy=one(db,'SELECT * FROM volume_copies WHERE id=?',(r['copy'],))
    if not copy:return event(db,'erasure',r['copy'],'missing_copy',{})
    expected={b['id']:b for b in many(db,'SELECT * FROM physical_blocks WHERE volume=?',(copy['volume'],))}
    observed=r.get('observed',{})
    bad=[bid for bid,dig in observed.items() if bid not in expected or expected[bid]['cipher_digest']!=dig]
    if bad:
        db.execute('UPDATE volume_copies SET status=? WHERE id=?',('quarantined',r['copy']))
        step(db,copy['volume'],'erasure.verify_copy',r['at'],{'copy':r['copy'],'result':'quarantined','bad':sorted(bad)})
        return event(db,'erasure',r['copy'],'quarantined',{'bad_blocks':sorted(bad)})
    return event(db,'erasure',r['copy'],'verified',{'blocks':sorted(observed)})

def shred_key(db,r):
    key=one(db,'SELECT * FROM data_keys WHERE id=?',(r['key'],))
    if not key:return event(db,'erasure',r['key'],'missing_key',{})
    existing=one(db,'SELECT id FROM key_shreds WHERE key_id=?',(r['key'],))
    if existing:return event(db,'erasure',r['key'],'idempotent',{'receipt':existing['id']})
    shares=many(db,'SELECT * FROM key_shares WHERE key_id=?',(r['key'],))
    if not shares or any(s['present']==0 for s in shares):
        missing=[s['id'] for s in shares if s['present']==0] if shares else [r['key']]
        return event(db,'erasure',r['key'],'key_shares_missing',{'missing':missing})
    # a preservation record still only readable through this key loses its decryption ability
    at_risk=holds_relying_on_key(db,r['key'],key['identity'],r['at'])
    if at_risk:
        return event(db,'erasure',r['key'],'hold_decryption_at_risk',{'records':at_risk})
    h=digest({'shred':r['receipt'],'key':r['key'],'shares':sorted(s['id'] for s in shares)})
    db.execute("UPDATE data_keys SET status='shredded' WHERE id=?",(r['key'],))
    db.execute('INSERT INTO key_shreds VALUES(?,?,?,?)',(r['receipt'],r['key'],r['at'],h))
    step(db,key['identity'],'erasure.shred_key',r['at'],{'receipt':r['receipt'],'key':r['key']})
    return event(db,'erasure',r['key'],'key_shredded',{'receipt':r['receipt'],'receipt_hash':h})

def reachability(db,r):
    ident=r['identity'];at=r['at']
    return event(db,'erasure',ident,'reachability',{'tenants':tenant_status(db,ident,at),'quarantined_copies':quarantined_copies(db,ident)})
