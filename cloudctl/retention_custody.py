import json
from .store import one,many,event,digest,step
from . import physical_erasure as pe

# ---------- small lookups ----------
def _case(db,identity):
    return one(db,'SELECT * FROM custody_cases WHERE identity=?',(identity,))

def _reopen_if_closed(db,ident):
    """Newly discovered physical material invalidates a finished case; it is reopened rather than hidden."""
    case=_case(db,ident)
    if case and case['state'] in ('completed','amended'):
        db.execute("UPDATE custody_cases SET state='reopened',closed_at=NULL WHERE identity=?",(ident,))

def _scope_blocks(db,identity,scope):
    blocks=set()
    for oid in scope:
        for row in many(db,'SELECT volume,block_id FROM object_blocks WHERE identity=? AND object_id=? AND reachable=1',(identity,oid)):
            blocks.add((row['volume'],row['block_id']))
    return blocks

def _shared_blocks(db,identity,at):
    deletion=set();hold=set()
    for order in pe.active_orders(db,identity,at):
        target=deletion if order['kind']=='deletion' else hold
        target |= _scope_blocks(db,identity,pe.order_scope(order))
    return sorted(deletion & hold)

def _receipts_for_location(db,copy_id,block_id):
    copy=one(db,'SELECT * FROM volume_copies WHERE id=?',(copy_id,))
    if not copy:return []
    if copy['status']=='erased':
        return [r['id'] for r in many(db,"SELECT id FROM erasure_receipts WHERE copy_id=? AND block_id IS NULL",(copy_id,))]
    row=one(db,'SELECT receipt_id FROM copy_block_erasure WHERE copy_id=? AND block_id=?',(copy_id,block_id))
    return [row['receipt_id']] if row else []

def _location_destroyed(db,key_id,copy_id,block_id):
    if _receipts_for_location(db,copy_id,block_id):return True
    if key_id and one(db,'SELECT id FROM key_shreds WHERE key_id=?',(key_id,)):return True
    return False

# ---------- legal orders ----------
def file_order(db,r):
    ident=r['identity']
    body=r.get('original_body','')
    if r.get('original_hash')!=digest({'ref':r['original_ref'],'body':body}):
        return event(db,'custody',r['id'],'original_unverifiable',{'identity':ident})
    if r['issued_at']>=r['expires']:
        return event(db,'custody',r['id'],'invalid_window',{})
    prev=one(db,'SELECT MAX(version) v FROM legal_orders WHERE id=?',(r['id'],))
    version=r.get('version') or ((prev['v'] or 0)+1)
    existing=one(db,'SELECT * FROM legal_orders WHERE id=? AND version=?',(r['id'],version))
    fingerprint=digest({'kind':r['kind'],'subject':r['subject'],'scope':sorted(r['scope']),'expires':r['expires'],
                        'executor':r['executor'],'ref':r['original_ref'],'hash':r['original_hash'],
                        'require_original_ciphertext':r.get('require_original_ciphertext',False)})
    if existing:
        if existing['identity']!=ident:return event(db,'custody',r['id'],'conflict',{})
        return event(db,'custody',r['id'],'idempotent',{'version':version})
    if prev['v'] and version!=prev['v']+1:
        return event(db,'custody',r['id'],'wrong_version',{'expected':prev['v']+1})
    db.execute('UPDATE legal_orders SET superseded=1 WHERE id=?',(r['id'],))
    db.execute('INSERT INTO legal_orders VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (r['id'],version,r['kind'],ident,r['subject'],json.dumps(sorted(r['scope'])),
                r['issued_at'],r['expires'],r['executor'],r.get('custodian'),r['original_ref'],
                r['original_hash'],1 if r.get('require_original_ciphertext') else 0,0))
    case=_case(db,ident)
    if case and case['state'] in ('open','in_progress','completed','amended'):
        current=pe.order_fingerprint(db,ident,r.get('at',r['issued_at']))
        if current!=case['order_fingerprint']:
            db.execute("UPDATE custody_cases SET state=? WHERE identity=?",('order_changed',ident))
    step(db,ident,'custody.file_order',r.get('at',r['issued_at']),{'order':r['id'],'version':version,'kind':r['kind']})
    return event(db,'custody',r['id'],'filed',{'version':version,'fingerprint':fingerprint})

# ---------- inventory registration ----------
def register_key(db,r):
    existing=one(db,'SELECT id FROM data_keys WHERE id=?',(r['id'],))
    if not existing:
        db.execute('INSERT INTO data_keys VALUES(?,?,?,?)',(r['id'],r['identity'],r['generation'],'active'))
    for share in r['shares']:
        db.execute('INSERT OR REPLACE INTO key_shares VALUES(?,?,?,?)',(share['id'],r['id'],share['holder'],1 if share.get('present',True) else 0))
    return event(db,'custody',r['id'],'key_registered',{'shares':len(r['shares'])})

def register_volume(db,r):
    ident=r['identity']
    if not one(db,'SELECT id FROM physical_volumes WHERE id=?',(r['id'],)):
        db.execute('INSERT INTO physical_volumes VALUES(?,?,?,?)',(r['id'],ident,r['key_id'],'active'))
    for copy in r['copies']:
        if not one(db,'SELECT id FROM volume_copies WHERE id=?',(copy['id'],)):
            db.execute('INSERT INTO volume_copies VALUES(?,?,?,?)',(copy['id'],r['id'],copy['controller'],copy.get('status','active')))
    for block in r['blocks']:
        if not one(db,'SELECT id FROM physical_blocks WHERE id=? AND volume=?',(block['id'],r['id'])):
            db.execute('INSERT INTO physical_blocks VALUES(?,?,?,?,?,?)',
                       (block['id'],r['id'],block['cipher_digest'],block['plain_digest'],r['key_id'],'active'))
    _reopen_if_closed(db,ident)
    return event(db,'custody',r['id'],'volume_registered',{'copies':len(r['copies']),'blocks':len(r['blocks'])})

def register_objects(db,r):
    ident=r['identity']
    for obj in r['objects']:
        if not one(db,'SELECT id FROM data_objects WHERE id=? AND identity=?',(obj['id'],ident)):
            db.execute('INSERT INTO data_objects VALUES(?,?,?,?)',(obj['id'],ident,obj['tenant'],obj['plain_digest']))
        for loc in obj['locations']:
            if not one(db,'SELECT object_id FROM object_blocks WHERE object_id=? AND block_id=? AND volume=?',(obj['id'],loc['block_id'],loc['volume'])):
                db.execute('INSERT INTO object_blocks VALUES(?,?,?,?,?,?)',
                           (obj['id'],ident,loc['block_id'],loc['volume'],loc['key_id'],1))
    _reopen_if_closed(db,ident)
    return event(db,'custody',ident,'objects_registered',{'objects':len(r['objects'])})

def register_manifest(db,r):
    ident=r['identity']
    inventory=[[o['id'],o['tenant'],o['plain_digest'],
                sorted([[b['volume'],b['block_id'],b['key_id']] for b in many(db,'SELECT volume,block_id,key_id FROM object_blocks WHERE identity=? AND object_id=? AND reachable=1',(ident,o['id']))])]
               for o in many(db,'SELECT * FROM data_objects WHERE identity=? ORDER BY id',(ident,))]
    h=digest(inventory)
    if r.get('digest') and r['digest']!=h:return event(db,'custody',r['id'],'manifest_mismatch',{'digest':h})
    db.execute('INSERT OR REPLACE INTO manifests VALUES(?,?,?,?)',(r['id'],ident,r['at'],h))
    step(db,ident,'custody.register_manifest',r['at'],{'manifest':r['id'],'digest':h})
    return event(db,'custody',r['id'],'manifest_recorded',{'digest':h})

# ---------- case lifecycle ----------
def open_case(db,r):
    ident=r['identity'];at=r['at']
    identity=one(db,'SELECT * FROM identities WHERE id=?',(ident,))
    if not identity:return event(db,'custody',ident,'missing_identity',{})
    if identity['status']!='retired':return event(db,'custody',ident,'identity_not_retired',{})
    orders=pe.active_orders(db,ident,at)
    if not orders:return event(db,'custody',ident,'no_active_orders',{})
    requires_original=any(o['require_original_ciphertext']==1 for o in orders if o['kind']=='preservation')
    mode=r.get('mode') or ('rearrangement' if requires_original else 'migration')
    if requires_original and mode=='migration':
        return event(db,'custody',ident,'original_ciphertext_required',{})
    shared=_shared_blocks(db,ident,at)
    if mode=='rearrangement' and shared:
        db.execute("INSERT OR REPLACE INTO custody_cases VALUES(?,?,?,?,?,?)",(ident,mode,pe.order_fingerprint(db,ident,at),'escalated_court',at,None))
        step(db,ident,'custody.open',at,{'mode':mode,'result':'escalated','shared':shared})
        return event(db,'custody',ident,'rearrangement_blocked_escalated',{'mode':mode,'shared_blocks':shared})
    fingerprint=pe.order_fingerprint(db,ident,at)
    case=_case(db,ident)
    if case and case['state'] in ('completed','amended'):
        return event(db,'custody',ident,'already_completed',{'certificates':[c['id'] for c in many(db,"SELECT id FROM destruction_certificates WHERE identity=? AND superseded_by=''",(ident,))]})
    # rebinding after an order change or escalation reopens the case under the new fingerprint
    db.execute('INSERT OR REPLACE INTO custody_cases VALUES(?,?,?,?,?,?)',(ident,mode,fingerprint,'open',at,case['closed_at'] if case else None))
    step(db,ident,'custody.open',at,{'mode':mode,'orders':[o['id'] for o in orders]})
    return event(db,'custody',ident,'opened',{'mode':mode,'fingerprint':fingerprint,'shared_blocks':shared})

# ---------- path one: migration to independent key volume ----------
def migrate(db,r):
    ident=r['identity'];at=r['at']
    case=_case(db,ident)
    if not case:return event(db,'custody',ident,'no_case',{})
    if case['state'] not in ('open','in_progress'):return event(db,'custody',ident,'case_not_open',{'state':case['state']})
    if case['mode']!='migration':return event(db,'custody',ident,'wrong_mode',{'mode':case['mode']})
    order=one(db,'SELECT * FROM legal_orders WHERE id=? AND version=? AND identity=? AND superseded=0',(r['order_id'],r['order_version'],ident))
    if not order or order['kind']!='preservation' or not (order['issued_at']<=at<order['expires']):
        return event(db,'custody',r['order_id'],'order_unavailable',{})
    to_vol=one(db,'SELECT * FROM physical_volumes WHERE id=? AND identity=?',(r['to_volume'],ident))
    if not to_vol:return event(db,'custody',r['to_volume'],'missing_volume',{})
    new_key=to_vol['key_id']
    old_blocks=sorted(_scope_blocks(db,ident,pe.order_scope(order)))
    old_keys={b[0]:one(db,'SELECT key_id FROM physical_blocks WHERE id=? AND volume=?',(b[1],b[0]))['key_id'] for b in old_blocks}
    if any(k==new_key for k in old_keys.values()):
        return event(db,'custody',ident,'not_independent_key',{})
    # verification: every live copy of each source block must match its recorded cipher digest
    observed=r.get('observed',{})
    bad=[]
    for volume,block_id in old_blocks:
        block=one(db,'SELECT * FROM physical_blocks WHERE id=? AND volume=?',(block_id,volume))
        for copy in many(db,'SELECT * FROM volume_copies WHERE volume=?',(volume,)):
            if not pe.copy_live_block(db,copy['id'],block_id):continue
            dig=observed.get(copy['id'],{}).get(block_id,block['cipher_digest'])
            if dig!=block['cipher_digest']:
                bad.append(copy['id'])
                db.execute("UPDATE volume_copies SET status='quarantined' WHERE id=?",(copy['id'],))
    if bad:
        db.execute("UPDATE custody_cases SET state='in_progress' WHERE identity=?",(ident,))
        step(db,ident,'custody.migrate',at,{'result':'verification_failed','copies':sorted(set(bad))})
        return event(db,'custody',ident,'verification_failed_quarantined',{'copies':sorted(set(bad))})
    preserved=[[oid,one(db,'SELECT plain_digest FROM data_objects WHERE id=? AND identity=?',(oid,ident))['plain_digest']] for oid in json.loads(order['scope'])]
    excluded=sorted({oid for o in pe.active_orders(db,ident,at,'deletion') for oid in pe.order_scope(o)})
    new_blocks=r['new_blocks']
    for (volume,block_id),new_id in new_blocks.items():
        src=one(db,'SELECT * FROM physical_blocks WHERE id=? AND volume=?',(block_id,volume))
        db.execute('INSERT OR REPLACE INTO physical_blocks VALUES(?,?,?,?,?,?)',
                   (new_id,to_vol['id'],r['new_cipher'][new_id],src['plain_digest'],new_key,'active'))
    for oid in json.loads(order['scope']):
        for row in many(db,'SELECT * FROM object_blocks WHERE identity=? AND object_id=? AND reachable=1',(ident,oid)):
            new_id=new_blocks.get((row['volume'],row['block_id']))
            if not new_id:continue
            db.execute('UPDATE object_blocks SET reachable=0 WHERE object_id=? AND block_id=? AND volume=?',(oid,row['block_id'],row['volume']))
            db.execute('INSERT OR REPLACE INTO object_blocks VALUES(?,?,?,?,?,?)',(oid,ident,new_id,to_vol['id'],new_key,1))
    preserved_digest=digest(preserved);excluded_digest=digest(excluded)
    h=digest({'proof':r['proof'],'order':[order['id'],order['version']],'preserved':preserved_digest,'excluded':excluded_digest,
              'from':sorted(set(v for v,_ in old_blocks)),'to':to_vol['id'],'old_keys':sorted(set(old_keys.values())),'new_key':new_key})
    if r.get('receipt_hash') and r['receipt_hash']!=h:return event(db,'custody',r['proof'],'receipt_hash_mismatch',{})
    db.execute('INSERT INTO migration_proofs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (r['proof'],ident,json.dumps(sorted(set(v for v,_ in old_blocks))),to_vol['id'],
                json.dumps(sorted(set(old_keys.values()))),new_key,order['id'],order['version'],
                preserved_digest,json.dumps(excluded),at,h,'verified'))
    db.execute("UPDATE custody_cases SET state='in_progress' WHERE identity=?",(ident,))
    step(db,ident,'custody.migrate',at,{'proof':r['proof'],'to_volume':to_vol['id'],'new_key':new_key,'excluded':excluded})
    return event(db,'custody',ident,'migrated',{'proof':r['proof'],'preserved_digest':preserved_digest,'excluded_digest':excluded_digest,'receipt_hash':h})

# ---------- path two: proven physical rearrangement on original ciphertext ----------
def rearrange(db,r):
    ident=r['identity'];at=r['at']
    case=_case(db,ident)
    if not case:return event(db,'custody',ident,'no_case',{})
    kept=set(r['kept_blocks'])
    if case['state']=='escalated_court':
        # re-evaluating an escalated case must still surface the blocking shared block, not a false proof
        volume=r['volume']
        blocked=[]
        for o in pe.active_orders(db,ident,at,'deletion'):
            for oid in pe.order_scope(o):
                for row in many(db,'SELECT block_id FROM object_blocks WHERE identity=? AND object_id=? AND volume=? AND reachable=1',(ident,oid,volume)):
                    if row['block_id'] in kept:blocked.append({'block':row['block_id'],'object':oid})
        if blocked:
            return event(db,'custody',ident,'rearrangement_blocked_escalated',blocked[0])
        return event(db,'custody',ident,'case_not_open',{'state':case['state']})
    if case['state'] not in ('open','in_progress','reopened'):return event(db,'custody',ident,'case_not_open',{'state':case['state']})
    if case['mode']!='rearrangement':return event(db,'custody',ident,'wrong_mode',{'mode':case['mode']})
    order=one(db,'SELECT * FROM legal_orders WHERE id=? AND version=? AND identity=? AND superseded=0',(r['order_id'],r['order_version'],ident))
    if not order or order['kind']!='preservation' or not (order['issued_at']<=at<order['expires']):
        return event(db,'custody',r['order_id'],'order_unavailable',{})
    volume=r['volume']
    vol=one(db,'SELECT * FROM physical_volumes WHERE id=? AND identity=?',(volume,ident))
    if not vol:return event(db,'custody',volume,'missing_volume',{})
    scope=json.loads(order['scope'])
    # a kept (original-ciphertext) block still reachable by a deletion subject makes rearrangement impossible
    kept=set(r['kept_blocks'])
    for o in pe.active_orders(db,ident,at,'deletion'):
        for oid in pe.order_scope(o):
            for row in many(db,'SELECT block_id FROM object_blocks WHERE identity=? AND object_id=? AND volume=? AND reachable=1',(ident,oid,volume)):
                if row['block_id'] in kept:
                    db.execute("UPDATE custody_cases SET state='escalated_court' WHERE identity=?",(ident,))
                    step(db,ident,'custody.rearrange',at,{'result':'blocked','block':row['block_id'],'object':oid})
                    return event(db,'custody',ident,'rearrangement_blocked_escalated',{'block':row['block_id'],'object':oid})
    # verification of original kept bytes
    observed=r.get('observed',{})
    bad=[]
    for bid in sorted(kept):
        block=one(db,'SELECT * FROM physical_blocks WHERE id=? AND volume=?',(bid,volume))
        for copy in many(db,'SELECT * FROM volume_copies WHERE volume=?',(volume,)):
            if not pe.copy_live_block(db,copy['id'],bid):continue
            dig=observed.get(copy['id'],{}).get(bid,block['cipher_digest'])
            if dig!=block['cipher_digest']:
                bad.append(copy['id'])
                db.execute("UPDATE volume_copies SET status='quarantined' WHERE id=?",(copy['id'],))
    if bad:
        step(db,ident,'custody.rearrange',at,{'result':'verification_failed','copies':sorted(set(bad))})
        return event(db,'custody',ident,'verification_failed_quarantined',{'copies':sorted(set(bad))})
    excluded=sorted({oid for o in pe.active_orders(db,ident,at,'deletion') for oid in pe.order_scope(o)})
    # rewrite: new physical blocks, same key, same volume; deletion content dropped
    for old_id,new_id in r['rewritten_blocks'].items():
        src=one(db,'SELECT * FROM physical_blocks WHERE id=? AND volume=?',(old_id,volume))
        db.execute('INSERT OR REPLACE INTO physical_blocks VALUES(?,?,?,?,?,?)',
                   (new_id,volume,r['new_cipher'][new_id],r['new_plain_digest'][new_id],vol['key_id'],'active'))
        for copy in many(db,'SELECT id FROM volume_copies WHERE volume=?',(volume,)):
            db.execute('INSERT OR REPLACE INTO copy_block_erasure VALUES(?,?,?)',(copy['id'],old_id,r['rewrite_receipt']))
    # preserve only hold objects; every deletion reachability path on this volume is severed
    hold_objects=set(scope)
    for row in many(db,'SELECT DISTINCT object_id,block_id FROM object_blocks WHERE identity=? AND volume=? AND reachable=1',(ident,volume)):
        if row['object_id'] not in hold_objects:
            db.execute('UPDATE object_blocks SET reachable=0 WHERE identity=? AND object_id=? AND block_id=? AND volume=?',(ident,row['object_id'],row['block_id'],volume))
    for old_id,new_id in r['rewritten_blocks'].items():
        for row in many(db,'SELECT object_id FROM object_blocks WHERE identity=? AND block_id=? AND volume=?',(ident,old_id,volume)):
            if row['object_id'] in hold_objects:
                db.execute('UPDATE object_blocks SET reachable=0 WHERE identity=? AND object_id=? AND block_id=? AND volume=?',(ident,row['object_id'],old_id,volume))
                db.execute('INSERT OR REPLACE INTO object_blocks VALUES(?,?,?,?,?,?)',(row['object_id'],ident,new_id,volume,vol['key_id'],1))
    kept_digest=digest([[oid,one(db,'SELECT plain_digest FROM data_objects WHERE id=? AND identity=?',(oid,ident))['plain_digest']] for oid in scope])
    excluded_digest=digest(excluded)
    proof=r.get('proof','proof-rr-'+volume)
    h=digest({'proof':proof,'order':[order['id'],order['version']],'volume':volume,'key':vol['key_id'],
              'kept':kept_digest,'excluded':excluded_digest,'kept_blocks':sorted(kept)})
    if r.get('receipt_hash') and r['receipt_hash']!=h:return event(db,'custody',proof,'receipt_hash_mismatch',{})
    db.execute('INSERT INTO rearrangement_proofs VALUES(?,?,?,?,?,?,?,?,?,?)',
               (proof,ident,volume,order['id'],order['version'],kept_digest,excluded_digest,at,h,'verified'))
    db.execute("UPDATE custody_cases SET state='in_progress' WHERE identity=?",(ident,))
    step(db,ident,'custody.rearrange',at,{'proof':proof,'volume':volume,'kept':sorted(kept),'excluded':excluded})
    return event(db,'custody',ident,'rearranged',{'proof':proof,'kept_digest':kept_digest,'excluded_digest':excluded_digest,'receipt_hash':h})

# ---------- court delivery ----------
def deliver_court(db,r):
    ident=r['identity'];at=r['at']
    order=one(db,'SELECT * FROM legal_orders WHERE id=? AND version=? AND identity=? AND superseded=0',(r['order_id'],r['order_version'],ident))
    if not order or order['kind']!='preservation' or not (order['issued_at']<=at<order['expires']):
        return event(db,'custody',r.get('order_id','?'),'order_unavailable',{})
    if r['custodian']!=order['custodian']:
        return event(db,'custody',r['id'],'custodian_unauthorized',{'authorized':order['custodian']})
    scope=set(r['scope']);allowed=pe.order_scope(order)
    if scope-allowed:
        return event(db,'custody',r['id'],'scope_exceeds_order',{'excess':sorted(scope-allowed)})
    if allowed-scope:
        return event(db,'custody',r['id'],'hold_scope_incomplete',{'missing':sorted(allowed-scope)})
    # verifiable original byte form
    blocks=_scope_blocks(db,ident,scope)
    if r['form']=='original_ciphertext':
        vol_blocks=[b for v,b in blocks if v==r['volume']]
        if not vol_blocks:return event(db,'custody',r['id'],'no_original_bytes',{})
        byte_digest=digest(sorted(one(db,'SELECT cipher_digest FROM physical_blocks WHERE id=? AND volume=?',(b,r['volume']))['cipher_digest'] for b in vol_blocks))
    else:
        proof=one(db,'SELECT * FROM migration_proofs WHERE id=? AND identity=?',(r.get('proof',''),ident))
        if not proof or proof['status']!='verified':return event(db,'custody',r['id'],'migration_proof_missing',{})
        byte_digest=proof['preserved_digest']
    if r['byte_digest']!=byte_digest:
        return event(db,'custody',r['id'],'byte_digest_mismatch',{'expected':byte_digest})
    h=digest({'delivery':r['id'],'order':[order['id'],order['version']],'custodian':r['custodian'],'scope':sorted(scope),'digest':byte_digest})
    if r.get('receipt_hash') and r['receipt_hash']!=h:return event(db,'custody',r['id'],'receipt_hash_mismatch',{})
    db.execute('INSERT INTO court_deliveries VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
               (r['id'],ident,order['id'],order['version'],r['custodian'],r['volume'],r.get('key_id'),
                r['form'],json.dumps(sorted(scope)),byte_digest,at,h))
    step(db,ident,'custody.deliver_court',at,{'delivery':r['id'],'order':order['id'],'form':r['form']})
    return event(db,'custody',r['id'],'delivered',{'order':order['id'],'form':r['form'],'byte_digest':byte_digest,'receipt_hash':h})

# ---------- completeness evaluation ----------
def _deletion_evaluation(db,ident,at):
    incomplete={};evidence_missing=[]
    for order in pe.active_orders(db,ident,at,'deletion'):
        for oid in pe.order_scope(order):
            locs=pe.live_occurrences(db,oid,ident)
            readable=[loc for loc in locs if loc['key_usable']]
            if readable:
                incomplete[oid]=sorted({loc['copy'] for loc in readable})
                continue
            all_rows=many(db,'SELECT * FROM object_blocks WHERE identity=? AND object_id=?',(ident,oid))
            for row in all_rows:
                for copy in many(db,'SELECT id FROM volume_copies WHERE volume=?',(row['volume'],)):
                    if not _location_destroyed(db,row['key_id'],copy['id'],row['block_id']):
                        evidence_missing.append({'object':oid,'copy':copy['id'],'block':row['block_id']})
    return incomplete,evidence_missing

def _hold_evaluation(db,ident,at):
    unverified=[]
    for order in pe.active_orders(db,ident,at,'preservation'):
        deliveries=pe.deliveries_for_order(db,order)
        scope=pe.order_scope(order)
        delivered=set()
        for d in deliveries:delivered |= set(json.loads(d['scope']))
        for oid in scope:
            locs=pe.live_occurrences(db,oid,ident)
            readable=any(loc['key_usable'] for loc in locs)
            if oid in delivered:
                if order['require_original_ciphertext']==1 and not any(d['form']=='original_ciphertext' for d in deliveries) and not readable:
                    unverified.append({'order':order['id'],'object':oid,'reason':'original_ciphertext_lost'})
                continue
            if not readable:
                unverified.append({'order':order['id'],'object':oid,'reason':'undelivered_and_unreadable'})
    return unverified

def _certificate_basis(db,ident):
    return {'erasure_receipts':[r['id'] for r in many(db,'SELECT id FROM erasure_receipts WHERE identity=?',(ident,))],
            'key_shreds':[r['id'] for r in many(db,'SELECT s.id FROM key_shreds s JOIN data_keys k ON k.id=s.key_id WHERE k.identity=?',(ident,))],
            'migration_proofs':[r['id'] for r in many(db,'SELECT id FROM migration_proofs WHERE identity=? AND status=?',(ident,'verified'))],
            'rearrangement_proofs':[r['id'] for r in many(db,'SELECT id FROM rearrangement_proofs WHERE identity=? AND status=?',(ident,'verified'))],
            'court_deliveries':[r['id'] for r in many(db,'SELECT id FROM court_deliveries WHERE identity=?',(ident,))]}

def complete(db,r):
    ident=r['identity'];at=r['at']
    case=_case(db,ident)
    if not case:return event(db,'custody',ident,'no_case',{})
    if case['state']=='escalated_court':return event(db,'custody',ident,'escalated_no_false_certificate',{})
    if case['state']=='order_changed':
        return event(db,'custody',ident,'order_changed',{'bound_fingerprint':case['order_fingerprint']})
    if case['state']=='completed':
        # destruction proofs are never re-issued; a finished case returns its existing certificate
        existing=one(db,"SELECT id FROM destruction_certificates WHERE identity=? AND superseded_by=''",(ident,))
        return event(db,'custody',ident,'idempotent',{'certificate':existing['id'] if existing else None})
    if case['state'] not in ('open','in_progress','reopened'):return event(db,'custody',ident,'case_not_open',{'state':case['state']})
    if pe.order_fingerprint(db,ident,at)!=case['order_fingerprint']:
        db.execute("UPDATE custody_cases SET state='order_changed' WHERE identity=?",(ident,))
        return event(db,'custody',ident,'order_changed',{})
    quarantined=pe.quarantined_copies(db,ident)
    if quarantined:return event(db,'custody',ident,'quarantined_copies_present',{'copies':quarantined})
    incomplete,missing_evidence=_deletion_evaluation(db,ident,at)
    if incomplete:return event(db,'custody',ident,'deletion_incomplete',{'recoverable':incomplete})
    if missing_evidence:return event(db,'custody',ident,'evidence_missing',{'locations':missing_evidence})
    unverified=_hold_evaluation(db,ident,at)
    if unverified:return event(db,'custody',ident,'hold_unverified',{'records':unverified})
    existing=one(db,"SELECT id FROM destruction_certificates WHERE identity=? AND superseded_by=''",(ident,))
    if existing:
        # a finished case reopened by newly discovered material cannot be silently re-certified
        return event(db,'custody',ident,'prior_certificate_on_record_amend_required',{'certificate':existing['id']})
    basis=_certificate_basis(db,ident)
    cert_id='cert-'+ident.replace('/','-')
    h=digest({'certificate':cert_id,'identity':ident,'fingerprint':case['order_fingerprint'],'basis':basis,'at':at})
    db.execute('INSERT INTO destruction_certificates VALUES(?,?,?,?,?,?)',(cert_id,ident,at,json.dumps(basis,sort_keys=True),'',''))
    db.execute("UPDATE custody_cases SET state='completed',closed_at=? WHERE identity=?",(at,ident))
    step(db,ident,'custody.complete',at,{'certificate':cert_id,'basis':basis})
    return event(db,'custody',ident,'completed',{'certificate':cert_id,'basis':basis,'certificate_hash':h})

def amend(db,r):
    """A later-discovered volume can only be handled by supplementing and correcting; old proofs stay on record."""
    ident=r['identity'];at=r['at']
    case=_case(db,ident)
    if not case:return event(db,'custody',ident,'no_case',{})
    old=one(db,"SELECT * FROM destruction_certificates WHERE identity=? AND superseded_by=''",(ident,))
    if not old:return event(db,'custody',ident,'no_prior_certificate',{})
    if case['state'] not in ('reopened','completed','amended','in_progress','open'):
        return event(db,'custody',ident,'case_not_open',{'state':case['state']})
    if pe.order_fingerprint(db,ident,at)!=case['order_fingerprint']:
        db.execute("UPDATE custody_cases SET state='order_changed' WHERE identity=?",(ident,))
        return event(db,'custody',ident,'order_changed',{})
    quarantined=pe.quarantined_copies(db,ident)
    if quarantined:return event(db,'custody',ident,'quarantined_copies_present',{'copies':quarantined})
    incomplete,missing_evidence=_deletion_evaluation(db,ident,at)
    if incomplete:return event(db,'custody',ident,'deletion_incomplete',{'recoverable':incomplete})
    if missing_evidence:return event(db,'custody',ident,'evidence_missing',{'locations':missing_evidence})
    unverified=_hold_evaluation(db,ident,at)
    if unverified:return event(db,'custody',ident,'hold_unverified',{'records':unverified})
    new_id=old['id']+'-amendment-'+str(at)
    basis=_certificate_basis(db,ident)
    db.execute("UPDATE destruction_certificates SET superseded_by=? WHERE id=?",(new_id,old['id']))
    db.execute('INSERT INTO destruction_certificates VALUES(?,?,?,?,?,?)',
               (new_id,ident,at,json.dumps(basis,sort_keys=True),'',r.get('note','late_volume_supplement')))
    db.execute("UPDATE custody_cases SET state='amended',closed_at=? WHERE identity=?",(at,ident))
    step(db,ident,'custody.amend',at,{'old':old['id'],'new':new_id,'note':r.get('note','late_volume_supplement')})
    return event(db,'custody',ident,'amended',{'superseded':old['id'],'certificate':new_id,'basis':basis})

def resume(db,r):
    """Recover an interrupted execution by physical volume, key generation and order version; never re-issue a proof."""
    ident=r['identity'];at=r['at']
    case=_case(db,ident)
    if not case:return event(db,'custody',ident,'no_case',{})
    plan=[]
    for vol in many(db,'SELECT * FROM physical_volumes WHERE identity=?',(ident,)):
        key=one(db,'SELECT * FROM data_keys WHERE id=?',(vol['key_id'],))
        for copy in many(db,'SELECT * FROM volume_copies WHERE volume=?',(vol['id'],)):
            if copy['status']=='quarantined':
                plan.append({'action':'re_verify_or_replace_copy','volume':vol['id'],'copy':copy['id'],'key_generation':key['generation'] if key else None})
            elif copy['status']!='erased':
                live_blocks=[b['id'] for b in many(db,'SELECT id FROM physical_blocks WHERE volume=?',(vol['id'],))
                             if pe.copy_live_block(db,copy['id'],b['id'])]
                if live_blocks:plan.append({'action':'erase_copy','volume':vol['id'],'copy':copy['id'],'blocks':sorted(live_blocks),'key_generation':key['generation'] if key else None})
        if key and key['status']=='active' and not pe.holds_relying_on_key(db,key['id'],ident,at):
            plan.append({'action':'shred_key','key':key['id'],'key_generation':key['generation']})
    for order in pe.active_orders(db,ident,at):
        if order['kind']=='preservation' and not pe.deliveries_for_order(db,order):
            plan.append({'action':'deliver_court','order':order['id'],'order_version':order['version']})
    incomplete,missing=_deletion_evaluation(db,ident,at)
    if not incomplete and not missing and not _hold_evaluation(db,ident,at) and not pe.quarantined_copies(db,ident):
        plan.append({'action':'custody.complete'})
    return event(db,'custody',ident,'resume_plan',{'mode':case['mode'],'state':case['state'],'plan':plan,
                                                   'order_versions':[[o['id'],o['version']] for o in pe.active_orders(db,ident,at)]})

def status(db,r):
    ident=r['identity'];at=r['at']
    case=_case(db,ident)
    tenants=pe.tenant_status(db,ident,at)
    controllers=sorted({c for t in tenants.values() for c in t['controllers_of_recoverable_copies']})
    irrecoverable=sorted({oid for t in tenants.values() for oid in t['irrecoverable_objects']})
    return event(db,'custody',ident,'status',{
        'case':case,'tenants':tenants,'controllers_of_recoverable_copies':controllers,
        'irrecoverable_customer_data':irrecoverable,
        'active_orders':[{'id':o['id'],'version':o['version'],'kind':o['kind'],'subject':o['subject'],
                          'scope':json.loads(o['scope']),'expires':o['expires'],'require_original_ciphertext':o['require_original_ciphertext']==1}
                         for o in pe.active_orders(db,ident,at)],
        'court_deliveries':many(db,'SELECT id,order_id,order_version,custodian,form,scope,byte_digest FROM court_deliveries WHERE identity=?',(ident,)),
        'certificates':many(db,'SELECT id,at,superseded_by,note FROM destruction_certificates WHERE identity=?',(ident,)),
        'quarantined_copies':pe.quarantined_copies(db,ident),
        'volumes':many(db,'SELECT id,key_id,status FROM physical_volumes WHERE identity=?',(ident,)),
        'keys':many(db,'SELECT id,generation,status FROM data_keys WHERE identity=?',(ident,))})
