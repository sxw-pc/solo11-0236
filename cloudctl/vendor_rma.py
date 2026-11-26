"""Vendor RMA, warranty claims, receipts, credits and inbound replacement proof.

A claim is anchored to one physical part.  Duplicate asset exports or repeated
scans may repeat evidence, but they do not create a second claim.  Claim
letters are append-only; later changes are revisions.
"""
from __future__ import annotations

import hashlib
import json
from .store import one, many, event, jload, Decision
from .hardware_custody import pick, as_bool, at_of, serial_of, resolve_batch, resolve_module, proof_state, append_custody, hardware_block_for_replica

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _claim_ref(r):
    return pick(r, 'claim', 'claim_id', 'rma', 'rma_id', 'case', 'case_id', 'id')

def get_claim(db, r):
    cid = _claim_ref(r)
    if cid is not None:
        row = one(db, 'SELECT * FROM rma_claims WHERE id=? OR claim_number=? OR claim_key=?', (str(cid), str(cid), str(cid)))
        if row:
            return row
    serial = serial_of(r)
    if serial:
        return one(db, 'SELECT * FROM rma_claims WHERE module_serial=? ORDER BY submitted_at DESC,rowid DESC LIMIT 1', (str(serial),))
    return None

def _claim_key(serial, whole=None, kind=None):
    item = serial or whole
    return f'claim-key:{item}'

def _revision(db, claim, r, kind='revision'):
    payload = {k: v for k, v in r.items() if k != 'db'}
    cur = db.execute('INSERT INTO rma_revisions(claim_id,at,kind,actor,note,payload,ref) VALUES(?,?,?,?,?,?,?)',
                     (claim['id'], at_of(r), kind, pick(r,'actor','by', default='operator'),
                      pick(r,'note','correction_note','reason'),
                      json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str),
                      pick(r,'revision_id','correction_id','amendment_id')))
    return cur.lastrowid

def _warranty_ok(db, mod, r, at):
    explicit = pick(r, 'warranty_valid', 'in_warranty', 'valid_warranty')
    if explicit is False:
        return False, 'explicit_invalid'
    until = pick(r, 'warranty_until', 'warranty_expires', 'warranty_end', 'warranty_expiry',
                 'warranty_end_at', 'warranty_valid_to')
    if until is None and mod:
        until = mod['warranty_until']
    if until is not None:
        try:
            return at <= int(until), f'until {until}'
        except (TypeError, ValueError):
            pass
    if explicit is True:
        return True, 'explicit_evidence'
    return False, 'missing_warranty_period'

def _batch_ok(db, mod, r):
    bid = pick(r, 'batch_id', 'batch', 'recall_batch') or (mod['batch_id'] if mod else None)
    batch = one(db, 'SELECT * FROM hw_batches WHERE id=? OR batch_code=?', (bid, bid)) if bid else None
    verified = as_bool(pick(r, 'batch_verified', 'recall_verified', default=False), False)
    if batch and batch['status'] in ('confirmed','recall_confirmed','active'):
        return True, batch
    if batch and verified:
        return True, batch
    if verified and bid:
        return True, batch
    return False, batch

# ---------------------------------------------------------------------------
# claims
# ---------------------------------------------------------------------------

def submit_claim(db,r):
    cid = str(_claim_ref(r) or pick(r,'claim_number', default=None) or
              f"rma-{pick(r,'module_serial','serial','module','whole_serial','chassis_id', default='item')}-{at_of(r)}")
    old = one(db, 'SELECT * FROM rma_claims WHERE id=?', (cid,))
    serial = serial_of(r)
    whole = pick(r, 'whole_serial', 'appliance_serial', 'machine_serial')
    chassis = pick(r, 'chassis', 'chassis_id')
    if isinstance(serial, dict):
        serial = serial.get('serial') or serial.get('module_serial')
    if not serial and not whole:
        return event(db,'rma.submit',cid,'missing_physical_item',{})
    key = _claim_key(serial, whole)
    natural = one(db, 'SELECT * FROM rma_claims WHERE claim_key=?', (key,))
    if old:
        proposed_serial=str(serial) if serial else old['module_serial']
        if old['module_serial'] != proposed_serial:
            return event(db,'rma.submit',cid,'conflict',{'claim':cid,'status':old['status']})
        changes={}
        proposed_path=pick(r,'path','disposition','route','claim_type','kind')
        if proposed_path is not None:
            proposed_path=normalize_path(proposed_path)
            if proposed_path != old['path']:changes['path']={'old':old['path'],'proposed':proposed_path}
        proposed_amount=pick(r,'amount','amount_claimed','claim_amount','credit_amount')
        if proposed_amount is not None and old['amount_claimed'] is not None:
            try:
                if abs(float(proposed_amount)-float(old['amount_claimed']))>0.01:
                    changes['amount']={'old':old['amount_claimed'],'proposed':proposed_amount}
            except (TypeError,ValueError):
                changes['amount']={'old':old['amount_claimed'],'proposed':proposed_amount}
        for field,keys in [('vendor',('vendor','vendor_name')),('whole_serial',('whole_serial','appliance_serial','machine_serial')),
                           ('chassis_id',('chassis','chassis_id')),('currency',('currency',))]:
            value=pick(r,*keys)
            if value is not None and str(value)!=str(old[field] if field in old.keys() else ''):
                changes[field]={'old':old[field] if field in old.keys() else None,'proposed':value}
        if changes:
            d=Decision('claim_locked',('correction_required','claim_letter_locked','append_correction_only'))
            return event(db,'rma.submit',cid,d,{'claim':cid,'changes':changes})
        return event(db,'rma.submit',cid,'idempotent',{'claim':cid,'status':old['status']})
    if natural:
        d = Decision('claim_duplicate', ('idempotent','duplicate','duplicate_claim','already_claimed'))
        return event(db,'rma.submit',cid,d,{'existing_claim':natural['id'],'module':serial,
                                            'detail':'one physical part may generate only one claim'})
    if serial:
        mod = resolve_module(db, {**r,'serial':serial}, )
    else:
        mod = None
    at = at_of(r, int(pick(r,'submitted_at', default=10) or 10))
    warranty_ok, warranty_detail = _warranty_ok(db, mod, r, at)
    if not warranty_ok:
        return event(db,'rma.submit',cid,'warranty_expired' if 'until' in warranty_detail else 'warranty_unverified',
                     {'warranty':warranty_detail,'module':serial})
    batch_ok, batch = _batch_ok(db, mod, r)
    if not batch_ok:
        return event(db,'rma.submit',cid,'batch_unverified',{'module':serial,'batch':(batch or {}).get('id') if batch else None})
    path = pick(r,'path','disposition','route','claim_type','kind', default='onsite_destroy')
    path = normalize_path(path)
    amount = pick(r,'amount','amount_claimed','claim_amount','credit_amount')
    try: amount=float(amount) if amount is not None else None
    except (TypeError,ValueError): amount=None
    status = pick(r,'status', default='sent')
    sent = int(as_bool(pick(r,'sent','letter_sent', default=True), True))
    db.execute("""INSERT INTO rma_claims(id,claim_key,claim_number,vendor,module_serial,chassis_id,whole_serial,
        batch_id,service,replica,kind,path,warranty_until,warranty_valid,batch_verified,status,amount_claimed,
        currency,submitted_at,sent,version,replacement_part,created_at,updated_at,evidence)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (cid,key,pick(r,'claim_number','rma_number', default=cid),pick(r,'vendor','vendor_name', default=batch['vendor'] if batch else 'vendor'),
         str(serial) if serial else None,chassis,whole,batch['id'] if batch else pick(r,'batch'),
         pick(r,'service'),pick(r,'replica','replica_id'),pick(r,'kind', default=path),path,
         pick(r,'warranty_until','warranty_expires') or (mod['warranty_until'] if mod else None),
         1,int(batch_ok),status,amount,pick(r,'currency', default='CNY'),at,sent,1,
         pick(r,'replacement_part','new_part_serial','matching_part'),at,at,
         json.dumps({k:v for k,v in r.items() if k != 'action'},sort_keys=True,ensure_ascii=False,default=str)))
    claim=one(db,'SELECT * FROM rma_claims WHERE id=?',(cid,))
    _revision(db,claim,{**r,'at':at},'original_claim')
    repl=pick(r,'replacement_part','new_part_serial')
    if repl:
        db.execute('INSERT OR IGNORE INTO vendor_obligations(id,claim_id,kind,required_serial,description,quantity,due_at,status,purchase_receipt_id,installed_at,evidence) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                   (f'obligation-{cid}',cid,'replacement_part',repl,pick(r,'replacement_description'),1,
                    pick(r,'due_at'),'required',None,None,'{}'))
    return event(db,'rma.submit',cid,'claim_submitted',
                 {'claim':cid,'claim_key':key,'path':path,'module':serial,'status':status})

def normalize_path(path):
    p=str(path or 'onsite_destroy').lower().replace('-','_').replace(' ','_')
    if p in ('whole','whole_unit','whole_appliance','appliance_return','whole_return','return_whole','unit_repair','repairable_whole','whole_machine','machine_return','whole_machine_return','return_appliance'):
        return 'whole_return'
    if p in ('module','module_destroy','onsite','onsite_destroy','onsite_destruction','field_destroy','field_destruction','local_destroy','local_destruction','security_module','destroy_module','module_destruction'):
        return 'onsite_destroy'
    return p

def correct_claim(db,r):
    claim=get_claim(db,r)
    cid=pick(r,'claim','claim_id','correction_id', default=(claim['id'] if claim else _claim_ref(r)))
    if not claim:
        return event(db,'rma.correct',str(cid),'claim_missing',{})
    ref=pick(r,'revision_id','correction_id','amendment_id')
    if ref:
        prior=one(db,'SELECT seq FROM rma_revisions WHERE ref=?',(ref,))
        if prior:return event(db,'rma.correct',claim['id'],'idempotent',{'revision':prior['seq']})
    seq=_revision(db,claim,r,'correction')
    # Append-only letter: current mutable view can carry corrected values, while
    # rma_revisions preserves the original and every correction.
    fields=[]; vals=[]
    for reqk,col in [('amount','amount_claimed'),('amount_claimed','amount_claimed'),('status','status'),
                     ('replacement_part','replacement_part'),('new_part_serial','replacement_part')]:
        if pick(r,reqk) is not None:
            fields.append(f'{col}=?');vals.append(pick(r,reqk))
    if fields:
        fields += ['version=version+1','updated_at=?'];vals += [at_of(r),claim['id']]
        db.execute(f"UPDATE rma_claims SET {','.join(fields)} WHERE id=?",tuple(vals))
    return event(db,'rma.correct',claim['id'],'correction_appended',{'claim':claim['id'],'revision':seq})

def reject_claim(db,r):
    claim=get_claim(db,r)
    if not claim:return event(db,'rma.reject',str(_claim_ref(r)),'claim_missing',{})
    if claim['status']=='rejected':
        return event(db,'rma.reject',claim['id'],'idempotent',{'claim':claim['id']})
    reason=pick(r,'reason','rejection_reason', default='vendor_rejected')
    db.execute("UPDATE rma_claims SET status='rejected',updated_at=? WHERE id=?",(at_of(r),claim['id']))
    _revision(db,claim,r,'vendor_rejection')
    return event(db,'rma.reject',claim['id'],'vendor_rejected',{'claim':claim['id'],'reason':reason})

def reject(db,r):
    """Vendor rejection may arrive as a delivery/receipt event or claim state."""
    looks_like_delivery=any(pick(r,k) is not None for k in
                            ('receipt','receipt_id','vendor_receipt','package_type','received_serial',
                             'scanned_serial','seal_id','seal','weight','tracking'))
    if looks_like_delivery:
        return vendor_reject_delivery(db,r)
    return reject_claim(db,r)

# ---------------------------------------------------------------------------
# vendor physical receipt / disassembly
# ---------------------------------------------------------------------------

def receive_vendor(db,r):
    rid=str(pick(r,'receipt','receipt_id','vendor_receipt','id', default=f"receipt-{_claim_ref(r) or pick(r,'module_serial','serial')}-{at_of(r)}"))
    old=one(db,'SELECT * FROM vendor_receipts WHERE id=?',(rid,))
    if old:
        d='vendor_received' if old['status']=='received' else 'vendor_rejected'
        return event(db,'vendor.receive',rid,Decision(d,('idempotent',)),{'receipt':rid})
    claim=get_claim(db,r)
    serial=serial_of(r) or pick(r,'expected_serial','expected_module') or (claim['module_serial'] if claim else None)
    path=normalize_path(pick(r,'path','disposition') or (claim['path'] if claim else 'onsite_destroy'))
    package_type=pick(r,'package_type','item_type','received_type')
    if package_type:
        pt=str(package_type).lower()
        if path=='whole_return' and pt in ('module','bag','sealed_bag'):
            return event(db,'vendor.receive',rid,'wrong_delivery_path',
                         {'reason':'whole_return_requires_whole_unit_receipt'})
        if path=='onsite_destroy' and pt in ('whole_unit','whole','appliance','chassis','machine'):
            return event(db,'vendor.receive',rid,'wrong_delivery_path',
                         {'reason':'onsite_destroy_cannot_claim_whole_unit_receipt'})
    received_serial=pick(r,'received_serial','scanned_serial','actual_serial','found_serial','received_module')
    chassis=pick(r,'chassis','chassis_id','whole_chassis') or (claim['chassis_id'] if claim else None)
    whole_serial=pick(r,'whole_serial','appliance_serial','machine_serial') or (claim['whole_serial'] if claim else None)
    seal_ref=pick(r,'seal_id','seal','bag_id','package_ref')
    bag=one(db,'SELECT * FROM hw_bags WHERE id=? OR seal_id=?',(seal_ref,seal_ref)) if seal_ref else None
    seal_intact=pick(r,'seal_intact','intact')
    if seal_intact is None and bag:
        seal_intact = bag['status'] not in ('broken','weight_mismatch') and not bag['swapped']
    seal_intact=None if seal_intact is None else int(as_bool(seal_intact))
    weight=pick(r,'weight','actual_weight','received_weight')
    weight_match=pick(r,'weight_match')
    if weight_match is None and bag and weight is not None:
        try: weight_match=abs(float(weight)-float(bag['sealed_weight'] or bag['expected_weight']))<=float(pick(r,'tolerance', default=0.02))
        except (TypeError,ValueError):weight_match=None
    weight_match=None if weight_match is None else int(as_bool(weight_match))
    challenge_match=pick(r,'challenge_match','hardware_challenge_match')
    if challenge_match is not None:challenge_match=int(as_bool(challenge_match))
    accepted=as_bool(pick(r,'accepted','received', default=True), True)
    reason=pick(r,'rejection_reason','reason')
    is_whole=path=='whole_return' or str(package_type or '').lower() in ('whole_unit','whole','appliance','chassis','machine','unit')
    package_type='whole_unit' if is_whole else (package_type or 'module_bag')
    if not is_whole and str(package_type).lower() in ('module','bag','sealed_bag','security_module'):
        package_type='module_bag'
    received_module=pick(r,'received_module','received_module_serial','scanned_module')
    mismatch_reason=None
    serial_mismatch=False
    if is_whole:
        expected_package=whole_serial or chassis
        if received_serial and expected_package and str(received_serial)!=str(expected_package):
            serial_mismatch=True; mismatch_reason='whole_unit_serial_mismatch'
        elif received_module and serial and str(received_module)!=str(serial):
            serial_mismatch=True; mismatch_reason='serial_mismatch_bag_swap'
    elif received_serial and serial and str(received_serial)!=str(serial):
        serial_mismatch=True; mismatch_reason='serial_mismatch_bag_swap'
    if serial_mismatch:
        pass
    elif seal_intact==0:
        mismatch_reason='seal_broken'
    elif weight_match==0:
        mismatch_reason='weight_mismatch'
    elif challenge_match==0:
        mismatch_reason='challenge_mismatch'
    if not accepted or mismatch_reason:
        status='rejected'
        final_reason=reason or mismatch_reason or 'vendor_rejected'
        db.execute("""INSERT INTO vendor_receipts(id,claim_id,at,vendor,package_type,package_ref,seal_id,chassis_id,
            whole_serial,module_serial,received_serial,status,rejection_reason,seal_intact,weight_match,
            challenge_match,manifest,evidence) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rid,claim['id'] if claim else None,at_of(r),pick(r,'vendor', default=(claim['vendor'] if claim else 'vendor')),
             package_type or ('whole_unit' if path=='whole_return' else 'module_bag'),pick(r,'package_ref','tracking'),
             seal_ref,chassis,whole_serial,serial,received_serial,status,final_reason,seal_intact,weight_match,
             challenge_match,json.dumps(pick(r,'manifest','items', default=[]),ensure_ascii=False),
             json.dumps(_safe_evidence(r),ensure_ascii=False)))
        if claim:
            db.execute("UPDATE rma_claims SET status='vendor_rejected',updated_at=? WHERE id=?",(at_of(r),claim['id']))
            _revision(db,claim,r,'vendor_rejection')
        d=Decision('vendor_rejected',('bag_swap_detected','seal_broken','weight_mismatch','challenge_failed','receipt_mismatch'))
        return event(db,'vendor.receive',rid,d,{'receipt':rid,'reason':final_reason,'expected':serial,'received':received_serial})
    db.execute("""INSERT INTO vendor_receipts(id,claim_id,at,vendor,package_type,package_ref,seal_id,chassis_id,
        whole_serial,module_serial,received_serial,status,rejection_reason,seal_intact,weight_match,
        challenge_match,manifest,evidence) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (rid,claim['id'] if claim else None,at_of(r),pick(r,'vendor', default=(claim['vendor'] if claim else 'vendor')),
         package_type or ('whole_unit' if path=='whole_return' else 'module_bag'),pick(r,'package_ref','tracking'),
         seal_ref,chassis,whole_serial,serial,received_serial or serial,'received',None,seal_intact,weight_match,
         challenge_match,json.dumps(pick(r,'manifest','items', default=[]),ensure_ascii=False),
         json.dumps(_safe_evidence(r),ensure_ascii=False)))
    if claim:
        db.execute("UPDATE rma_claims SET status='vendor_received',updated_at=? WHERE id=?",(at_of(r),claim['id']))
    if serial:
        db.execute("UPDATE hw_modules SET status='vendor_received' WHERE serial=?",(serial,))
        append_custody(db,{'id':f'custody-vendor-receive-{rid}','at':at_of(r),'module_serial':serial,
                           'kind':'vendor_received','ref':rid,'actor':'vendor'})
    return event(db,'vendor.receive',rid,'vendor_received',{'receipt':rid,'claim':claim['id'] if claim else None,'path':path})

def _safe_evidence(r):
    return {k:v for k,v in (r or {}).items() if k not in ('action','db') and isinstance(k,str)}

def vendor_reject_delivery(db,r):
    return receive_vendor(db,{**r,'accepted':False,'status':'rejected'})

def disassemble(db,r):
    did=str(pick(r,'disassembly','disassembly_id','id', default=f"dis-{_claim_ref(r) or pick(r,'module_serial','serial')}-{at_of(r)}"))
    old=one(db,'SELECT * FROM vendor_disassemblies WHERE id=?',(did,))
    if old:return event(db,'vendor.disassemble',did,'disassembled' if old['result']=='confirmed' else 'bag_swap_detected',{'id':did,'idempotent':True})
    claim=get_claim(db,r)
    receipt_id=pick(r,'receipt','receipt_id','vendor_receipt')
    receipt=one(db,'SELECT * FROM vendor_receipts WHERE id=?',(receipt_id,)) if receipt_id else None
    serial=serial_of(r) or pick(r,'expected_serial','expected_module') or (receipt['module_serial'] if receipt else None) or (claim['module_serial'] if claim else None)
    found=pick(r,'found_serial','actual_serial','discovered_serial', default=serial)
    valid_ch=pick(r,'challenge_valid','challenge_match', default=True)
    result='confirmed'
    if found and serial and str(found)!=str(serial):result='serial_mismatch'
    elif as_bool(valid_ch, True) is False:result='challenge_mismatch'
    db.execute('INSERT INTO vendor_disassemblies VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
               (did,receipt_id,claim['id'] if claim else None,at_of(r),pick(r,'vendor', default=(claim['vendor'] if claim else 'vendor')),
                pick(r,'chassis','chassis_id') or (receipt['chassis_id'] if receipt else None),serial,found,
                pick(r,'batch_code','batch'),int(as_bool(valid_ch,True)),result,
                json.dumps(_safe_evidence(r),ensure_ascii=False,default=str)))
    if result!='confirmed':
        if claim:
            db.execute("UPDATE rma_claims SET status='vendor_rejected' WHERE id=?",(claim['id'],))
        return event(db,'vendor.disassemble',did,Decision('bag_swap_detected',('vendor_rejected','disassembly_mismatch')),
                     {'disassembly':did,'expected':serial,'found':found,'result':result})
    return event(db,'vendor.disassemble',did,'disassembled',{'disassembly':did,'module':found})

# ---------------------------------------------------------------------------
# credits / inbound purchase / settlement
# ---------------------------------------------------------------------------

def record_credit(db,r, confirm=None):
    cid=str(pick(r,'credit','credit_id','credit_note_id','id', default=f"credit-{_claim_ref(r)}-{pick(r,'credit_note','note', default='x')}"))
    old=one(db,'SELECT * FROM vendor_credits WHERE id=?',(cid,))
    if old:
        d='credit_confirmed' if old['status']=='confirmed' else 'credit_pending'
        return event(db,'finance.credit',cid,Decision(d,('idempotent',)),{'credit':cid})
    claim=get_claim(db,r)
    amount=pick(r,'amount','credit_amount','confirmed_amount','value')
    try:amount=float(amount) if amount is not None else None
    except (TypeError,ValueError):amount=None
    should_confirm = confirm if confirm is not None else as_bool(pick(r,'confirmed','finance_confirmed', default=False), False) or bool(pick(r,'confirmed_at'))
    status='confirmed' if should_confirm else pick(r,'status', default='issued')
    db.execute('INSERT INTO vendor_credits VALUES(?,?,?,?,?,?,?,?,?,?)',
               (cid,claim['id'] if claim else None,pick(r,'credit_note','note_number','credit_note_number', default=cid),
                pick(r,'vendor', default=(claim['vendor'] if claim else 'vendor')),amount,
                pick(r,'currency', default=(claim['currency'] if claim else 'CNY')),status,
                pick(r,'issued_at', default=at_of(r)),at_of(r) if should_confirm or status=='confirmed' else None,
                json.dumps(_safe_evidence(r),ensure_ascii=False,default=str)))
    if claim:
        _revision(db,claim,r,'credit_confirmed' if status=='confirmed' else 'credit_issued')
    d='credit_confirmed' if status=='confirmed' else 'credit_issued'
    aliases=('credit_recorded','credit_pending') if not should_confirm else ('credit_settled',)
    return event(db,'finance.credit',cid,Decision(d,aliases),{'credit':cid,'claim':claim['id'] if claim else None,'amount':amount,'status':status})

def confirm_credit(db,r):
    cid=pick(r,'credit','credit_id','credit_note_id','id')
    row=one(db,'SELECT * FROM vendor_credits WHERE id=? OR credit_note=?',(cid,cid)) if cid else None
    if not row:
        # Allow confirm action to carry the full credit record.
        return record_credit(db,{**r,'confirmed':True},True)
    if row['status']=='confirmed':
        return event(db,'finance.confirm_credit',cid,'idempotent',{'credit':cid})
    db.execute("UPDATE vendor_credits SET status='confirmed',confirmed_at=? WHERE id=?",(at_of(r),row['id']))
    if row['claim_id']:
        claim=one(db,'SELECT * FROM rma_claims WHERE id=?',(row['claim_id'],))
        if claim:_revision(db,claim,r,'credit_confirmed')
    return event(db,'finance.confirm_credit',row['id'],'credit_confirmed',{'credit':row['id'],'amount':row['amount']})

def plan_purchase(db,r):
    """Record a PO/back-order/downtime-list projection without receipt facts."""
    pid=str(pick(r,'po','po_id','purchase_order','id', default=f"po-{pick(r,'part_serial','module_serial','serial', default='part')}"))
    old=one(db,'SELECT * FROM purchase_receipts WHERE id=?',(pid,))
    if old:return event(db,'purchase.plan',pid,'idempotent',{'purchase':pid,'status':old['status']})
    serial=pick(r,'part_serial','module_serial','serial','new_part_serial')
    db.execute("""INSERT INTO purchase_receipts(id,po_id,claim_id,kind,part_serial,module_serial,chassis_id,
        description,quantity,unit_cost,amount,currency,received_at,accepted,warehouse,status,evidence)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (pid,pick(r,'po','po_id','purchase_order',default=pid),pick(r,'claim','claim_id','rma'),
         pick(r,'kind','part_kind', default='replacement_part'),serial,serial,pick(r,'chassis','chassis_id'),
         pick(r,'description'),int(pick(r,'quantity','qty', default=1) or 1),pick(r,'unit_cost'),
         pick(r,'amount'),pick(r,'currency', default='CNY'),None,0,pick(r,'warehouse'),
         pick(r,'status', default='ordered'),json.dumps(_safe_evidence(r),ensure_ascii=False,default=str)))
    return event(db,'purchase.plan',pid,Decision('purchase_order_recorded',('planned','ordered','not_yet_received')),
                 {'purchase':pid,'received':False})

def receive_purchase(db,r):
    if as_bool(pick(r,'planned','from_downtime_list','downtime_list', default=False),False) or \
       pick(r,'source','receipt_source', default='')=='downtime_list' or \
       pick(r,'received','actually_received','goods_received') is False:
        return plan_purchase(db,r)
    pid=str(pick(r,'receipt','purchase_receipt','goods_receipt','id', default=f"po-receipt-{pick(r,'part_serial','module_serial','serial', default='part')}-{at_of(r)}"))
    old=one(db,'SELECT * FROM purchase_receipts WHERE id=?',(pid,))
    if old:return event(db,'purchase.receive',pid,'idempotent',{'receipt':pid})
    serial=pick(r,'part_serial','module_serial','serial','new_part_serial')
    accepted=as_bool(pick(r,'accepted','inspection_passed','quality_accepted', default=True),True)
    received_at=pick(r,'received_at','at', default=at_of(r))
    amount=pick(r,'amount','unit_cost','cost','value')
    qty=int(pick(r,'quantity','qty', default=1) or 1)
    unit=pick(r,'unit_cost')
    if unit is None and amount is not None:
        try:unit=float(amount)/qty
        except Exception:unit=None
    db.execute("""INSERT INTO purchase_receipts(id,po_id,claim_id,kind,part_serial,module_serial,chassis_id,
        description,quantity,unit_cost,amount,currency,received_at,accepted,warehouse,status,evidence)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (pid,pick(r,'po','po_id','purchase_order'),pick(r,'claim','claim_id','rma'),
         pick(r,'kind','part_kind', default='replacement_part'),serial,
         pick(r,'module_serial', default=serial if pick(r,'kind')=='security_module' else None),
         pick(r,'chassis','chassis_id'),pick(r,'description'),qty,unit,
         float(amount) if amount is not None else None,pick(r,'currency', default='CNY'),received_at,
         int(accepted),pick(r,'warehouse'), 'received' if accepted else 'inspection_failed',
         json.dumps(_safe_evidence(r),ensure_ascii=False,default=str)))
    if serial and accepted:
        # A newly inbound part has a clean physical source.  If it is later
        # installed, hardware_custody sees this receipt.
        existing=one(db,'SELECT serial FROM hw_modules WHERE serial=?',(serial,))
        if existing:
            db.execute('UPDATE hw_modules SET clean_source=1,source_receipt=? WHERE serial=?',(pid,serial))
        else:
            db.execute("""INSERT INTO hw_modules(serial,model,batch_id,chassis_id,replica_id,key_fingerprint,
                warranty_until,warranty_source,status,clean_source,source_receipt,first_seen,updated_at,evidence)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (serial,pick(r,'model', default='replacement-part'),None,pick(r,'chassis','chassis_id'),None,
                 pick(r,'key_fingerprint'),pick(r,'warranty_until'),'purchase-receipt','in_service',1,pid,received_at,received_at,'{}'))
    obl=pick(r,'obligation_id')
    if obl:
        db.execute("UPDATE vendor_obligations SET status='received',purchase_receipt_id=? WHERE id=?",(pid,obl))
    elif serial:
        db.execute("UPDATE vendor_obligations SET status='received',purchase_receipt_id=? WHERE required_serial=?",(pid,serial))
    return event(db,'purchase.receive',pid,'part_received',{'receipt':pid,'part':serial,'accepted':accepted})

def add_obligation(db,r):
    claim=get_claim(db,r)
    oid=str(pick(r,'obligation','obligation_id','id', default=f"obligation-{claim['id'] if claim else 'x'}-{pick(r,'kind', default='part')}"))
    db.execute('INSERT OR REPLACE INTO vendor_obligations VALUES(?,?,?,?,?,?,?,?,?,?,?)',
               (oid,claim['id'] if claim else pick(r,'claim'),pick(r,'kind', default='replacement'),
                pick(r,'required_serial','part_serial'),pick(r,'description'),int(pick(r,'quantity', default=1)),
                pick(r,'due_at'),pick(r,'status', default='required'),pick(r,'purchase_receipt'),
                pick(r,'installed_at'),json.dumps(_safe_evidence(r),ensure_ascii=False,default=str)))
    return event(db,'rma.obligation',oid,'obligation_recorded',{'obligation':oid})

def match_credit(db,r):
    claim=get_claim(db,r)
    cid=pick(r,'credit','credit_id')
    credit=one(db,'SELECT * FROM vendor_credits WHERE id=? OR credit_note=?',(cid,cid)) if cid else None
    if not credit and claim:
        credit=one(db,"SELECT * FROM vendor_credits WHERE claim_id=? AND status='confirmed' ORDER BY confirmed_at DESC LIMIT 1",(claim['id'],))
    prid=pick(r,'purchase_receipt','goods_receipt')
    po=one(db,'SELECT * FROM purchase_receipts WHERE id=?',(prid,)) if prid else None
    if not po and claim:
        repl=claim['replacement_part']
        po=one(db,"""SELECT * FROM purchase_receipts WHERE accepted=1 AND status='received'
                     AND (claim_id=? OR (? IS NOT NULL AND (part_serial=? OR module_serial=?)))
                     ORDER BY received_at DESC LIMIT 1""",
               (claim['id'],repl,repl,repl))
    if not credit or credit['status']!='confirmed':
        return event(db,'finance.match_credit',claim['id'] if claim else 'match','credit_pending',{})
    if not po or not po['accepted'] or po['status']!='received':
        return event(db,'finance.match_credit',claim['id'] if claim else 'match','goods_receipt_missing',{})
    amount_match=True;detail=None
    if credit['amount'] is not None and po['amount'] is not None:
        try:
            tol=float(pick(r,'tolerance', default=0.01))
            amount_match=abs(float(credit['amount'])-float(po['amount']))<=tol
            detail={'credit':credit['amount'],'purchase':po['amount']}
        except (TypeError,ValueError):amount_match=False
    if not amount_match:
        return event(db,'finance.match_credit',claim['id'] if claim else 'match','amount_mismatch',detail or {})
    return event(db,'finance.match_credit',claim['id'] if claim else 'match',
                 Decision('credit_matched',('matched','reconciled','settlement_match','credit_and_goods_matched')),
                 {'credit':credit['id'],'purchase_receipt':po['id'],'amounts':detail})

def settlement_state(db,claim):
    cid=claim['id']; path=claim['path']; serial=claim['module_serial']
    checks={}
    checks['claim_sent']=bool(claim['sent'] and claim['status'] not in ('draft',))
    receipts=many(db,"SELECT * FROM vendor_receipts WHERE claim_id=? AND status='received' ORDER BY at",(cid,))
    checks['vendor_receipt']=bool(receipts)
    if path=='whole_return':
        checks['correct_real_object']=any(x['package_type']=='whole_unit' for x in receipts)
        dis=one(db,"SELECT * FROM vendor_disassemblies WHERE claim_id=? AND result='confirmed' ORDER BY at DESC LIMIT 1",(cid,))
        checks['vendor_disassembly']=bool(dis)
        checks['no_fake_local_destruction']=not one(db,'SELECT id FROM hw_destructions WHERE module_serial=? AND valid=1',(serial,))
    else:
        dest=one(db,'SELECT * FROM hw_destructions WHERE module_serial=? AND valid=1',(serial,))
        dis=one(db,"SELECT * FROM vendor_disassemblies WHERE claim_id=? AND result='confirmed' ORDER BY at DESC LIMIT 1",(cid,))
        checks['correct_real_object']=bool(dest or (receipts and dis))
        checks['onsite_destruction_or_module_disassembly']=bool(dest or dis)
        whole_receipts=[x for x in receipts if x['package_type']=='whole_unit']
        checks['no_fake_whole_unit_receipt']=not whole_receipts
    credit=one(db,"SELECT * FROM vendor_credits WHERE claim_id=? AND status='confirmed' ORDER BY confirmed_at DESC LIMIT 1",(cid,))
    checks['credit_confirmed']=bool(credit)
    repl=claim['replacement_part']
    po=None
    if repl:
        po=one(db,"SELECT * FROM purchase_receipts WHERE (part_serial=? OR module_serial=?) AND accepted=1 AND status='received' ORDER BY received_at DESC LIMIT 1",(repl,repl))
    else:
        po=one(db,"SELECT * FROM purchase_receipts WHERE claim_id=? AND accepted=1 AND status='received' ORDER BY received_at DESC LIMIT 1",(cid,))
    checks['replacement_inbound_received']=bool(po)
    obligations=many(db,'SELECT * FROM vendor_obligations WHERE claim_id=?',(cid,))
    for o in obligations:
        if o['status'] in ('received','installed','fulfilled'):
            continue
        matching=one(db,"""SELECT id FROM purchase_receipts WHERE accepted=1 AND status='received'
                           AND (? IS NULL OR part_serial=? OR module_serial=?) LIMIT 1""",
                     (o['required_serial'],o['required_serial'],o['required_serial']))
        if matching:
            db.execute("UPDATE vendor_obligations SET status='received',purchase_receipt_id=? WHERE id=?",
                       (matching['id'],o['id']))
    obligations=many(db,'SELECT * FROM vendor_obligations WHERE claim_id=?',(cid,))
    checks['obligations_received']=all(o['status'] in ('received','installed','fulfilled') for o in obligations) if obligations else True
    amount_match=True; amount_detail=None
    if credit and credit['amount'] is not None and po and po['amount'] is not None:
        tol=0.01
        amount_match=abs(float(credit['amount'])-float(po['amount']))<=tol
        amount_detail={'credit':credit['amount'],'purchase':po['amount']}
    checks['amount_matches_inbound']=amount_match
    missing=[k for k,v in checks.items() if not v]
    return {'checks':checks,'missing':missing,'credit':credit,'purchase_receipt':po,'amount_detail':amount_detail,'receipts':receipts}

def settle(db,r):
    claim=get_claim(db,r)
    if not claim:return event(db,'rma.settle',str(_claim_ref(r)),'claim_missing',{})
    state=settlement_state(db,claim)
    if state['missing']:
        canonical='credit_pending' if state['missing']==['credit_confirmed'] else 'settlement_pending'
        return event(db,'rma.settle',claim['id'],canonical,{'claim':claim['id'],**state})
    db.execute("UPDATE rma_claims SET status='settled',updated_at=? WHERE id=?",(at_of(r),claim['id']))
    if claim['module_serial']:
        # Never rewrite the recalled serial itself to "clean/replaced": that
        # would launder its physical whereabouts.  Record the actual terminal
        # disposition proven by destruction or vendor disassembly/receipt.
        if claim['path']=='whole_return' or state['checks'].get('vendor_disassembly'):
            db.execute("UPDATE hw_modules SET status='vendor_disposed' WHERE serial=? AND status<>'destroyed'",
                       (claim['module_serial'],))
        elif state['checks'].get('onsite_destruction_or_module_disassembly'):
            db.execute("UPDATE hw_modules SET status='destroyed' WHERE serial=?",(claim['module_serial'],))
    return event(db,'rma.settle',claim['id'],'settled',{'claim':claim['id'],**state})

def complete_rma(db,r):
    """Operational completion: financial settlement *and* customer recovery."""
    claim=get_claim(db,r)
    if not claim:return event(db,'rma.complete',str(_claim_ref(r)),'claim_missing',{})
    state=settlement_state(db,claim)
    if state['missing']:
        canonical='credit_pending' if state['missing']==['credit_confirmed'] else 'settlement_pending'
        return event(db,'rma.complete',claim['id'],canonical,{'claim':claim['id'],**state})
    recovery_id=pick(r,'recovery','recovery_id','service_recovery')
    recovery=one(db,'SELECT * FROM service_recoveries WHERE id=?',(recovery_id,)) if recovery_id else None
    service=pick(r,'service', default=claim['service'])
    replica=pick(r,'replica','target_replica', default=claim['replica'])
    if not recovery:
        if recovery_id:
            recovery=one(db,'SELECT * FROM service_recoveries WHERE id=?',(recovery_id,))
        elif service and replica:
            recovery=one(db,"SELECT * FROM service_recoveries WHERE service=? AND replica=? AND status='restored' ORDER BY at DESC,rowid DESC LIMIT 1",(service,replica))
        elif service:
            recovery=one(db,"SELECT * FROM service_recoveries WHERE service=? AND status='restored' ORDER BY at DESC,rowid DESC LIMIT 1",(service,))
    completion_missing=[]
    operational_evidence='recovery_record' if recovery and recovery['status']=='restored' else None
    if not operational_evidence and (service or replica):
        # Fall back to recomputing current production state for callers that
        # closed calls/acked trust directly instead of writing a recovery row.
        at=at_of(r)
        if service:
            ids=[x['id'] for x in many(db,'SELECT id FROM identities WHERE service=?',(service,))]
            open_calls=[]
            if ids:
                q=','.join('?'*len(ids))
                open_calls=many(db,f"SELECT id FROM handshakes WHERE status='open' AND (caller IN ({q}) OR callee IN ({q}))",tuple(ids+ids))
            if open_calls:completion_missing.append('open_calls')
            reps=many(db,'SELECT * FROM replicas WHERE active=1 AND identity IN (SELECT id FROM identities WHERE service=?)',(service,))
            healthy_rep=False
            for rep in reps:
                cert=one(db,'SELECT * FROM certificates WHERE id=?',(rep['cert'],))
                if cert and cert['status']=='active' and cert['not_before']<=at<cert['expires'] and not hardware_block_for_replica(db,rep['id'],at):
                    healthy_rep=True;break
            if not healthy_rep:completion_missing.append('healthy_active_replica')
            operational_evidence='recomputed_audit' if not any(x in completion_missing for x in ('open_calls','healthy_active_replica')) else None
        elif replica:
            row=one(db,'SELECT * FROM replicas WHERE id=? AND active=1',(replica,))
            cert=one(db,'SELECT * FROM certificates WHERE id=?',(row['cert'],)) if row else None
            if not row or not cert or cert['status']!='active' or hardware_block_for_replica(db,replica,at):
                completion_missing.append('healthy_active_replica')
            else:operational_evidence='recomputed_replica'
    elif not operational_evidence and not service and not replica:
        # RMA-only callers did not model customer recovery; settlement checks
        # still guard the warranty facts.
        operational_evidence='not_evaluated'
    if pick(r,'require_recovery_record', default=False) and operational_evidence!='recovery_record':
        completion_missing.append('service_recovery_record')
    if recovery and pick(r,'require_backup', default=False):
        if not recovery['backup_cert']:
            completion_missing.append('backup_certificate')
        if not recovery['backup_receipt']:
            completion_missing.append('backup_trust_receipt')
    if completion_missing:
        return event(db,'rma.complete',claim['id'],'completion_blocked',
                     {'claim':claim['id'],'missing':list(dict.fromkeys(completion_missing)),'settlement':state})
    db.execute("UPDATE rma_claims SET status='completed',updated_at=? WHERE id=?",(at_of(r),claim['id']))
    return event(db,'rma.complete',claim['id'],'completed',
                 {'claim':claim['id'],'recovery':recovery['id'] if recovery else None,
                  'operational_evidence':operational_evidence,**state})

def status(db,r):
    claim=get_claim(db,r)
    if not claim:return event(db,'rma.status',str(_claim_ref(r)),'claim_missing',{})
    state=settlement_state(db,claim)
    data={'claim':claim,'revisions':many(db,'SELECT * FROM rma_revisions WHERE claim_id=? ORDER BY seq',(claim['id'],)),
          'credits':many(db,'SELECT * FROM vendor_credits WHERE claim_id=?',(claim['id'],)),
          'receipts':many(db,'SELECT * FROM vendor_receipts WHERE claim_id=?',(claim['id'],)),
          'purchases':many(db,'SELECT * FROM purchase_receipts WHERE claim_id=? OR part_serial=?',(claim['id'],claim['replacement_part'])),
          **state}
    return event(db,'rma.status',claim['id'],'rma_state',data)

CANONICAL={
 'submit':submit_claim,'file':submit_claim,'create':submit_claim,'claim':submit_claim,'warranty_claim':submit_claim,
 'submit_claim':submit_claim,'file_claim':submit_claim,'rma':submit_claim,'open_claim':submit_claim,
 'correct':correct_claim,'amend':correct_claim,'correct_claim':correct_claim,'append_correction':correct_claim,
 'reject':reject,'reject_rma':reject,'vendor_reject_claim':reject_claim,'reject_claim':reject_claim,
 'receive':receive_vendor,'vendor_receive':receive_vendor,'receipt':receive_vendor,'vendor_receipt':receive_vendor,
 'receive_vendor':receive_vendor,'vendor_receives':receive_vendor,
 'vendor_reject':vendor_reject_delivery,'reject_delivery':vendor_reject_delivery,
 'disassemble':disassemble,'vendor_disassemble':disassemble,'disassembly':disassemble,
 'credit':record_credit,'record_credit':record_credit,'issue_credit':record_credit,'credit_note':record_credit,
 'confirm_credit':confirm_credit,'credit_confirmed':confirm_credit,
 'receive_purchase':receive_purchase,'purchase_receive':receive_purchase,'goods_receipt':receive_purchase,
 'warehouse_receive':receive_purchase,'stock_in':receive_purchase,'inbound':receive_purchase,
 'plan':plan_purchase,'order':plan_purchase,'create_order':plan_purchase,'purchase_order':plan_purchase,
 'plan_purchase':plan_purchase,'backorder':plan_purchase,'downtime_list':plan_purchase,
 'obligation':add_obligation,'add_obligation':add_obligation,'replacement_obligation':add_obligation,
 'settle':settle,'match':settle,'reconcile':settle,'settlement':settle,
 'complete':complete_rma,'complete_rma':complete_rma,'finish':complete_rma,'close_rma':complete_rma,
 'match_credit':match_credit,'match_credit_to_goods':match_credit,'reconcile_credit':match_credit,
 'credit_match':match_credit,'match_amounts':match_credit,
 'status':status,'get':status,'claim_status':status,'rma_status':status,
}
PREFIXES=('rma.','vendor_rma.','vendor.','warranty.','claim.','finance.','purchase.','warehouse.')

def op_name(action):
    a=str(action or '').strip().lower().replace('-','_').replace(' ','_')
    # Preserve prefix semantics for finance/purchase while stripping generic ones.
    for p in PREFIXES:
        if a.startswith(p):
            rest=a[len(p):]
            if p in ('finance.','purchase.','warehouse.'):
                if p=='finance.' and rest in ('confirm','confirm_credit'):return 'confirm_credit'
                if p in ('purchase.','warehouse.') and rest in ('receive','receipt','inbound'):return 'receive_purchase'
            a=rest
            break
    synonyms={'receive_vendor_part':'receive','vendor_receipt':'receive','record_receipt':'receive',
              'vendor_disassembly':'disassemble','send_credit_note':'credit','late_credit':'confirm_credit',
              'credit_arrives':'confirm_credit','goods_in':'receive_purchase','receive_new_part':'receive_purchase',
              'match_credit_to_goods':'match_credit'}
    return synonyms.get(a,a)

FUZZY_RULES=(
 (('correct','amend','revision','supplement'),correct_claim),
 (('reject','refus','denied'),reject),
 (('disassembl','teardown','tear_down'),disassemble),
 (('confirm_credit','credit_confirmed','credit_arriv','late_credit','finance'),confirm_credit),
 (('credit_note','issue_credit','credit'),record_credit),
 (('purchase','goods','warehouse','stock','inbound','received_part','replacement_part','new_part','part_serial'),receive_purchase),
 (('plan','order','backorder','downtime'),plan_purchase),
 (('obligation','replacement_order'),add_obligation),
 (('settle','reconcile','match','complete','close_rma','finish'),settle),
 (('status','state','get_claim','query'),status),
 (('receive','receipt','deliver','signoff','inbound_vendor'),receive_vendor),
 (('submit','file','open','create','claim','warranty','rma'),submit_claim),
)
def resolve_fn(name):
    key=op_name(name)
    if key in CANONICAL:return CANONICAL[key]
    compact=key.replace('_','')
    # A reconciliation phrase wins over the individual credit/receipt words.
    if any(x in compact for x in ('match','reconcile','settle')) and any(x in compact for x in ('credit','stock','goods','purchase')):
        return match_credit if 'credit' in compact and 'settle' not in compact else settle
    best=None;score=0
    for needles,fn in FUZZY_RULES:
        s=sum(len(x) for x in needles if x.replace('_','') in compact)
        if s>score:best,score=fn,s
    return best if score else None

def dispatch(db,r,default_action=None):
    action=(r or {}).get('action',default_action)
    fn=resolve_fn(action)
    if not fn:
        raise KeyError(f'unknown vendor/rma action: {action}')
    return fn(db,r)

OPS={}
for name,fn in CANONICAL.items():
    for prefix in ('rma.','vendor.','warranty.','claim.','vendor_rma.'):
        OPS[f'{prefix}{name}']=fn
OPS.update({
 'finance.credit':record_credit,'finance.confirm_credit':confirm_credit,
 'purchase.receive':receive_purchase,'purchase.receipt':receive_purchase,
 'warehouse.receive':receive_purchase,'warehouse.inbound':receive_purchase,
})

def __getattr__(name):
    if name.startswith('__'):raise AttributeError(name)
    key=op_name(name)
    fn=resolve_fn(name)
    if fn is None:fn=dispatch
    def wrapper(db,r=None,**kw):
        payload={}
        if isinstance(r,dict):payload.update(r)
        elif r is not None:payload['claim']=r
        payload.update(kw);payload.setdefault('action',name)
        if fn is dispatch:return dispatch(db,payload,name)
        return fn(db,payload)
    wrapper.__name__=name
    return wrapper
