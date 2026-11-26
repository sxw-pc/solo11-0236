"""Physical hardware recall custody.

The important boundary in this module is a real module serial.  Chassis labels,
asset exports and logical replica ids are evidence/indices, never identities
that can launder a recalled module into a clean state.
"""
from __future__ import annotations

import hashlib
import json
from .store import one, many, event, jload, Decision

# ---------------------------------------------------------------------------
# request adaptation helpers
# ---------------------------------------------------------------------------

def pick(r, *keys, default=None):
    if not isinstance(r, dict):
        return default
    for k in keys:
        if k in r and r[k] is not None:
            return r[k]
    return default

def as_bool(v, default=False):
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    return str(v).strip().lower() in {'1','true','yes','y','valid','verified','ok','confirmed','intact'}

def at_of(r, default=0):
    v = pick(r, 'at', 'time', 'ts', 'timestamp', 'minute', 'observed_at', default=default)
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

def serial_of(r):
    return pick(r, 'module_serial', 'serial', 'module', 'module_id', 'physical_module',
                'part_serial', 'serial_number', 'hardware_serial', 'new_module',
                'replacement_serial', 'physical_serial', 'part')

def chassis_of(r):
    return pick(r, 'chassis', 'chassis_id', 'chassis_serial', 'rack', 'rack_id',
                'enclosure', 'enclosure_id', 'machine', 'machine_id', 'host', 'host_id',
                'chassis_no', 'chassis_number')

def _id(r, prefix, *natural):
    v = pick(r, 'id', prefix + '_id', prefix + 'Id')
    if v:
        return str(v)
    base = '|'.join(str(x) for x in natural if x is not None)
    digest = hashlib.sha1(base.encode('utf-8')).hexdigest()[:16]
    return f'{prefix}-{digest}'

def _subject(r, fallback='hardware'):
    return str(pick(r, 'subject', 'id', 'module', 'serial', 'module_serial', 'claim', default=fallback))

def _evidence(r, extra=None):
    ev = dict(pick(r, 'evidence', default={}) or {})
    if not isinstance(ev, dict):
        ev = {'raw_evidence': ev}
    for k in ('note','notes','witness','actor','source_system','system','tracking','tracking_id','seal_id'):
        if pick(r, k) is not None:
            ev.setdefault(k, pick(r, k))
    if extra:
        ev.update(extra)
    return ev

def _same(existing, payload, keys):
    return all(existing.get(k) == payload.get(k) for k in keys if k in payload)

# ---------------------------------------------------------------------------
# lookup and materialization
# ---------------------------------------------------------------------------

def resolve_batch(db, r, create=False):
    ref = pick(r, 'batch', 'batch_id', 'recall_batch', 'campaign', 'campaign_id', 'batch_code')
    if isinstance(ref, dict):
        rd = ref
        r = {**rd, **{k: v for k, v in r.items() if k not in ('batch', 'batch_id')}}
        ref = pick(rd, 'id', 'batch_id', 'batch_code')
    batch = None
    if ref is not None:
        batch = one(db, 'SELECT * FROM hw_batches WHERE id=? OR batch_code=?', (str(ref), str(ref)))
    if batch or not create:
        return batch
    bid = str(pick(r, 'batch_id', 'id', 'batch', 'recall_batch', default=ref or 'batch'))
    code = pick(r, 'batch_code', 'code', 'lot', 'lot_code', default=bid)
    vendor = pick(r, 'vendor', 'vendor_name', 'manufacturer', default='unknown-vendor')
    model = pick(r, 'model', 'module_model', 'product', default='unknown-model')
    signed = as_bool(pick(r, 'signed', 'signature_valid', 'vendor_signed', 'authenticated',
                          'vendor_signature', 'signature', 'signed_statement', default=True), True)
    announced = at_of(r, int(pick(r, 'announced_at', default=10) or 10))
    warranty_until = pick(r, 'warranty_until', 'warranty_expires', 'warranty_end', 'warranty_valid_until', 'warranty_expiry', 'warranty_end_at', 'warranty_valid_to')
    terms = pick(r, 'terms', 'warranty_terms', default={}) or {}
    db.execute("""INSERT INTO hw_batches(id,vendor,model,batch_code,signed_by,signature_valid,
        announced_at,warranty_until,module_disposition,whole_disposition,terms,status,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (bid, vendor, model, code, pick(r,'signed_by','signer',default='vendor-key'), int(signed),
         announced, warranty_until,
         pick(r,'module_disposition','module_warranty',default='destroy_only'),
         pick(r,'whole_disposition','whole_warranty',default='repair_or_replace'),
         json.dumps(terms, ensure_ascii=False), pick(r,'batch_status','status',default='announced'), announced))
    return one(db, 'SELECT * FROM hw_batches WHERE id=?', (bid,))

def resolve_module(db, r, create=True):
    ref = pick(r, 'module_serial', 'serial', 'module', 'module_id', 'physical_module',
               'part_serial', 'serial_number', 'hardware_serial', 'new_module', 'replacement_serial', 'part')
    if isinstance(ref, dict):
        nested = ref
        ref = pick(nested, 'serial', 'module_serial', 'id')
        r = {**nested, **r}
    if ref is None:
        return None
    serial = str(ref)
    mod = one(db, 'SELECT * FROM hw_modules WHERE serial=?', (serial,))
    if mod or not create:
        return mod
    batch = resolve_batch(db, r, create=as_bool(pick(r,'create_batch','auto_batch',default=False), False))
    batch_id = pick(r, 'batch_id', 'recall_batch', 'batch')
    if batch:
        batch_id = batch['id']
    warranty_until = pick(r, 'warranty_until', 'warranty_expires', 'warranty_end', 'warranty_valid_until', 'warranty_expiry', 'warranty_end_at', 'warranty_valid_to')
    now = at_of(r)
    clean = as_bool(pick(r, 'clean_source', 'clean', 'verified_source', default=False), False)
    db.execute("""INSERT INTO hw_modules(serial,model,batch_id,chassis_id,replica_id,key_fingerprint,
        warranty_until,warranty_source,status,clean_source,source_receipt,first_seen,updated_at,evidence)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (serial, pick(r,'model','module_model', default='unknown-model'), batch_id,
         pick(r,'chassis','chassis_id','rack','enclosure','machine'),
         pick(r,'replica','replica_id'),
         pick(r,'key_fingerprint','fingerprint','public_key_fingerprint','key_id'),
         warranty_until, pick(r,'warranty_source', default='vendor-terms'),
         pick(r,'module_status','status', default='in_service'), int(clean),
         pick(r,'source_receipt','purchase_receipt','goods_receipt'), now, now,
         json.dumps(_evidence(r), ensure_ascii=False)))
    return one(db, 'SELECT * FROM hw_modules WHERE serial=?', (serial,))

def upsert_chassis(db, r, chassis_id=None, module_serial=None):
    cid = chassis_id or pick(r, 'chassis', 'chassis_id', 'chassis_serial', 'rack', 'rack_id',
                             'enclosure', 'enclosure_id', 'machine', 'machine_id', 'host', 'host_id',
                             'chassis_no', 'chassis_number')
    if cid is None:
        return None
    cid = str(cid)
    row = one(db, 'SELECT * FROM hw_chassis WHERE id=?', (cid,))
    now = at_of(r)
    if not row:
        db.execute('INSERT INTO hw_chassis(id,label,serial,current_module,status,updated_at,evidence) VALUES(?,?,?,?,?,?,?)',
                   (cid, pick(r,'chassis_label','label', default=cid), pick(r,'chassis_serial','machine_serial', default=cid),
                    module_serial, pick(r,'chassis_status','status', default='in_service'), now,
                    json.dumps(_evidence(r), ensure_ascii=False)))
    elif module_serial:
        db.execute('UPDATE hw_chassis SET current_module=?,updated_at=? WHERE id=?', (module_serial, now, cid))
    return one(db, 'SELECT * FROM hw_chassis WHERE id=?', (cid,))

def bind_certificate(db, cert_id, module_serial=None, key_fingerprint=None, source='request', at=None, identity=None, evidence=None):
    if not cert_id:
        return None
    cert = one(db, 'SELECT * FROM certificates WHERE id=?', (cert_id,))
    identity = identity or (cert['identity'] if cert else None)
    if not module_serial:
        rh = one(db, 'SELECT module_serial,key_fingerprint FROM replica_hardware WHERE key_fingerprint IS NOT NULL AND replica IN (SELECT id FROM replicas WHERE cert=?)', (cert_id,))
        if rh:
            module_serial = rh['module_serial']
            key_fingerprint = key_fingerprint or rh['key_fingerprint']
    if not key_fingerprint and module_serial:
        key_fingerprint = f'hw-key:{module_serial}'
    if key_fingerprint is None and cert:
        # The simulation has no real private key.  Root alone is not a key, so
        # only synthesize a stable origin when a physical module is named.
        key_fingerprint = f'cert:{cert_id}' if module_serial else None
    old = one(db, 'SELECT * FROM certificate_origins WHERE cert_id=?', (cert_id,))
    if old:
        if module_serial and old['module_serial'] and module_serial != old['module_serial']:
            # A cert/key cannot silently migrate to another physical module;
            # retain the original origin for recall/key-reuse checks.
            return old
        return old
    db.execute('INSERT INTO certificate_origins VALUES(?,?,?,?,?,?,?)',
               (cert_id, identity, module_serial, key_fingerprint, source, at or 0,
                json.dumps(evidence or {}, sort_keys=True, ensure_ascii=False)))
    return one(db, 'SELECT * FROM certificate_origins WHERE cert_id=?', (cert_id,))

def record_replica_binding(db, replica_id, identity_id=None, cert_id=None, active=None, at=None, r=None):
    if not replica_id:
        return
    r = r or {}
    module_serial = serial_of(r)
    chassis_id = pick(r, 'chassis', 'chassis_id', 'rack', 'rack_id', 'enclosure', 'machine', 'host',
                      'chassis_no', 'chassis_number')
    fp = pick(r, 'key_fingerprint', 'fingerprint', 'public_key_fingerprint')
    if not module_serial and not chassis_id:
        return one(db, 'SELECT * FROM replica_hardware WHERE replica=?', (replica_id,))
    old = one(db, 'SELECT * FROM replica_hardware WHERE replica=?', (replica_id,))
    ev = _evidence(r)
    if old:
        db.execute("""UPDATE replica_hardware SET module_serial=COALESCE(?,module_serial),
            chassis_id=COALESCE(?,chassis_id),key_fingerprint=COALESCE(?,key_fingerprint),
            source=?,at=?,evidence=? WHERE replica=?""",
                   (module_serial, chassis_id, fp, pick(r,'source', default='identity.replica'), at or at_of(r),
                    json.dumps(ev, ensure_ascii=False), replica_id))
    else:
        db.execute('INSERT INTO replica_hardware VALUES(?,?,?,?,?,?,?)',
                   (replica_id, module_serial, chassis_id, fp, pick(r,'source', default='identity.replica'),
                    at or at_of(r), json.dumps(ev, ensure_ascii=False)))
    if module_serial:
        resolve_module(db, {**r, 'serial': module_serial, 'chassis': chassis_id, 'replica': replica_id})
        db.execute('UPDATE hw_modules SET chassis_id=COALESCE(?,chassis_id),replica_id=? WHERE serial=?',
                   (chassis_id, replica_id, module_serial))
    if chassis_id:
        upsert_chassis(db, r, chassis_id, module_serial)
    if cert_id:
        bind_certificate(db, cert_id, module_serial, fp, 'identity.replica', at or at_of(r), identity_id)
    return one(db, 'SELECT * FROM replica_hardware WHERE replica=?', (replica_id,))

# ---------------------------------------------------------------------------
# history / candidate location
# ---------------------------------------------------------------------------

def candidate_chassis(db, serial, batch_id=None):
    ids = []
    def add(x):
        if x and x not in ids:
            ids.append(x)
    m = one(db, 'SELECT chassis_id,batch_id FROM hw_modules WHERE serial=?', (serial,)) if serial else None
    if m:
        add(m['chassis_id'])
    if serial:
        for row in many(db, 'SELECT DISTINCT chassis_id FROM hw_install_events WHERE module_serial=? AND chassis_id IS NOT NULL', (serial,)):
            add(row['chassis_id'])
        for row in many(db, "SELECT DISTINCT related_id AS chassis_id FROM hw_install_events WHERE module_serial=? AND action='move' AND related_id IS NOT NULL", (serial,)):
            add(row['chassis_id'])
        for row in many(db, 'SELECT DISTINCT chassis_id FROM hw_asset_records WHERE module_serial=? AND chassis_id IS NOT NULL', (serial,)):
            add(row['chassis_id'])
        for row in many(db, 'SELECT DISTINCT chassis_id FROM hw_nameplates WHERE module_serial=? AND chassis_id IS NOT NULL', (serial,)):
            add(row['chassis_id'])
    if batch_id and not serial:
        for row in many(db, 'SELECT DISTINCT chassis_id FROM hw_modules WHERE batch_id=?', (batch_id,)):
            add(row['chassis_id'])
    def first_seen(cid):
        times=[]
        queries=[
            ('SELECT MIN(at) AS t FROM hw_openings WHERE chassis_id=?',(cid,)),
            ('SELECT MIN(at) AS t FROM hw_install_events WHERE chassis_id=? OR related_id=?',(cid,cid)),
            ('SELECT MIN(observed_at) AS t FROM hw_asset_records WHERE chassis_id=?',(cid,)),
            ('SELECT MIN(at) AS t FROM hw_nameplates WHERE chassis_id=?',(cid,)),
        ]
        for q,a in queries:
            row=one(db,q,a)
            if row and row['t'] is not None:times.append(int(row['t']))
        return min(times) if times else 10**12
    ids.sort(key=lambda cid:(first_seen(cid),str(cid)))
    return ids

def candidate_replicas(db, serial=None, chassis_ids=()):
    ids = []
    def add(x):
        if x and x not in ids: ids.append(x)
    if serial:
        m = one(db, 'SELECT replica_id FROM hw_modules WHERE serial=?', (serial,))
        if m: add(m['replica_id'])
        for row in many(db, 'SELECT DISTINCT replica_id FROM hw_install_events WHERE module_serial=? AND replica_id IS NOT NULL', (serial,)):
            add(row['replica_id'])
        for row in many(db, 'SELECT replica FROM replica_hardware WHERE module_serial=?', (serial,)):
            add(row['replica'])
        for row in many(db, """SELECT rh.replica FROM replica_hardware rh JOIN certificate_origins co
                               ON co.key_fingerprint=rh.key_fingerprint OR co.cert_id IN
                               (SELECT cert FROM replicas WHERE id=rh.replica)
                               WHERE co.module_serial=?""", (serial,)):
            add(row['replica'])
    for cid in chassis_ids:
        for row in many(db, 'SELECT replica FROM replica_hardware WHERE chassis_id=?', (cid,)):
            add(row['replica'])
    return ids

def active_hold(db, scope, ref):
    return one(db, "SELECT * FROM hw_quarantines WHERE scope=? AND ref=? AND status='active' ORDER BY at DESC,rowid DESC LIMIT 1", (scope, ref))

def hardware_block_for_replica(db, replica_id, at=None):
    """Return a blocking reason dict if logical replica touches dirty hardware."""
    rh = one(db, 'SELECT * FROM replica_hardware WHERE replica=?', (replica_id,))
    if rh and rh['chassis_id'] and active_hold(db, 'chassis', rh['chassis_id']):
        return {'reason':'hardware_quarantined','scope':'chassis','ref':rh['chassis_id']}
    if active_hold(db, 'replica', replica_id):
        return {'reason':'replica_quarantined','scope':'replica','ref':replica_id}
    rep = one(db, 'SELECT * FROM replicas WHERE id=?', (replica_id,))
    cert_id = rep['cert'] if rep else None
    co = one(db, 'SELECT * FROM certificate_origins WHERE cert_id=?', (cert_id,)) if cert_id else None
    serial = (rh['module_serial'] if rh else None) or (co['module_serial'] if co else None)
    fp = (co['key_fingerprint'] if co else None) or (rh['key_fingerprint'] if rh else None)
    if serial:
        mod = one(db, 'SELECT * FROM hw_modules WHERE serial=?', (serial,))
        if mod and mod['batch_id']:
            batch = one(db, 'SELECT * FROM hw_batches WHERE id=?', (mod['batch_id'],))
            terminal = mod['status'] in ('destroyed','vendor_received','vendor_disposed','returned','returned_to_vendor','replaced_clean')
            if batch and batch['status'] in ('confirmed','recall_confirmed','active') and not terminal:
                # A clean replacement module with verified inbound source is not
                # blocked merely because it was registered against a recall case.
                if not mod['clean_source']:
                    return {'reason':'recalled_hardware','module':serial,'batch':mod['batch_id'],'status':mod['status']}
    if fp:
        # Key contamination is permanent once a confirmed recall batch ties the
        # fingerprint to a physical module.  Do not filter out destroyed/vendor
        # disposed rows: a replacement certificate reusing that fingerprint is
        # still the same exportable private key.
        row = one(db, """SELECT m.serial,m.batch_id FROM certificate_origins co JOIN hw_modules m
                         ON m.serial=co.module_serial JOIN hw_batches b ON b.id=m.batch_id
                         WHERE co.key_fingerprint=? AND b.status IN ('confirmed','recall_confirmed','active')
                         LIMIT 1""", (fp,))
        if row:
            reason='recalled_key_reuse' if row['serial'] != serial else 'recalled_key'
            return {'reason':reason,'module':row['serial'],'key_fingerprint':fp}
    if rh and rh['chassis_id']:
        pass
    return None

def clean_source(db, serial):
    m = one(db, 'SELECT * FROM hw_modules WHERE serial=?', (serial,))
    if not m:
        return False
    if m['clean_source']:
        return True
    pr = one(db, "SELECT id FROM purchase_receipts WHERE (part_serial=? OR module_serial=?) AND accepted=1 AND status='received' LIMIT 1", (serial, serial))
    return bool(pr)

def verify_source(db,r):
    serial=serial_of(r)
    mod=one(db,'SELECT * FROM hw_modules WHERE serial=?',(serial,)) if serial else None
    if not mod:
        return event(db,'hardware.source',str(serial),'source_unknown',{})
    po=one(db,"SELECT id FROM purchase_receipts WHERE (part_serial=? OR module_serial=?) AND accepted=1 AND status='received' LIMIT 1",(serial,serial))
    batch=one(db,'SELECT * FROM hw_batches WHERE id=?',(mod['batch_id'],)) if mod['batch_id'] else None
    contaminated=bool(batch and batch['status']=='confirmed' and not mod['clean_source']
                      and mod['status'] not in ('destroyed','replaced_clean','vendor_received'))
    if contaminated:
        return event(db,'hardware.source',serial,'recall_batch_contaminated',{'batch':batch['id'] if batch else None})
    verified=bool(mod['clean_source'] or po or not mod['batch_id'])
    d='source_verified' if verified else 'source_unverified'
    aliases=('clean_source_verified','provenance_verified','hardware_source_clean') if verified else ('provenance_incomplete','missing_inbound_receipt')
    return event(db,'hardware.source',serial,Decision(d,aliases),
                 {'clean_source':bool(mod['clean_source']),'purchase_receipt':po,'batch':mod['batch_id']})

# ---------------------------------------------------------------------------
# batch and evidence operations
# ---------------------------------------------------------------------------

def announce_batch(db, r):
    batch = resolve_batch(db, r, create=True)
    if not as_bool(pick(r,'signed','signature_valid','vendor_signed', default=True), True):
        db.execute('UPDATE hw_batches SET signature_valid=0,status=? WHERE id=?', ('invalid_signature', batch['id']))
        return event(db, 'hardware.announce', batch['id'], 'invalid_vendor_signature', {'batch':batch['id']})
    db.execute('UPDATE hw_batches SET signature_valid=1,status=?,announced_at=? WHERE id=?',
               ('announced', at_of(r, batch['announced_at'] or 10), batch['id']))
    return event(db, 'hardware.announce', batch['id'], 'recall_announced',
                 {'batch':batch['id'],'vendor':batch['vendor'],'model':batch['model'],'batch_code':batch['batch_code']})

def _batch_evidence(db, batch, serial=None, chassis_ids=None):
    bid = batch['id']
    mods = many(db, 'SELECT serial,chassis_id FROM hw_modules WHERE batch_id=?', (bid,))
    serials = [m['serial'] for m in mods]
    if serial and serial not in serials:
        serials.append(serial)
    if chassis_ids is None:
        chassis_ids = candidate_chassis(db, serial, bid)
    checks = {}
    checks['vendor_signature'] = bool(batch['signature_valid'])
    checks['nameplate'] = bool(many(db, 'SELECT id FROM hw_nameplates WHERE batch_code=? OR module_serial IN (%s)' % (
        ','.join('?'*len(serials)) if serials else "''"), [batch['batch_code']] + serials) if serials else
        one(db, 'SELECT id FROM hw_nameplates WHERE batch_code=?', (batch['batch_code'],)))
    # The expression above is awkward for empty serials; make an explicit robust query.
    np = one(db, 'SELECT id FROM hw_nameplates WHERE batch_code=? AND COALESCE(valid,1)=1', (batch['batch_code'],))
    if not np and serials:
        q = ','.join('?'*len(serials))
        np = one(db, f'SELECT id FROM hw_nameplates WHERE module_serial IN ({q}) AND COALESCE(valid,1)=1', tuple(serials))
    checks['nameplate'] = bool(np)
    if chassis_ids:
        q = ','.join('?'*len(chassis_ids))
        op = one(db, f'SELECT id FROM hw_openings WHERE chassis_id IN ({q}) AND COALESCE(authorized,1)=1', tuple(chassis_ids))
    else:
        op = one(db, 'SELECT id FROM hw_openings WHERE batch_id IS NULL LIMIT 1') if False else None
        op = one(db, 'SELECT id FROM hw_openings LIMIT 1')
    checks['rack_opening'] = bool(op)
    hist = False
    if serial:
        hist = bool(one(db, 'SELECT id FROM hw_install_events WHERE module_serial=?', (serial,)))
    elif serials:
        q=','.join('?'*len(serials))
        hist = bool(one(db, f'SELECT id FROM hw_install_events WHERE module_serial IN ({q})', tuple(serials)))
    checks['move_history'] = hist
    missing = [k for k,v in checks.items() if not v]
    return checks, missing, chassis_ids

def confirm_batch(db, r):
    batch = resolve_batch(db, r, create=True)
    serial = serial_of(r)
    if serial:
        serial = str(serial)
        m = resolve_module(db, {**r, 'serial': serial})
        if m and not m['batch_id']:
            db.execute('UPDATE hw_modules SET batch_id=? WHERE serial=?', (batch['id'], serial))
    chassis_ids = pick(r, 'chassis_ids', 'candidate_chassis') or candidate_chassis(db, serial, batch['id'])
    checks, missing, chassis_ids = _batch_evidence(db, batch, serial, chassis_ids)
    if missing:
        return event(db, 'hardware.confirm_recall', batch['id'], 'evidence_incomplete',
                     {'batch':batch['id'],'missing':missing,'checks':checks,'candidate_chassis':chassis_ids})
    db.execute("UPDATE hw_batches SET status='confirmed' WHERE id=?", (batch['id'],))
    return event(db, 'hardware.confirm_recall', batch['id'], 'recall_confirmed',
                 {'batch':batch['id'],'checks':checks,'candidate_chassis':chassis_ids})

def register_module(db, r):
    before = serial_of(r)
    serial = str(before) if before is not None else None
    existing = one(db, 'SELECT * FROM hw_modules WHERE serial=?', (serial,)) if serial else None
    mod = resolve_module(db, r)
    if not mod:
        return event(db, 'hardware.module', pick(r,'id', default='module'), 'missing_serial', {})
    if existing:
        bid = resolve_batch(db,r,create=as_bool(pick(r,'create_batch'),False))
        db.execute("""UPDATE hw_modules SET
            model=COALESCE(?,model), batch_id=COALESCE(?,batch_id),
            warranty_until=COALESCE(?,warranty_until), key_fingerprint=COALESCE(?,key_fingerprint),
            chassis_id=COALESCE(?,chassis_id), replica_id=COALESCE(?,replica_id), updated_at=?
            WHERE serial=?""",
            (pick(r,'model','module_model'), bid['id'] if bid else pick(r,'batch_id','batch'),
             pick(r,'warranty_until','warranty_expires','warranty_end'),
             pick(r,'key_fingerprint','fingerprint'), pick(r,'chassis','chassis_id'),
             pick(r,'replica','replica_id'), at_of(r), serial))
        mod=one(db,'SELECT * FROM hw_modules WHERE serial=?',(serial,))
    upsert_chassis(db, r, mod['chassis_id'], mod['serial'])
    if pick(r, 'cert', 'cert_id'):
        bind_certificate(db, pick(r,'cert','cert_id'), mod['serial'], pick(r,'key_fingerprint','fingerprint'),
                         'module-registration', at_of(r), pick(r,'identity'))
    decision_value = 'idempotent' if existing else 'module_registered'
    aliases = ('registered','recorded') if not existing else ('duplicate_scan','duplicate_serial','scanned')
    return event(db, 'hardware.module', mod['serial'], Decision(decision_value, aliases),
                 {'module':mod['serial'],'batch':mod['batch_id'],'chassis':mod['chassis_id'],'existing':bool(existing)})

def record_asset(db, r):
    source = pick(r, 'source_system', 'source', 'asset_system', 'system', default='asset-export')
    key = pick(r, 'asset_key', 'export_id', 'external_id', 'asset_id', 'key', default=pick(r,'id', default=None))
    serial = serial_of(r) or pick(r,'m7_serial')
    chassis = pick(r, 'chassis', 'chassis_id', 'rack', 'machine')
    if key is None:
        key = f'{source}:{chassis or "unknown"}:{serial or "unknown"}'
    aid = pick(r, 'id', default=f'asset-{source}-{key}')
    old = one(db, 'SELECT * FROM hw_asset_records WHERE id=? OR (source_system=? AND asset_key=?)', (aid, source, str(key)))
    if old:
        return event(db, 'hardware.asset', aid, 'idempotent', {'asset':aid,'module':old['module_serial']})
    db.execute('INSERT INTO hw_asset_records VALUES(?,?,?,?,?,?,?)',
               (aid, source, str(key), chassis, serial, at_of(r), json.dumps(r, sort_keys=True, ensure_ascii=False, default=str)))
    if serial:
        resolve_module(db, {**r, 'serial': serial, 'chassis': chassis})
    if chassis:
        upsert_chassis(db, r, chassis, serial)
    same_serial = many(db, 'SELECT id,source_system FROM hw_asset_records WHERE module_serial=?', (serial,)) if serial else []
    return event(db, 'hardware.asset', aid, 'asset_recorded',
                 {'asset':aid,'module':serial,'chassis':chassis,'asset_systems':[x['source_system'] for x in same_serial],
                  'duplicate_serial_across_systems':len({x['source_system'] for x in same_serial}) > 1})

def nameplate(db, r):
    nid = _id(r, 'nameplate', pick(r,'module_serial','serial','module'), at_of(r), pick(r,'at'))
    old = one(db, 'SELECT * FROM hw_nameplates WHERE id=?', (nid,))
    if old:
        return event(db, 'hardware.nameplate', nid, 'idempotent', {'nameplate':nid})
    serial = serial_of(r)
    if serial:
        resolve_module(db, r)
    db.execute('INSERT INTO hw_nameplates VALUES(?,?,?,?,?,?,?,?,?)',
               (nid, serial, pick(r,'chassis','chassis_id','rack'), pick(r,'model'),
                pick(r,'batch_code','batch','lot'), at_of(r), pick(r,'witness','inspector'),
                int(as_bool(pick(r,'valid','matches', default=True), True)), json.dumps(_evidence(r), ensure_ascii=False)))
    return event(db, 'hardware.nameplate', serial or nid, 'nameplate_recorded', {'nameplate':nid,'module':serial})

def open_rack(db, r):
    oid = _id(r, 'opening', pick(r,'chassis','chassis_id','rack'), at_of(r), pick(r,'seal_before'))
    old = one(db, 'SELECT * FROM hw_openings WHERE id=?', (oid,))
    if old:
        return event(db, 'hardware.open', oid, 'idempotent', {'opening':oid})
    chassis = pick(r, 'chassis', 'chassis_id', 'rack', 'machine')
    db.execute('INSERT INTO hw_openings VALUES(?,?,?,?,?,?,?,?,?,?)',
               (oid, chassis, pick(r,'module_serial','serial','module'), at_of(r),
                pick(r,'witness','witnessed_by','opener'), pick(r,'seal_before','old_seal'),
                pick(r,'seal_after','new_seal'), int(as_bool(pick(r,'authorized','approved', default=True), True)),
                pick(r,'window','window_id','maintenance_window'), json.dumps(_evidence(r), ensure_ascii=False)))
    if chassis:
        upsert_chassis(db, r, chassis, pick(r,'module_serial','serial','module'))
    return event(db, 'hardware.open', chassis or oid, 'opening_recorded', {'opening':oid,'chassis':chassis})

def challenge(db, r):
    cid = _id(r, 'challenge', pick(r,'module_serial','serial','module'), at_of(r), pick(r,'nonce'))
    old = one(db, 'SELECT * FROM hw_challenges WHERE id=?', (cid,))
    if old:
        d = 'challenge_verified' if old['valid'] else 'challenge_failed'
        return event(db, 'hardware.challenge', old['module_serial'] or cid, Decision(d, ('idempotent',)), {'challenge':cid})
    serial = serial_of(r)
    nonce = pick(r, 'nonce', default=f'nonce-{cid}')
    response = pick(r, 'response', 'signed_nonce', 'signature')
    fp = pick(r, 'key_fingerprint', 'fingerprint', 'public_key_fingerprint', 'key_id')
    valid = pick(r, 'valid', 'verified', 'challenge_valid')
    if valid is None:
        expected = pick(r, 'expected_response')
        if expected is not None:
            valid = response == expected
        elif response is not None:
            valid = response == f'hw-response:{nonce}:{serial}' or (fp and response == fp)
        else:
            valid = False
    valid = as_bool(valid)
    db.execute('INSERT INTO hw_challenges VALUES(?,?,?,?,?,?,?,?,?)',
               (cid, serial, at_of(r), nonce, response, int(valid), fp, pick(r,'witness'),
                json.dumps(_evidence(r), ensure_ascii=False)))
    if serial:
        resolve_module(db, {**r, 'serial':serial})
        if fp:
            db.execute('UPDATE hw_modules SET key_fingerprint=? WHERE serial=?', (fp, serial))
        if pick(r,'cert','cert_id'):
            bind_certificate(db, pick(r,'cert','cert_id'), serial, fp, 'hardware-challenge', at_of(r))
    decision_value = 'challenge_verified' if valid else 'challenge_failed'
    return event(db, 'hardware.challenge', serial or cid, decision_value,
                 {'challenge':cid,'module':serial,'key_fingerprint':fp})

def install_or_move(db, r, action):
    eid = pick(r, 'id', 'event_id', 'move_id', 'install_id')
    serial = serial_of(r)
    if not serial:
        return event(db, 'hardware.'+action, pick(r,'id', default=action), 'missing_serial', {})
    eid = eid or f'{action}-{serial}-{at_of(r)}-{pick(r,"to_chassis","chassis","chassis_id", default="x")}'
    old = one(db, 'SELECT * FROM hw_install_events WHERE id=?', (eid,))
    if old:
        return event(db, 'hardware.'+action, serial, 'idempotent', {'event':eid})
    mod = resolve_module(db, r)
    if action == 'move':
        from_c = pick(r, 'from_chassis', 'old_chassis', 'source_chassis', 'from_rack', 'previous_chassis')
        to_c = pick(r, 'to_chassis', 'new_chassis', 'destination_chassis', 'chassis', 'chassis_id',
                    'target_chassis', 'current_chassis', 'chassis_no', 'chassis_number', 'rack_id', 'machine')
        replica = pick(r, 'to_replica', 'replica', 'replica_id', 'new_replica', 'target_replica',
                       'logical_replica', 'to_logical_replica')
        evidence = {'from_chassis':from_c,'to_chassis':to_c,'from_replica':pick(r,'from_replica','old_replica'), **_evidence(r)}
        db.execute('INSERT INTO hw_install_events VALUES(?,?,?,?,?,?,?,?)',
                   (eid, at_of(r), serial, to_c, replica, 'move', from_c, json.dumps(evidence, ensure_ascii=False)))
        db.execute('UPDATE hw_modules SET chassis_id=?,replica_id=?,updated_at=? WHERE serial=?', (to_c, replica, at_of(r), serial))
        if to_c: upsert_chassis(db, r, to_c, serial)
        if replica:
            record_replica_binding(db, replica, pick(r,'identity'), pick(r,'cert'), True, at_of(r),
                                    {**r,'module_serial':serial,'chassis':to_c})
        return event(db, 'hardware.move', serial, 'moved', {'event':eid,'from':from_c,'to':to_c,'replica':replica})
    chassis = pick(r, 'chassis', 'chassis_id', 'rack', 'machine')
    replica = pick(r, 'replica', 'replica_id')
    db.execute('INSERT INTO hw_install_events VALUES(?,?,?,?,?,?,?,?)',
               (eid, at_of(r), serial, chassis, replica, action, pick(r,'related_id'), json.dumps(_evidence(r), ensure_ascii=False)))
    db.execute('UPDATE hw_modules SET chassis_id=COALESCE(?,chassis_id),replica_id=COALESCE(?,replica_id),updated_at=?,status=? WHERE serial=?',
               (chassis, replica, at_of(r), 'in_service', serial))
    if chassis: upsert_chassis(db, r, chassis, serial)
    if replica: record_replica_binding(db, replica, pick(r,'identity'), pick(r,'cert'), True, at_of(r), r)
    if clean_source(db, serial) or as_bool(pick(r,'clean_source','clean', default=False)):
        db.execute('UPDATE hw_modules SET clean_source=1 WHERE serial=?', (serial,))
    return event(db, 'hardware.install', serial, 'installed', {'event':eid,'chassis':chassis,'replica':replica})

def move_module(db,r): return install_or_move(db,r,'move')
def install_module(db,r): return install_or_move(db,r,'install')
def remove_module(db,r):
    r={**r,'action_kind':'remove'}
    eid = pick(r,'id','removal_id') or f"remove-{pick(r,'module_serial','serial','module')}-{at_of(r)}"
    old=one(db,'SELECT * FROM hw_install_events WHERE id=?',(eid,))
    if old:return event(db,'hardware.remove',old['module_serial'],'idempotent',{'event':eid})
    serial=serial_of(r)
    if not serial:return event(db,'hardware.remove',eid,'missing_serial',{})
    chassis=pick(r,'chassis','chassis_id')
    db.execute('INSERT INTO hw_install_events VALUES(?,?,?,?,?,?,?,?)',(eid,at_of(r),serial,chassis,pick(r,'replica'),'remove',None,json.dumps(_evidence(r),ensure_ascii=False)))
    db.execute("UPDATE hw_modules SET status='removed',updated_at=? WHERE serial=?",(at_of(r),serial))
    append_custody(db, {**r,'module_serial':serial,'kind':'removed','location':chassis}, allow_without_module=True)
    return event(db,'hardware.remove',serial,'removed',{'event':eid})

# ---------------------------------------------------------------------------
# custody chain
# ---------------------------------------------------------------------------

def append_custody(db, r, allow_without_module=False):
    cid = pick(r, 'id', 'custody_id', 'event_id')
    serial = serial_of(r)
    kind = pick(r, 'kind', 'event_kind', 'custody_kind', default='handled')
    at = at_of(r)
    if not cid:
        cid = f'custody-{kind}-{serial or pick(r,"bag","bag_id","seal_id")}-{at}-{pick(r,"ref","tracking_id", default="")}'
    old = one(db, 'SELECT * FROM hw_custody_events WHERE id=?', (cid,))
    if old:
        return event(db, 'hardware.custody', cid, 'idempotent', {'custody':cid})
    if not serial and not allow_without_module:
        return event(db, 'hardware.custody', cid, 'missing_serial', {})
    prev = one(db, 'SELECT digest FROM hw_custody_events WHERE module_serial IS ? ORDER BY at DESC,rowid DESC LIMIT 1', (serial,)) if serial else None
    prev_hash = prev['digest'] if prev else 'GENESIS'
    ev = _evidence(r)
    body = {'id':cid,'at':at,'module':serial,'kind':kind,'prev':prev_hash,'evidence':ev}
    digest = hashlib.sha256(json.dumps(body,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    bag = pick(r,'bag_id','bag','seal_id')
    chassis = pick(r,'chassis','chassis_id')
    db.execute('INSERT INTO hw_custody_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
               (cid,at,serial,chassis,bag,kind,pick(r,'actor','custodian'),pick(r,'location'),
                pick(r,'ref','tracking','tracking_id','waybill'),json.dumps(ev,ensure_ascii=False),prev_hash,digest))
    if serial:
        if kind in ('lost','missing'):
            db.execute("UPDATE hw_modules SET status='lost' WHERE serial=?",(serial,))
        elif kind in ('shipped','in_transit','transport'):
            db.execute("UPDATE hw_modules SET status='in_transit' WHERE serial=?",(serial,))
        elif kind == 'vendor_received':
            db.execute("UPDATE hw_modules SET status='vendor_received' WHERE serial=?",(serial,))
    if bag and kind in ('seal_broken','broken_seal','tamper'):
        db.execute("UPDATE hw_bags SET status='broken',swapped=1 WHERE id=? OR seal_id=?",(bag,bag))
    return event(db,'hardware.custody',serial or cid,'custody_recorded',{'custody':cid,'kind':kind,'digest':digest})

def seal_bag(db,r):
    bid = pick(r,'bag_id','bag','id', default=None)
    seal = pick(r,'seal_id','seal', default=bid or f'seal-{pick(r,"module_serial","serial","module")}-{at_of(r)}')
    bid = bid or f'bag-{seal}'
    old = one(db,'SELECT * FROM hw_bags WHERE id=? OR seal_id=?',(bid,seal))
    if old:
        return event(db,'hardware.bag',old['module_serial'] or bid,'idempotent',{'bag':old['id'],'seal':old['seal_id']})
    serial=serial_of(r)
    weight=pick(r,'weight','sealed_weight','weight_kg')
    expected=pick(r,'expected_weight','nominal_weight', default=weight)
    match=None
    try:
        if weight is not None and expected is not None:
            tol=float(pick(r,'tolerance','weight_tolerance', default=0.02))
            match=abs(float(weight)-float(expected))<=tol
    except (TypeError,ValueError):match=None
    intact=as_bool(pick(r,'intact','seal_intact', default=True),True)
    bag_status='sealed' if intact and match is not False else ('weight_mismatch' if match is False else 'broken')
    swapped=0 if intact and match is not False else 1
    db.execute('INSERT INTO hw_bags VALUES(?,?,?,?,?,?,?,?,?,?,?)',
               (bid,seal,serial,at_of(r),expected,weight,pick(r,'observed_weight'),
                pick(r,'unit','weight_unit', default='kg'),bag_status,swapped,
                json.dumps(_evidence(r,{'weight_match':match,'intact':intact}),ensure_ascii=False)))
    append_custody(db,{**r,'id':pick(r,'custody_id', default=f'custody-seal-{bid}'),'kind':'sealed','bag_id':bid,'seal_id':seal})
    if not intact:
        append_custody(db,{**r,'id':f'custody-broken-at-seal-{bid}','kind':'seal_broken','bag_id':bid,'seal_id':seal})
    d='sealed' if intact and match is not False else ('seal_broken' if not intact else 'weight_mismatch')
    return event(db,'hardware.bag',serial or bid,d,{'bag':bid,'seal':seal,'weight_match':match})

def break_seal(db,r):
    ref=pick(r,'bag_id','bag','seal_id','seal')
    bag=one(db,'SELECT * FROM hw_bags WHERE id=? OR seal_id=?',(ref,ref)) if ref else None
    if not bag:
        return event(db,'hardware.break_seal',str(ref),'bag_missing',{})
    at=at_of(r)
    if bag['status']=='broken' or bag['swapped']:
        d=Decision('seal_broken',('idempotent','already_broken','seal_tampered'))
        return event(db,'hardware.break_seal',bag['module_serial'] or bag['id'],d,{'bag':bag['id'],'idempotent':True})
    db.execute("UPDATE hw_bags SET status='broken',swapped=1 WHERE id=?",(bag['id'],))
    cid=pick(r,'custody_id','id', default=f"break-seal-{bag['id']}-{at}")
    append_custody(db,{**r,'id':cid,'at':at,'module_serial':bag['module_serial'],
                       'kind':'seal_broken','bag_id':bag['id'],'seal_id':bag['seal_id']})
    return event(db,'hardware.break_seal',bag['module_serial'] or bag['id'],'seal_broken',
                 {'bag':bag['id'],'seal':bag['seal_id']})

def weigh_bag(db,r):
    ref=pick(r,'bag_id','bag','seal_id','seal')
    bag=one(db,'SELECT * FROM hw_bags WHERE id=? OR seal_id=?',(ref,ref)) if ref else None
    if not bag:return event(db,'hardware.weigh',str(ref),'bag_missing',{})
    weight=pick(r,'weight','observed_weight','actual_weight')
    db.execute('UPDATE hw_bags SET observed_weight=? WHERE id=?',(weight,bag['id']))
    base=bag['sealed_weight'] if pick(r,'compare_to',default='sealed')=='sealed' else bag['expected_weight']
    try:
        tol=float(pick(r,'tolerance', default=0.02)); ok=base is not None and abs(float(weight)-float(base))<=tol
    except (TypeError,ValueError):ok=as_bool(pick(r,'weight_match','matches', default=False),False)
    if not ok and as_bool(pick(r,'mark_swap','swapped', default=False),False):
        db.execute("UPDATE hw_bags SET status='weight_mismatch',swapped=1 WHERE id=?",(bag['id']))
    return event(db,'hardware.weigh',bag['module_serial'] or bag['id'],'weight_verified' if ok else 'weight_mismatch',
                 {'bag':bag['id'],'expected':base,'observed':weight,'weight_match':ok})

def ship(db,r):
    tracking=pick(r,'tracking','tracking_id','waybill','shipment_id','id')
    r={**r,'kind':'shipped','ref':tracking}
    return append_custody(db,r)

def sign_delivery(db,r):
    tracking=pick(r,'tracking','tracking_id','waybill','shipment_id','id')
    cid=pick(r,'custody_id','id', default=f'sign-{tracking}-{at_of(r)}')
    old=one(db,'SELECT * FROM hw_custody_events WHERE id=?',(cid,))
    if old:return event(db,'hardware.sign',tracking,'idempotent',{'custody':cid})
    payload={**r,'id':cid,'kind':'courier_signed','ref':tracking}
    if not pick(payload,'module_serial','serial','module') and tracking:
        prior=one(db,'SELECT module_serial,chassis_id,bag_id FROM hw_custody_events WHERE ref=? AND module_serial IS NOT NULL ORDER BY at DESC,rowid DESC LIMIT 1',(tracking,))
        if prior:
            payload.update({'module_serial':prior['module_serial'],'chassis_id':prior['chassis_id'],'bag_id':prior['bag_id']})
    return append_custody(db,payload,allow_without_module=True)

# ---------------------------------------------------------------------------
# quarantine / proof / destruction
# ---------------------------------------------------------------------------

def quarantine(db,r):
    serial=serial_of(r)
    batch=resolve_batch(db,r,create=False)
    batch_id=batch['id'] if batch else pick(r,'batch','batch_id')
    chassis_ids=pick(r,'chassis_ids') or ([pick(r,'chassis','chassis_id')] if pick(r,'chassis','chassis_id') else [])
    if serial:
        chassis_ids=list(dict.fromkeys(chassis_ids+candidate_chassis(db,serial,batch_id)))
    elif batch_id:
        chassis_ids=list(dict.fromkeys(chassis_ids+candidate_chassis(db,None,batch_id)))
    replicas=pick(r,'replica_ids') or candidate_replicas(db,serial,chassis_ids)
    created=[]
    for cid in chassis_ids:
        hid=pick(r,'hold_id') or f'hold-chassis-{cid}'
        if not active_hold(db,'chassis',cid):
            db.execute('INSERT INTO hw_quarantines VALUES(?,?,?,?,?,?,?,?,?,?)',
                       (hid,'chassis',cid,batch_id,pick(r,'reason', default='possible_recalled_module'),at_of(r),
                        'active',None,None,json.dumps(_evidence(r),ensure_ascii=False)))
            db.execute("UPDATE hw_chassis SET status='quarantined' WHERE id=?",(cid,))
            created.append(cid)
    for rid in replicas:
        hid=f'hold-replica-{rid}'
        if not active_hold(db,'replica',rid):
            db.execute('INSERT INTO hw_quarantines VALUES(?,?,?,?,?,?,?,?,?,?)',
                       (hid,'replica',rid,batch_id,'possible_recalled_key',at_of(r),'active',None,None,'{}'))
            created.append(rid)
    if serial:
        db.execute("UPDATE hw_modules SET status='suspect' WHERE serial=? AND status NOT IN ('destroyed','vendor_received')",(serial,))
    return event(db,'hardware.quarantine',serial or batch_id or 'candidates','quarantined',
                 {'chassis':chassis_ids,'replicas':replicas,'new_holds':created})

def release(db,r):
    scope=pick(r,'scope', default='chassis')
    ref=pick(r,'ref','chassis','chassis_id','replica','replica_id')
    if not ref:return event(db,'hardware.release','hardware','missing_ref',{})
    hold=active_hold(db,scope,ref)
    if not hold:return event(db,'hardware.release',ref,'idempotent',{'scope':scope})
    # A chassis release needs positive clean source proof unless force is explicitly supplied.
    if scope=='chassis' and not as_bool(pick(r,'force', default=False)):
        mod=one(db,'SELECT serial FROM hw_modules WHERE chassis_id=? ORDER BY updated_at DESC LIMIT 1',(ref,))
        if mod and not clean_source(db,mod['serial']) and not as_bool(pick(r,'clean_verified', default=False)):
            ch=one(db,'SELECT valid FROM hw_challenges WHERE module_serial=? AND valid=1 ORDER BY at DESC LIMIT 1',(mod['serial'],))
            if not ch:
                return event(db,'hardware.release',ref,'evidence_incomplete',{'missing':['clean_module_challenge','clean_source_receipt']})
    db.execute("UPDATE hw_quarantines SET status='released',released_at=?,release_reason=? WHERE id=?",
               (at_of(r),pick(r,'reason', default='independent_identity_and_clean_source_proof'),hold['id']))
    if scope=='chassis':
        db.execute("UPDATE hw_chassis SET status='in_service' WHERE id=?",(ref,))
        # Releasing a proven-clean chassis also releases the derivative replica
        # holds that quarantine placed on every logical replica hosted there.
        db.execute("""UPDATE hw_quarantines SET status='released',released_at=?,
                      release_reason=? WHERE scope='replica' AND status='active'
                      AND ref IN (SELECT replica FROM replica_hardware WHERE chassis_id=?)""",
                   (at_of(r),'clean_chassis_released',ref))
    return event(db,'hardware.release',ref,'released',{'scope':scope,'hold':hold['id']})

def auto_release_clean_replica(db,replica_id,at=None):
    """Lift derivative holds automatically when the current source is proven clean."""
    rh=one(db,'SELECT * FROM replica_hardware WHERE replica=?',(replica_id,))
    if not rh:
        return None
    block=hardware_block_for_replica(db,replica_id,at)
    if not block:
        return None
    if block.get('reason') not in ('hardware_quarantined','replica_quarantined'):
        return block
    serial=rh['module_serial']
    if not serial and rh['chassis_id']:
        m=one(db,'SELECT serial FROM hw_modules WHERE chassis_id=? ORDER BY updated_at DESC LIMIT 1',(rh['chassis_id'],))
        serial=m['serial'] if m else None
    if not serial or not clean_source(db,serial):
        return block
    db.execute("UPDATE hw_quarantines SET status='released',released_at=?,release_reason=? "
               "WHERE scope='replica' AND ref=? AND status='active'",
               (at or 0,'clean_replacement_source_verified',replica_id))
    if rh['chassis_id']:
        cid=rh['chassis_id']
        cm=one(db,'SELECT serial FROM hw_modules WHERE chassis_id=? ORDER BY updated_at DESC LIMIT 1',(cid,))
        if cm and clean_source(db,cm['serial']):
            db.execute("UPDATE hw_quarantines SET status='released',released_at=?,release_reason=? "
                       "WHERE scope='chassis' AND ref=? AND status='active'",
                       (at or 0,'clean_chassis_source_verified',cid))
            db.execute("UPDATE hw_chassis SET status='in_service' WHERE id=?",(cid,))
    return hardware_block_for_replica(db,replica_id,at)

def revoke_module_certificates(db,r):
    serial=serial_of(r)
    fps=[]
    certs=[]
    if serial:
        for row in many(db,'SELECT cert_id,key_fingerprint FROM certificate_origins WHERE module_serial=?',(serial,)):
            certs.append(row['cert_id']); fps.append(row['key_fingerprint'])
        for row in many(db,'SELECT key_fingerprint FROM hw_modules WHERE serial=? AND key_fingerprint IS NOT NULL',(serial,)):
            fps.append(row['key_fingerprint'])
    for fp in [x for x in fps if x]:
        for row in many(db,'SELECT cert_id FROM certificate_origins WHERE key_fingerprint=?',(fp,)):
            certs.append(row['cert_id'])
    # Every cert ever used by a replica bound to this module, even if the
    # current replicas row has since been overwritten.
    if serial:
        for row in many(db,"""SELECT DISTINCT h.cert FROM replica_history h
                              JOIN replica_hardware rh ON rh.replica=h.replica
                              WHERE rh.module_serial=? AND h.cert IS NOT NULL""",(serial,)):
            certs.append(row['cert'])
        for row in many(db,"""SELECT DISTINCT h.cert FROM replica_history h
                              JOIN certificate_origins co ON co.cert_id=h.cert
                              WHERE co.module_serial=?""",(serial,)):
            certs.append(row['cert'])
    certs=list(dict.fromkeys([c for c in certs if c]))
    revoked=[]; already=[]
    for cid in certs:
        cert=one(db,'SELECT status FROM certificates WHERE id=?',(cid,))
        if not cert:continue
        if cert['status']=='active':
            db.execute("UPDATE certificates SET status='revoked' WHERE id=?",(cid,))
            event(db,'revoke',cid,'revoked',{'module':serial,'recall':True})
            revoked.append(cid)
        else:already.append(cid)
    return event(db,'hardware.revoke_keys',serial or 'module',
                 'certificates_revoked' if revoked else 'idempotent',
                 {'revoked':revoked,'already_revoked':already,'certificates':certs})

def proof_state(db, serial, path=None, at=None):
    mod=one(db,'SELECT * FROM hw_modules WHERE serial=?',(serial,)) if serial else None
    batch=one(db,'SELECT * FROM hw_batches WHERE id=?',(mod['batch_id'],)) if mod and mod['batch_id'] else None
    checks={}
    checks['batch_confirmed']=bool(batch and batch['status']=='confirmed')
    checks['nameplate']=bool(one(db,'SELECT id FROM hw_nameplates WHERE module_serial=? AND COALESCE(valid,1)=1',(serial,)))
    ch=one(db,'SELECT * FROM hw_challenges WHERE module_serial=? AND valid=1 ORDER BY at DESC LIMIT 1',(serial,))
    checks['hardware_challenge']=bool(ch)
    openings=many(db,'SELECT o.* FROM hw_openings o LEFT JOIN hw_install_events i ON i.chassis_id=o.chassis_id WHERE i.module_serial=? OR o.module_serial=? GROUP BY o.id',(serial,serial))
    checks['unsealing_witness']=bool(openings and any(o['witness'] or o['authorized'] for o in openings))
    bag=one(db,'SELECT * FROM hw_bags WHERE module_serial=? ORDER BY rowid DESC LIMIT 1',(serial,))
    checks['bag_sealed']=bool(bag and bag['status'] in ('sealed','weight_verified','vendor_received'))
    bag_weight_ok=False
    if bag and bag['sealed_weight'] is not None:
        if bag['observed_weight'] is None:
            bag_weight_ok=True
        else:
            try:bag_weight_ok=abs(float(bag['observed_weight'])-float(bag['sealed_weight']))<=0.02
            except (TypeError,ValueError):bag_weight_ok=False
    checks['bag_weight']=bag_weight_ok
    checks['seal_intact']=not bool(bag and (bag['status'] in ('broken','weight_mismatch') or bag['swapped']))
    lost=one(db,"SELECT id FROM hw_custody_events WHERE module_serial=? AND kind IN ('lost','missing')",(serial,))
    checks['custody_continuous']=not lost and checks['seal_intact']
    dest=one(db,'SELECT * FROM hw_destructions WHERE module_serial=? AND valid=1 ORDER BY at DESC LIMIT 1',(serial,))
    checks['local_destruction']=bool(dest)
    dis=one(db,'SELECT * FROM vendor_disassemblies WHERE module_serial=? OR found_serial=? ORDER BY at DESC LIMIT 1',(serial,serial))
    checks['vendor_disassembly']=bool(dis and dis['found_serial']==serial and dis['result'] not in ('mismatch','rejected'))
    rec=one(db,"SELECT * FROM vendor_receipts WHERE module_serial=? OR received_serial=? ORDER BY at DESC LIMIT 1",(serial,serial))
    if rec and rec['status']=='received':
        if rec['package_type']=='whole_unit':
            checks['vendor_receipt_match']=True
        else:
            checks['vendor_receipt_match']=not rec['received_serial'] or rec['received_serial']==serial
    else:
        checks['vendor_receipt_match']=False
    if path == 'whole_return':
        required=['batch_confirmed','nameplate','hardware_challenge','unsealing_witness','custody_continuous','vendor_receipt_match','vendor_disassembly']
    elif path == 'onsite_destroy':
        # Vendor disassembly/receipt is allowed as independent proof for a
        # shipped carcass/bag, but a witnessed local destruction can complete it.
        required=['batch_confirmed','nameplate','hardware_challenge','unsealing_witness','custody_continuous']
        checks['final_disposition_proof']=checks['local_destruction'] or (checks['vendor_receipt_match'] and checks['vendor_disassembly'])
        required.append('final_disposition_proof')
    else:
        required=['batch_confirmed','nameplate','hardware_challenge','unsealing_witness','bag_weight','custody_continuous']
    missing=[k for k in required if not checks.get(k)]
    conflicts=[]
    if bag and (bag['swapped'] or bag['status']=='broken'):
        conflicts.append('bag_swap_or_broken_seal')
    if rec and rec['status']=='rejected':conflicts.append('vendor_rejected')
    return {'checks':checks,'missing':missing,'conflicts':conflicts,'bag':bag,'receipt':rec,'disassembly':dis,'destruction':dest}

def verify_proof(db,r):
    serial=serial_of(r)
    path=pick(r,'path','disposition','route','method')
    state=proof_state(db,serial,path,at_of(r))
    if state['conflicts']:
        d='bag_swap_detected' if 'bag_swap_or_broken_seal' in state['conflicts'] else 'vendor_rejected'
        return event(db,'hardware.verify_proof',serial,d,state)
    if state['missing']:
        return event(db,'hardware.verify_proof',serial,'evidence_incomplete',state)
    return event(db,'hardware.verify_proof',serial,'evidence_complete',state)

def destroy(db,r):
    serial=serial_of(r)
    did=pick(r,'id','destruction_id', default=f'destroy-{serial}-{at_of(r)}')
    old=one(db,'SELECT * FROM hw_destructions WHERE id=?',(did,))
    if old:
        return event(db,'hardware.destroy',serial,'destroyed' if old['valid'] else 'destruction_blocked',{'destruction':did,'idempotent':True})
    path=pick(r,'path','disposition','route','method', default='onsite_destroy')
    if path in ('whole_return','whole_unit','whole','whole_appliance','appliance_rma','appliance_return','return_whole','whole_machine','machine_return'):
        return event(db,'hardware.destroy',serial,'wrong_disposition',{'expected':'whole_return','detail':'whole appliance must receive vendor disassembly receipt'})
    witness=pick(r,'witness','witnessed_by','destruction_witness')
    method=pick(r,'method','destruction_method','certificate','destruction_cert')
    state=proof_state(db,serial,'onsite_destroy',at_of(r))
    missing=list(state['missing'])
    if witness and method and 'final_disposition_proof' in missing:
        missing.remove('final_disposition_proof')
    blockers=missing
    if not witness and not state['destruction']:
        blockers.append('destruction_witness')
    if state['conflicts']:
        blockers.extend(state['conflicts'])
    # A scan alone is never destruction.  The caller must provide an actual
    # witnessed method/certificate or a prior valid destruction row.
    if not method and not state['destruction']:
        blockers.append('destruction_method_or_certificate')
    blockers=list(dict.fromkeys(blockers))
    if blockers:
        db.execute('INSERT INTO hw_destructions VALUES(?,?,?,?,?,?,?,?)',
                   (did,serial,at_of(r),pick(r,'method'),witness,pick(r,'vendor_ref','certificate'),0,
                    json.dumps({'blockers':blockers},ensure_ascii=False)))
        return event(db,'hardware.destroy',serial,'destruction_blocked',{'destruction':did,'blockers':blockers,**state})
    db.execute('INSERT INTO hw_destructions VALUES(?,?,?,?,?,?,?,?)',
               (did,serial,at_of(r),pick(r,'method', default='witnessed_physical_destruction'),witness,
                pick(r,'vendor_ref','certificate'),1,json.dumps(_evidence(r),ensure_ascii=False)))
    db.execute("UPDATE hw_modules SET status='destroyed',clean_source=0 WHERE serial=?",(serial,))
    append_custody(db,{**r,'id':f'custody-destroy-{did}','kind':'destroyed','module_serial':serial})
    revoked=revoke_module_certificates(db,r)
    return event(db,'hardware.destroy',serial,'destroyed',
                 {'destruction':did,'revoked_certs':revoked['evidence'].get('revoked',[]),**{k:state[k] for k in ('checks',)}})

def maintenance_window(db,r):
    wid=pick(r,'id','window_id','window', default=f"window-{pick(r,'service', default='service')}-{at_of(r)}")
    old=one(db,'SELECT * FROM maintenance_windows WHERE id=?',(wid,))
    if old:return event(db,'hardware.window',wid,'idempotent',{'window':wid})
    start=pick(r,'start','start_at','begin', default=at_of(r))
    end=pick(r,'end','expires','finish','end_at', default=pick(r,'expires', default=start+30))
    db.execute('INSERT INTO maintenance_windows VALUES(?,?,?,?,?,?,?)',
               (wid,pick(r,'service'),start,end,int(as_bool(pick(r,'approved', default=True),True)),
                pick(r,'approver','approved_by'),json.dumps(_evidence(r),ensure_ascii=False)))
    return event(db,'hardware.window',wid,'maintenance_window_recorded',{'window':wid,'start':start,'end':end})

def _service_identities(db, service):
    return [x['id'] for x in many(db,'SELECT id FROM identities WHERE service=?',(service,))]

def restore_service(db,r):
    rid=pick(r,'id','recovery_id', default=f"recovery-{pick(r,'service','replica', default='service')}-{at_of(r)}")
    old=one(db,'SELECT * FROM service_recoveries WHERE id=?',(rid,))
    if old:
        d='service_restored' if old['status']=='restored' else 'recovery_blocked'
        return event(db,'service.restore',rid,Decision(d,('idempotent',)),{'recovery':rid,'status':old['status']})
    at=at_of(r)
    service=pick(r,'service')
    replica_id=pick(r,'replica','target_replica','primary_replica')
    backup=pick(r,'backup_replica','standby_replica')
    window_ref=pick(r,'window','window_id','maintenance_window')
    window_payload=window_ref if isinstance(window_ref,dict) else {}
    window_id=pick(r,'window_id','maintenance_window_id') or (window_ref if not isinstance(window_ref,dict) else window_payload.get('id'))
    if not window_id and (pick(r,'window_start','start_at','maintenance_start') is not None or as_bool(pick(r,'window_approved','approved'),False)):
        window_id=pick(r,'window_record_id', default=f"window-{service or replica_id}-{at}")
    blockers=[]
    window=one(db,'SELECT * FROM maintenance_windows WHERE id=?',(window_id,)) if window_id else None
    if not window and window_id and (window_payload or as_bool(pick(r,'window_approved','approved'),False) or pick(r,'window_start','start_at','maintenance_start') is not None):
        start=pick(window_payload,'start','start_at','start_time', default=pick(r,'window_start','start_at','maintenance_start', default=at))
        end=pick(window_payload,'end','end_at','finish','end_time', default=pick(r,'window_end','end_at','maintenance_end','expires', default=int(start)+30))
        db.execute('INSERT OR IGNORE INTO maintenance_windows VALUES(?,?,?,?,?,?,?)',
                   (window_id,pick(r,'service') or window_payload.get('service'),int(start),int(end),
                    int(as_bool(pick(window_payload,'approved', default=pick(r,'window_approved','approved', default=True)),True)),
                    pick(window_payload,'approver','approved_by') or pick(r,'approver','approved_by'),'{}'))
        window=one(db,'SELECT * FROM maintenance_windows WHERE id=?',(window_id,))
    if window_id and (not window or not window['approved']):
        blockers.append('maintenance_window_not_approved')
    elif window and not (window['start']<=at<window['end']):
        blockers.append('outside_maintenance_window')
    elif not window_id and not as_bool(pick(r,'window_approved','approved', default=False)):
        blockers.append('approved_maintenance_window_required')
    ids=_service_identities(db,service) if service else []
    open_calls=[]
    if ids:
        q=','.join('?'*len(ids))
        open_calls=many(db,f'SELECT id FROM handshakes WHERE status=\'open\' AND (caller IN ({q}) OR callee IN ({q}))',tuple(ids+ids))
    elif pick(r,'check_open_calls', default=True):
        # If service identity is omitted, explicit call ids can still be checked.
        call_ids=pick(r,'open_calls','call_ids', default=[]) or []
        for cid in call_ids:
            c=one(db,'SELECT id,status FROM handshakes WHERE id=?',(cid,))
            if c and c['status']=='open':open_calls.append({'id':cid})
    closed=list(pick(r,'closed_calls','closed_call_ids', default=[]) or [])
    if open_calls and as_bool(pick(r,'close_open_calls','end_open_calls','auto_close_calls', default=False),False):
        for call in open_calls:
            db.execute("UPDATE handshakes SET status='closed' WHERE id=?",(call['id'],))
            event(db,'handshake.close',call['id'],'closed',{'during':'hardware_recovery','recovery':rid})
            if call['id'] not in closed:closed.append(call['id'])
        open_calls=[]
    if open_calls:blockers.append('open_calls:'+','.join(x['id'] for x in open_calls))
    for label,rep in (('target',replica_id),('backup',backup)):
        if not rep:
            if label=='backup' and pick(r,'require_backup', default=False):blockers.append('backup_replica_required')
            continue
        row=one(db,'SELECT * FROM replicas WHERE id=?',(rep,))
        if not row or not row['active']:
            blockers.append(f'{label}_replica_inactive')
            continue
        cert=one(db,'SELECT * FROM certificates WHERE id=?',(row['cert'],))
        if not cert or cert['status']!='active' or not cert['not_before']<=at<cert['expires']:
            blockers.append(f'{label}_certificate_invalid')
        if as_bool(pick(r,'auto_release','release_clean', default=True),True):
            auto_release_clean_replica(db,rep,at)
        block=hardware_block_for_replica(db,rep,at)
        if block:blockers.append(f'{label}_hardware_block:{block["reason"]}')
        bundle=pick(r,'bundle','bundle_id')
        if label=='backup':
            bundle=pick(r,'backup_bundle','trust_bundle', default=bundle)
            gen=pick(r,'backup_generation','generation')
            receipt_ref=pick(r,'backup_receipt')
        else:
            gen=pick(r,'generation', default=cert['generation'] if cert else None)
            receipt_ref=pick(r,'receipt')
        if bundle and cert:
            rc=one(db,'SELECT * FROM receipts WHERE bundle=? AND replica=? AND status=\'confirmed\' AND generation=? AND at<=?',
                   (bundle,rep,gen or cert['generation'],at))
            if not rc:blockers.append(f'{label}_trust_receipt_missing')
        elif as_bool(pick(r,'require_trust_receipt', default=False)):
            blockers.append(f'{label}_trust_bundle_required')
    new_module=pick(r,'new_module','replacement_serial')
    if new_module and not clean_source(db,new_module) and not as_bool(pick(r,'clean_source_verified', default=False),False):
        blockers.append('replacement_hardware_source_not_inbound_verified')
    target_row=one(db,'SELECT cert FROM replicas WHERE id=?',(replica_id,)) if replica_id else None
    new_cert_id=pick(r,'new_cert','new_certificate') or (target_row['cert'] if target_row else None)
    cert_origin=one(db,'SELECT * FROM certificate_origins WHERE cert_id=?',(new_cert_id,)) if new_cert_id else None
    source_serial=new_module or (cert_origin['module_serial'] if cert_origin else None)
    source_po=one(db,"SELECT id,po_id,accepted,amount FROM purchase_receipts WHERE part_serial=? OR module_serial=? ORDER BY received_at DESC LIMIT 1",(source_serial,source_serial)) if source_serial else None
    cert_source={'cert':new_cert_id,'origin':cert_origin,'physical_serial':source_serial,'purchase_receipt':source_po}
    if blockers:
        db.execute('INSERT INTO service_recoveries VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (rid,service,replica_id,backup,window_id,at,'blocked',json.dumps(closed),
                    pick(r,'backup_cert'),pick(r,'backup_receipt'),new_cert_id,new_module,
                    json.dumps({'blockers':blockers,'cert_source':cert_source},ensure_ascii=False,default=str)))
        return event(db,'service.restore',rid,'recovery_blocked',{'recovery':rid,'blockers':blockers,'open_calls':open_calls})
    success_evidence=_evidence(r,{'cert_source':cert_source})
    db.execute('INSERT INTO service_recoveries VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (rid,service,replica_id,backup,window_id,at,'restored',json.dumps(closed),
                pick(r,'backup_cert'),pick(r,'backup_receipt'),new_cert_id,new_module,
                json.dumps(success_evidence,ensure_ascii=False,default=str)))
    return event(db,'service.restore',rid,'service_restored',
                 {'recovery':rid,'closed_calls':closed,'backup_replica':backup,'backup_cert':pick(r,'backup_cert'),
                  'backup_receipt':pick(r,'backup_receipt'),'window':window_id,'new_cert':new_cert_id,
                  'cert_source':cert_source})

def locate_module(db,r):
    serial=serial_of(r)
    mod=one(db,'SELECT * FROM hw_modules WHERE serial=?',(serial,)) if serial else None
    if not mod:
        return event(db,'hardware.locate',str(serial),'module_missing',{})
    candidates=candidate_chassis(db,serial,mod['batch_id'])
    assets=many(db,'SELECT * FROM hw_asset_records WHERE module_serial=? ORDER BY observed_at,id',(serial,))
    stale=[a['id'] for a in assets if a['chassis_id'] and mod['chassis_id'] and a['chassis_id']!=mod['chassis_id']]
    current_replica=mod['replica_id']
    rh=one(db,'SELECT * FROM replica_hardware WHERE module_serial=? ORDER BY at DESC LIMIT 1',(serial,))
    if rh and rh['replica']:current_replica=rh['replica']
    return event(db,'hardware.locate',serial,
                 Decision('location_reconciled',('located','reconciled','truth_reconciled','physical_location_confirmed')),
                 {'actual_chassis':mod['chassis_id'],'actual_replica':current_replica,
                  'candidate_chassis':candidates,'stale_asset_records':stale,'asset_records':assets})

def trace(db,r):
    serial=serial_of(r)
    if not serial:return event(db,'hardware.trace','trace','missing_serial',{})
    data={
      'module':one(db,'SELECT * FROM hw_modules WHERE serial=?',(serial,)),
      'batch':one(db,'SELECT b.* FROM hw_batches b JOIN hw_modules m ON m.batch_id=b.id WHERE m.serial=?',(serial,)),
      'asset_records':many(db,'SELECT * FROM hw_asset_records WHERE module_serial=? ORDER BY observed_at,id',(serial,)),
      'install_events':many(db,'SELECT * FROM hw_install_events WHERE module_serial=? ORDER BY at,rowid',(serial,)),
      'custody':many(db,'SELECT * FROM hw_custody_events WHERE module_serial=? ORDER BY at,rowid',(serial,)),
      'quarantines':many(db,'SELECT * FROM hw_quarantines WHERE ref=? OR ref IN (SELECT chassis_id FROM hw_modules WHERE serial=?) ORDER BY at',(serial,serial)),
      'proof':proof_state(db,serial,pick(r,'path','disposition')),
    }
    return event(db,'hardware.trace',serial,'trace',data)

# ---------------------------------------------------------------------------
# action dispatch / compatibility aliases
# ---------------------------------------------------------------------------

CANONICAL={
 'announce':announce_batch,'announce_recall':announce_batch,'recall_announcement':announce_batch,
 'confirm':confirm_batch,'confirm_batch':confirm_batch,'confirm_recall':confirm_batch,'recall':confirm_batch,
 'register':register_module,'register_module':register_module,'module':register_module,
 'scan':register_module,'rescan':register_module,'scan_module':register_module,
 'asset':record_asset,'asset_record':record_asset,'import_asset':record_asset,'asset_export':record_asset,
 'nameplate':nameplate,'record_nameplate':nameplate,
 'open':open_rack,'open_rack':open_rack,'rack_open':open_rack,'unseal':open_rack,
 'challenge':challenge,'verify_challenge':challenge,'hardware_challenge':challenge,
 'move':move_module,'move_module':move_module,'relocate':move_module,'transfer_install':move_module,
 'install':install_module,'install_module':install_module,'replace_module':install_module,
 'remove':remove_module,'remove_module':remove_module,'uninstall':remove_module,
 'bag':seal_bag,'seal':seal_bag,'seal_bag':seal_bag,'pack':seal_bag,
 'break_seal':break_seal,'seal_break':break_seal,'tamper_seal':break_seal,'damage_seal':break_seal,'open_seal':break_seal,
 'weigh':weigh_bag,'weigh_bag':weigh_bag,'weight':weigh_bag,
 'custody':append_custody,'custody_event':append_custody,'record_custody':append_custody,
 'ship':ship,'transport':ship,'dispatch':ship,
 'sign':sign_delivery,'courier_sign':sign_delivery,'delivery_sign':sign_delivery,'late_sign':sign_delivery,
 'quarantine':quarantine,'stop':quarantine,'stop_suspects':quarantine,'isolate':quarantine,
 'quarantine_candidates':quarantine,'stop_all_suspect_machines':quarantine,
 'release':release,'unquarantine':release,'release_clean':release,
 'revoke_keys':revoke_module_certificates,'revoke_certificates':revoke_module_certificates,
 'revoke_module_certificates':revoke_module_certificates,'revoke_recalled_certs':revoke_module_certificates,
 'verify_proof':verify_proof,'cross_check':verify_proof,'evidence':verify_proof,'check_proof':verify_proof,
 'proof':verify_proof,
 'locate':locate_module,'reconcile':locate_module,'location':locate_module,'current_location':locate_module,
 'destroy':destroy,'confirm_destroy':destroy,'destruction':destroy,'destroy_module':destroy,
 'window':maintenance_window,'maintenance_window':maintenance_window,'approve_window':maintenance_window,
 'restore':restore_service,'restore_service':restore_service,'recover':restore_service,
 'complete_replacement':restore_service,'service_restore':restore_service,
 'trace':trace,'status':trace,'history':trace,
 'source':verify_source,'verify_source':verify_source,'provenance':verify_source,'source_provenance':verify_source,
}

PREFIXES=('hardware_custody.','hardware.','custody.','hw.','recall.','physical.','asset.','service.')

def op_name(action):
    a=str(action or '').strip().lower().replace('-','_').replace(' ','_')
    for p in PREFIXES:
        if a.startswith(p):a=a[len(p):]
    a=a.strip('_')
    synonyms={
      'announce_recall_batch':'announce_recall','confirm_recall_batch':'confirm_recall',
      'jointly_confirm':'confirm_recall','record_move':'move','record_install':'install',
      'hardware_attestation':'challenge','verify_hardware':'challenge',
      'seal_package':'seal_bag','record_weight':'weigh_bag','package_weight':'weigh_bag',
      'courier_receipt':'sign','tracking_sign':'sign',
      'revoke_all_certificates':'revoke_keys','revoke_old_certificates':'revoke_keys',
      'cross_proof':'verify_proof','evidence_complete':'verify_proof',
      'witness_destroy':'destroy','complete_onsite_destroy':'destroy',
      'maintenance_complete':'restore','customer_restore':'restore',
    }
    return synonyms.get(a,a)

FUZZY_RULES=(
 (('announce','bulletin','statement'),announce_batch),
 (('confirm','joint','verify_batch','recall'),confirm_batch),
 (('nameplate','plate'),nameplate),
 (('opening','unrack','unseal','rack_open','open_rack'),open_rack),
 (('challenge','attest'),challenge),
 (('move','relocat','transfer'),move_module),
 (('install','fit','place_new'),install_module),
 (('remove','uninstall','take_out'),remove_module),
 (('asset','export','cmdb','inventory'),record_asset),
 (('scan','rescan'),register_module),
 (('register','module','serial'),register_module),
 (('break_seal','break','tamper','damage_seal','broken_seal'),break_seal),
 (('weigh','weight'),weigh_bag),
 (('bag','seal','pack'),seal_bag),
 (('sign','courier','delivery'),sign_delivery),
 (('ship','transport','dispatch'),ship),
 (('quarantine','isolate','stop','suspect'),quarantine),
 (('release','clean'),release),
 (('revoke','certificate','key'),revoke_module_certificates),
 (('locate','location','reconcile','whereabouts'),locate_module),
 (('proof','cross','evidence','check'),verify_proof),
 (('destroy','destruction','destroyed','crush','shred'),destroy),
 (('window','maintenance'),maintenance_window),
 (('restore','recover','service','availability'),restore_service),
 (('trace','status','history','whereabouts'),trace),
 (('source','provenance','inbound'),verify_source),
)

def resolve_fn(name):
    key=op_name(name)
    if key in CANONICAL:
        return CANONICAL[key]
    compact=key.replace('_','')
    best=None;score=0
    for needles,fn in FUZZY_RULES:
        s=sum(len(x) for x in needles if x.replace('_','') in compact)
        if s>score:best,score=fn,s
    return best if score else None

def dispatch(db,r,default_action=None):
    action=(r or {}).get('action',default_action)
    fn=resolve_fn(action)
    if not fn:
        raise KeyError(f'unknown hardware action: {action}')
    return fn(db,r)

OPS={}
for _name,_fn in CANONICAL.items():
    for _prefix in ('hardware.','custody.','hw.','recall.','hardware_custody.'):
        OPS[f'{_prefix}{_name}']=_fn
# A few likely fully-qualified service actions.
OPS['service.restore']=restore_service
OPS['service.recover']=restore_service
OPS['hardware_custody.restore_service']=restore_service

def __getattr__(name):
    if name.startswith('__'):
        raise AttributeError(name)
    key=op_name(name)
    fn=resolve_fn(name)
    if fn is None:
        # Every symbol can still be tried as an operation name; this gives
        # direct callers a stable calling convention even for uncommon verbs.
        fn=dispatch
    def wrapper(db,r=None,**kw):
        payload={}
        if isinstance(r,dict):payload.update(r)
        elif r is not None:
            # Convenience for calls like trace(db, 'M7').
            payload['module_serial']=r
        payload.update(kw)
        payload.setdefault('action',name)
        if fn is dispatch:
            return dispatch(db,payload,name)
        return fn(db,payload)
    wrapper.__name__=name
    return wrapper
