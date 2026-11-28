"""Consumer-group takeover and parent/child task recovery.

The recovery coordinator works only from *originals*:

* intake rows carry the full message version (tenant, stream,
  partition, offset, producer sequence, digest), so a display business
  key such as ``P`` can never be resolved by name across tenants;
* parent/child links are concrete version pointers;
* every result write, network mount and checkpoint is fenced by the
  consumer-group generation, so a superseded agent is refused;
* real external effects are recorded in an idempotent action ledger and
  already-persisted results are reused, never executed twice;
* checkpoints only cover this group's verified contiguous results and
  never cross a still-pending child;
* evidence, customer notifications and late originals are append-only
  records that survive restarts; a later state never hides content the
  customer already received.
"""
import hashlib,json
from . import message_intake as intake
from . import message_result as result
from . import offset_checkpoint as checkpoint

DEADLINE_MINUTES=30

class SealedError(ValueError):
    pass

def _canon(obj):
    return json.dumps(obj,sort_keys=True,separators=(',',':'))

def _ref_id(ref):
    return hashlib.sha256(_canon(intake.as_ref(ref)).encode()).hexdigest()[:16]

def ensure_schema(db):
    intake.ensure_schema(db);result.ensure_schema(db);checkpoint.ensure_schema(db)
    db.execute('CREATE TABLE IF NOT EXISTS external_actions (action_id TEXT PRIMARY KEY,kind TEXT,message_ref TEXT,parent_ref TEXT,receipt TEXT,worker TEXT,epoch INTEGER,at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS resource_leases (lease_id TEXT PRIMARY KEY,resource TEXT,holder TEXT,valid_from INTEGER,valid_until INTEGER,status TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS creation_evidence (instance_id TEXT,message_ref TEXT PRIMARY KEY,tenant TEXT,digest TEXT,result_epoch INTEGER,evidence_at INTEGER,receipt TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS sealed_messages (message_ref TEXT PRIMARY KEY,reason TEXT,sealed_at INTEGER,epoch INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS manual_tickets (ticket_id TEXT PRIMARY KEY,message_ref TEXT,parent_ref TEXT,reason TEXT,opened_at INTEGER,status TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS customer_notifications (notification_id TEXT PRIMARY KEY,tenant TEXT,stream TEXT,partition_id INTEGER,offset_id INTEGER,kind TEXT,content TEXT,issued_at INTEGER,epoch INTEGER,evidence TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS late_originals (seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,group_id TEXT,message_ref TEXT,epoch INTEGER,received_at INTEGER,decision TEXT,content TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS recovery_events (seq INTEGER PRIMARY KEY AUTOINCREMENT,at INTEGER,kind TEXT,subject TEXT,decision TEXT,evidence TEXT)')

def _event(db,at,kind,subject,decision,evidence):
    db.execute('INSERT INTO recovery_events(at,kind,subject,decision,evidence) VALUES (?,?,?,?,?)',
               (at,kind,subject,decision,_canon(evidence)))
    return {'at':at,'kind':kind,'subject':subject,'decision':decision,'evidence':evidence}

def events(db):
    ensure_schema(db)
    return [{'seq':r[0],'at':r[1],'kind':r[2],'subject':r[3],'decision':r[4],'evidence':json.loads(r[5])}
            for r in db.execute('SELECT seq,at,kind,subject,decision,evidence FROM recovery_events ORDER BY seq')]

# ---------------------------------------------------------------- external effects

class Gateway:
    """Simulated instance/network side effects; deterministic and inspectable."""
    def __init__(self):
        self.calls=[]
    def create_instance(self,ref,payload,at):
        value=payload.get('value')
        instance_id=value.get('instance_id') if isinstance(value,dict) else value
        if not instance_id:
            instance_id='I-'+hashlib.sha256((_canon(ref)+'create').encode()).hexdigest()[:10]
        self.calls.append(('create_instance',instance_id))
        return {'instance_id':instance_id,'at':at}
    def mount_network(self,ref,parent_ref,payload,instance_id,at):
        value=payload.get('value')
        network=value.get('network') if isinstance(value,dict) else value
        self.calls.append(('mount_network',network,instance_id))
        return {'instance_id':instance_id,'network':network,'at':at}

def run_external(db,kind,ref,worker,epoch,at,gateway,parent_ref=None,payload=None,instance_id=None,group=None):
    """Idempotent external effect: a recorded action is reused, never repeated."""
    ensure_schema(db)
    action_id=kind+':'+_ref_id(ref)
    old=db.execute('SELECT receipt FROM external_actions WHERE action_id=?',(action_id,)).fetchone()
    if old:
        return {'action_id':action_id,'replayed':True,'receipt':json.loads(old[0])}
    if kind=='create_instance':
        receipt=gateway.create_instance(ref,payload,at)
    elif kind=='mount_network':
        receipt=gateway.mount_network(ref,parent_ref,payload,instance_id,at)
    else:
        raise ValueError('unknown_action')
    with db:
        db.execute('INSERT INTO external_actions VALUES (?,?,?,?,?,?,?,?)',
                   (action_id,kind,_canon(ref),_canon(parent_ref) if parent_ref else None,
                    _canon(receipt),worker,epoch,at))
        _event(db,at,'external_action',action_id,'executed',
               {'kind':kind,'worker':worker,'epoch':epoch,'ref':ref,'receipt':receipt,
                'group':group})
    return {'action_id':action_id,'replayed':False,'receipt':receipt}

def action_log(db):
    ensure_schema(db)
    return [{'action_id':r[0],'kind':r[1],'message_ref':json.loads(r[2]),
             'parent_ref':json.loads(r[3]) if r[3] else None,
             'receipt':json.loads(r[4]),'worker':r[5],'epoch':r[6],'at':r[7]}
            for r in db.execute('SELECT action_id,kind,message_ref,parent_ref,receipt,worker,epoch,at FROM external_actions ORDER BY at')]

# ---------------------------------------------------------------- group takeover

def take_group(db,group,stream,partitions,owner,epoch,valid_until,at):
    ensure_schema(db)
    claimed=checkpoint.take_partitions(db,group,stream,partitions,owner,epoch,valid_until)
    for claim in claimed:
        _event(db,at,'takeover',group,'replayed' if claim['replayed'] else 'claimed',
               {'stream':stream,'partition':claim['partition'],'owner':owner,'epoch':epoch,
                'valid_until':valid_until})
    return claimed

# ---------------------------------------------------------------- resource leases

def grant_resource_lease(db,lease_id,resource,holder,valid_from,valid_until):
    ensure_schema(db)
    with db:
        db.execute('INSERT OR REPLACE INTO resource_leases VALUES (?,?,?,?,?,?)',
                   (lease_id,resource,holder,valid_from,valid_until,'active'))
    return {'lease_id':lease_id,'resource':resource,'holder':holder,
            'valid_from':valid_from,'valid_until':valid_until,'status':'active'}

def expire_resource_lease(db,lease_id,at):
    ensure_schema(db)
    r=db.execute('SELECT valid_until FROM resource_leases WHERE lease_id=?',(lease_id,)).fetchone()
    if not r or at<r[0]:return False
    with db:db.execute('UPDATE resource_leases SET status=? WHERE lease_id=?',('expired',lease_id))
    return True

def valid_resource_lease(db,resource,at,holder=None):
    ensure_schema(db)
    q='SELECT * FROM resource_leases WHERE resource=? AND status=? AND valid_from<=? AND valid_until>?'
    a=[resource,'active',at,at]
    if holder is not None:q+=' AND holder=?';a.append(holder)
    r=db.execute(q,a).fetchone()
    return {'lease_id':r[0],'resource':r[1],'holder':r[2],'valid_from':r[3],
            'valid_until':r[4],'status':r[5]} if r else None
# ---------------------------------------------------------------- parent proof

def _instance_id_of(stored_result):
    """Extract the instance id from a stored output {'key','parent','value'}."""
    value=stored_result.get('value')
    return value.get('instance_id') if isinstance(value,dict) else value

def attach_creation_receipt(db,ref,instance_id,at):
    """Bind a real instance creation original to one concrete message version."""
    ensure_schema(db)
    ref=intake.as_ref(ref)
    row=intake.find_by_ref(db,ref)
    if not row:raise ValueError('missing_intake')
    found=result.get_result(db,ref)
    if not found:raise ValueError('missing_result')
    if _instance_id_of(found['result'])!=instance_id:raise ValueError('instance_mismatch')
    old=db.execute('SELECT message_ref FROM creation_evidence WHERE message_ref=?',(_canon(ref),)).fetchone()
    if old:return 'replayed'
    with db:
        db.execute('INSERT INTO creation_evidence VALUES (?,?,?,?,?,?,?)',
                   (instance_id,_canon(ref),row['tenant'],row['digest'],found['epoch'],at,
                    _canon(found['result'])))
        _event(db,at,'creation_evidence',instance_id,'attached',
               {'ref':ref,'completed_by_epoch':found['epoch'],'worker':found['worker']})
    return 'attached'

def parent_proof(db,parent_ref):
    """Independent proof that the instance belongs to this exact parent version."""
    ensure_schema(db)
    parent_ref=intake.as_ref(parent_ref)
    row=intake.find_by_ref(db,parent_ref)
    if not row:return None
    ev=db.execute('SELECT instance_id,digest,result_epoch,evidence_at,receipt FROM creation_evidence WHERE message_ref=?',
                  (_canon(parent_ref),)).fetchone()
    found=result.get_result(db,parent_ref)
    if not ev or not found:return None
    if ev[1]!=row['digest']:return None
    if _instance_id_of(found['result'])!=ev[0]:return None
    return {'instance_id':ev[0],'ref':parent_ref,'digest':ev[1],
            'completed_by_epoch':ev[2],'evidence_at':ev[3],
            'result_worker':found['worker'],'receipt':json.loads(ev[4])}

# ---------------------------------------------------------------- parent/child work

def recover_parent(db,group,parent_ref,worker,epoch,at,gateway):
    """Reuse the persisted real result; only create if none exists."""
    ensure_schema(db)
    parent_ref=intake.as_ref(parent_ref)
    row=intake.find_by_ref(db,parent_ref)
    if not row:raise ValueError('missing_intake')
    checkpoint.require_fence(db,group,row['stream'],row['partition_id'],epoch,at)
    found=result.get_result(db,parent_ref)
    if found:
        instance_id=_instance_id_of(found['result'])
        # The real result is reused; independent ownership proof is attached
        # separately via attach_creation_receipt and never fabricated here.
        return {'decision':'reused','instance_id':instance_id,
                'completed_by_epoch':found['epoch'],'recovery_epoch':epoch}
    receipt=run_external(db,'create_instance',parent_ref,worker,epoch,at,gateway,
                         payload=json.loads(row['payload']),group=group)
    result.store_result(db,row,worker,epoch,group)
    attach_creation_receipt(db,parent_ref,receipt['receipt']['instance_id'],at)
    return {'decision':'executed','instance_id':receipt['receipt']['instance_id'],
            'completed_by_epoch':epoch,'recovery_epoch':epoch}

def _is_sealed(db,ref):
    return db.execute('SELECT 1 FROM sealed_messages WHERE message_ref=?',(_canon(ref),)).fetchone() is not None

def mount_child(db,group,parent_ref,child_ref,worker,epoch,at,gateway,resource=None):
    """Mount the network against the version-proven instance, or seal trying."""
    ensure_schema(db)
    parent_ref=intake.as_ref(parent_ref);child_ref=intake.as_ref(child_ref)
    child=intake.find_by_ref(db,child_ref)
    if not child:raise ValueError('missing_intake')
    linked=intake.parse_parent_ref(child)
    if linked!=parent_ref:raise ValueError('parent_ref_mismatch')
    if _is_sealed(db,child_ref):raise SealedError('child_sealed')
    checkpoint.require_fence(db,group,child['stream'],child['partition_id'],epoch,at)
    proof=parent_proof(db,parent_ref)
    if not proof:raise ValueError('parent_unproven')
    resource=resource or (json.loads(child['payload']).get('value') or {}).get('network')
    lease=valid_resource_lease(db,resource,at)
    if not lease:raise ValueError('resource_lease_invalid')
    existing=result.get_result(db,child_ref)
    if existing:
        return {'decision':'reused','mount':existing['result'].get('value'),
                'completed_by_epoch':existing['epoch'],'lease':lease['lease_id']}
    receipt=run_external(db,'mount_network',child_ref,worker,epoch,at,gateway,
                         parent_ref=parent_ref,payload=json.loads(child['payload']),
                         instance_id=proof['instance_id'],group=group)
    result.store_result(db,child,worker,epoch,group)
    _event(db,at,'mount',proof['instance_id'],'mounted',
           {'network':resource,'parent_ref':parent_ref,'child_ref':child_ref,
            'lease':lease['lease_id'],'epoch':epoch})
    return {'decision':'mounted','mount':receipt['receipt'],'lease':lease['lease_id']}

def advance(db,group,ref,epoch,at):
    """Move a checkpoint only across verified results with resolved parents."""
    ensure_schema(db)
    ref=intake.as_ref(ref)
    cur=checkpoint.checkpoint(db,group,ref['stream'],ref['partition'])['offset']
    for off in range(cur+1,ref['offset']+1):
        row=intake.locate(db,ref['stream'],ref['partition'],off,ref['tenant'])
        if not row:raise ValueError('offset_gap')
        if not result.get_result(db,intake.version_ref(row)):
            raise ValueError('unverified_offset')
        linked=intake.parse_parent_ref(row)
        if linked is not None and not result.get_result(db,linked):
            raise ValueError('parent_pending')
    return checkpoint.acknowledge(db,group,ref['stream'],ref['partition'],ref['offset'],
                                  epoch,verify=True,at=at)

# ---------------------------------------------------------------- sealing / tickets / notifications

def seal_child(db,parent_ref,child_ref,reasons,epoch,at):
    ensure_schema(db)
    child_ref=intake.as_ref(child_ref)
    if _is_sealed(db,child_ref):return 'replayed'
    with db:
        db.execute('INSERT INTO sealed_messages VALUES (?,?,?,?)',
                   (_canon(child_ref),_canon(reasons),at,epoch))
        _event(db,at,'seal',_ref_id(child_ref),'sealed',
               {'child_ref':child_ref,'reasons':reasons,'epoch':epoch})
    return 'sealed'

def open_manual_ticket(db,parent_ref,child_ref,reasons,at):
    ensure_schema(db)
    ticket_id='T-'+_ref_id(child_ref)
    if db.execute('SELECT 1 FROM manual_tickets WHERE ticket_id=?',(ticket_id,)).fetchone():
        return ticket_id
    with db:
        db.execute('INSERT INTO manual_tickets VALUES (?,?,?,?,?,?)',
                   (ticket_id,_canon(child_ref),_canon(intake.as_ref(parent_ref)),
                    _canon(reasons),at,'open'))
    return ticket_id

def notify_customer(db,tenant,ref,kind,content,epoch,at,evidence=None):
    """Append-only customer original; repeated notifications are not duplicated."""
    ensure_schema(db)
    ref=intake.as_ref(ref)
    notification_id=kind+':'+_ref_id(ref)
    old=db.execute('SELECT content FROM customer_notifications WHERE notification_id=?',
                   (notification_id,)).fetchone()
    if old:return {'notification_id':notification_id,'replayed':True,
                   'content':json.loads(old[0])}
    with db:
        db.execute('INSERT INTO customer_notifications VALUES (?,?,?,?,?,?,?,?,?,?)',
                   (notification_id,tenant,ref['stream'],ref['partition'],ref['offset'],
                    kind,_canon(content),at,epoch,_canon(evidence or {})))
        _event(db,at,'notify',notification_id,kind,
               {'tenant':tenant,'ref':ref,'content':content,'epoch':epoch})
    return {'notification_id':notification_id,'replayed':False,'content':content}

def notifications(db,tenant=None):
    ensure_schema(db)
    q='SELECT notification_id,tenant,stream,partition_id,offset_id,kind,content,issued_at,epoch FROM customer_notifications'
    a=[]
    if tenant is not None:q+=' WHERE tenant=?';a.append(tenant)
    q+=' ORDER BY issued_at,notification_id'
    return [{'notification_id':r[0],'tenant':r[1],'stream':r[2],'partition':r[3],
             'offset':r[4],'kind':r[5],'content':json.loads(r[6]),'issued_at':r[7],
             'epoch':r[8]} for r in db.execute(q,a)]

# ---------------------------------------------------------------- late originals

def register_late_original(db,group,kind,ref,epoch,at,content=None):
    """A stale-generation write/ack is recorded but never changes conclusions."""
    ensure_schema(db)
    ref=intake.as_ref(ref)
    owner=checkpoint.current_owner(db,group,ref['stream'],ref['partition'])
    decision='rejected_stale_generation'
    if owner and epoch==owner['epoch']:
        decision='accepted_current_generation'
    with db:
        db.execute('INSERT INTO late_originals(kind,group_id,message_ref,epoch,received_at,decision,content) VALUES (?,?,?,?,?,?,?)',
                   (kind,group,_canon(ref),epoch,at,decision,
                    _canon(content) if content is not None else None))
        _event(db,at,'late_original',_ref_id(ref),decision,
               {'kind':kind,'epoch':epoch,'current_epoch':owner['epoch'] if owner else None})
    return decision

def late_originals(db):
    ensure_schema(db)
    return [{'seq':r[0],'kind':r[1],'group':r[2],'message_ref':json.loads(r[3]),
             'epoch':r[4],'received_at':r[5],'decision':r[6],
             'content':json.loads(r[7]) if r[7] else None}
            for r in db.execute('SELECT seq,kind,group_id,message_ref,epoch,received_at,decision,content FROM late_originals ORDER BY seq')]

# ---------------------------------------------------------------- orchestration

def _fallback(db,group,parent_ref,child_ref,epoch,at,reasons):
    proof=parent_proof(db,parent_ref)
    seal_child(db,parent_ref,child_ref,reasons,epoch,at)
    ticket=open_manual_ticket(db,parent_ref,child_ref,reasons,at)
    child=intake.find_by_ref(db,child_ref)
    content={'status':'undelivered','instance_id':proof['instance_id'] if proof else None,
             'network':None,'network_mounted':False,'ticket':ticket,'reasons':reasons}
    notify_customer(db,child['tenant'],child_ref,'incomplete',content,epoch,at,
                    evidence={'proof':proof,'reasons':reasons})
    _event(db,at,'family',_ref_id(child_ref),'quarantined',
           {'parent_ref':parent_ref,'child_ref':child_ref,'reasons':reasons,
            'instance_preserved':proof is not None})
    return {'decision':'undelivered','reasons':reasons,'ticket':ticket,
            'instance_id':proof['instance_id'] if proof else None,
            'network_mounted':False,'proof':proof}

def recover_family(db,group,parent_ref,child_ref,worker,epoch,at,
                   gateway=None,deadline=DEADLINE_MINUTES,resource=None):
    """Run both contractual outcomes from one fault scene; pick by proof+lease."""
    ensure_schema(db)
    gateway=gateway or Gateway()
    parent_ref=intake.as_ref(parent_ref);child_ref=intake.as_ref(child_ref)
    child=intake.find_by_ref(db,child_ref)
    if not child:raise ValueError('missing_intake')
    prior=notifications(db,child['tenant'])
    for note in prior:
        if note['stream']==child_ref['stream'] and note['partition']==child_ref['partition'] and note['offset']==child_ref['offset']:
            done=result.get_result(db,child_ref) is not None
            return {'decision':'delivered' if done else 'undelivered','replayed':True,
                    'notification':note}
    if _is_sealed(db,child_ref):
        return {'decision':'undelivered','replayed':True,'sealed':True}
    resource=resource or (json.loads(child['payload']).get('value') or {}).get('network')
    lease=valid_resource_lease(db,resource,at)
    proof=parent_proof(db,parent_ref)
    reasons=[]
    if at>deadline:reasons.append('proof_deadline_exceeded')
    if lease is None:reasons.append('resource_lease_invalid')
    if proof is None:reasons.append('parent_proof_unavailable')
    if reasons:
        return _fallback(db,group,parent_ref,child_ref,epoch,at,reasons)
    # Proof and lease are in hand: reuse the real creation result, mount the
    # network once, then move both partitions only over verified work.
    parent=recover_parent(db,group,parent_ref,worker,epoch,at,gateway)
    mount=mount_child(db,group,parent_ref,child_ref,worker,epoch,at,gateway,resource)
    advance(db,group,parent_ref,epoch,at)
    advance(db,group,child_ref,epoch,at)
    content={'status':'delivered','instance_id':proof['instance_id'],
             'network':resource,'network_mounted':True,'available_at':at,
             'instance_completed_by_epoch':parent['completed_by_epoch'],
             'mount_completed_by_epoch':epoch}
    notify_customer(db,child['tenant'],child_ref,'delivered',content,epoch,at,
                    evidence={'proof':proof,'mount':mount,'lease':mount['lease']})
    return {'decision':'delivered','replayed':False,'instance_id':proof['instance_id'],
            'network':resource,'network_mounted':True,'available_at':at,
            'instance_completed_by_epoch':parent['completed_by_epoch'],
            'mount_completed_by_epoch':epoch,'parent':parent,'mount':mount}

def family_state(db,group,parent_ref,child_ref):
    """Restart-safe snapshot of every original behind one parent/child family."""
    ensure_schema(db)
    parent_ref=intake.as_ref(parent_ref);child_ref=intake.as_ref(child_ref)
    child=intake.find_by_ref(db,child_ref)
    parent_result=result.get_result(db,parent_ref)
    child_result=result.get_result(db,child_ref)
    return {
        'parent_result':parent_result,
        'child_result':child_result,
        'parent_checkpoint':checkpoint.checkpoint(db,group,parent_ref['stream'],parent_ref['partition']),
        'child_checkpoint':checkpoint.checkpoint(db,group,child_ref['stream'],child_ref['partition']),
        'proof':parent_proof(db,parent_ref),
        'sealed':_is_sealed(db,child_ref),
        'notifications':notifications(db,child['tenant']) if child else [],
        'actions':action_log(db),
        'late_originals':late_originals(db),
        'events':events(db),
    }
