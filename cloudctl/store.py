import json,sqlite3,hashlib
from contextlib import contextmanager
SCHEMA="""
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS identities(id TEXT PRIMARY KEY,namespace TEXT,service TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS certificates(id TEXT PRIMARY KEY,identity TEXT,generation INTEGER,root TEXT,not_before INTEGER,expires INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS retirements(identity TEXT PRIMARY KEY,at INTEGER,reason TEXT);
CREATE TABLE IF NOT EXISTS bundles(id TEXT PRIMARY KEY,roots TEXT,start INTEGER,expires INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS receipts(bundle TEXT,replica TEXT,generation INTEGER,status TEXT,at INTEGER,PRIMARY KEY(bundle,replica,generation));
CREATE TABLE IF NOT EXISTS deliveries(bundle TEXT,replica TEXT,generation INTEGER,status TEXT,attempts INTEGER,last_error TEXT,PRIMARY KEY(bundle,replica));
CREATE TABLE IF NOT EXISTS replicas(id TEXT PRIMARY KEY,identity TEXT,active INTEGER,cert TEXT);
CREATE TABLE IF NOT EXISTS handshakes(id TEXT PRIMARY KEY,caller TEXT,callee TEXT,at INTEGER,status TEXT,reason TEXT);
CREATE TABLE IF NOT EXISTS admissions(id TEXT PRIMARY KEY,handshake TEXT,decision TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS call_policies(caller TEXT,callee TEXT,purpose TEXT,expires INTEGER,PRIMARY KEY(caller,callee,purpose));
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,subject TEXT,decision TEXT,evidence TEXT);
CREATE TABLE IF NOT EXISTS checkpoints(id INTEGER PRIMARY KEY AUTOINCREMENT,subject TEXT,num INTEGER,kind TEXT,ref TEXT,evidence TEXT,prev_digest TEXT,digest TEXT,event_seq INTEGER);
CREATE INDEX IF NOT EXISTS idx_cp_subject ON checkpoints(subject,num);
CREATE TABLE IF NOT EXISTS seals(seq INTEGER PRIMARY KEY AUTOINCREMENT,at INTEGER,heads TEXT,bundle_snapshot TEXT,digest TEXT);
CREATE TABLE IF NOT EXISTS migrations(bundle TEXT,subject TEXT,basis TEXT,ref TEXT,at INTEGER,seal_seq INTEGER,evidence TEXT,PRIMARY KEY(bundle,subject));
"""
GENESIS=hashlib.sha256(b'cloudctl-checkpoint-genesis').hexdigest()
CHAIN_KINDS=('issue','revoke','replica','publish','withdraw')
SUCCESS_DECISIONS={'issue':('issued',),'revoke':('revoked',),'replica':('active','stopped'),'publish':('published',),'withdraw':('withdrawn',)}
class CheckpointConflict(Exception):
    pass
def init(path):
    db=sqlite3.connect(path)
    try:db.executescript(SCHEMA)
    finally:db.close()
@contextmanager
def tx(path):
    db=sqlite3.connect(path);db.row_factory=sqlite3.Row
    try:
        db.execute('BEGIN IMMEDIATE');yield db;db.commit()
    except Exception:db.rollback();raise
    finally:db.close()
def one(db,q,a=()):
    r=db.execute(q,a).fetchone();return dict(r) if r else None
def many(db,q,a=()):return [dict(r) for r in db.execute(q,a).fetchall()]
def event(db,kind,subject,decision,evidence):
    seq=db.execute('INSERT INTO events(kind,subject,decision,evidence) VALUES(?,?,?,?)',(kind,subject,decision,json.dumps(evidence,sort_keys=True))).lastrowid
    return {'subject':subject,'decision':decision,'evidence':evidence,'seq':seq}
def canon(obj):return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def cp_digest(subject,num,kind,ref,evidence,prev_digest):
    return hashlib.sha256(canon({'subject':subject,'num':num,'kind':kind,'ref':ref,'evidence':evidence,'prev_digest':prev_digest}).encode('utf-8')).hexdigest()
def latest_seal(db):
    return one(db,'SELECT * FROM seals ORDER BY seq DESC LIMIT 1')
def sealed_head(db,subject):
    s=latest_seal(db)
    if not s:return 0
    return (json.loads(s['heads']) or {}).get(subject,0)
def append_checkpoint(db,subject,kind,ref,evidence,event_seq):
    """Append the next unforkable checkpoint for subject. Never overwrites:
    a same-number (or same-event) row can only be read back, and conflicting
    content raises."""
    # Same-number retry: the committed predecessor record is read back, never overwritten.
    prior=one(db,'SELECT * FROM checkpoints WHERE event_seq=? AND subject=?',(event_seq,subject))
    if prior:
        digest=cp_digest(subject,prior['num'],kind,ref,evidence,prior['prev_digest'])
        if prior['digest']==digest and prior['kind']==kind and prior['ref']==ref:
            return prior
        raise CheckpointConflict('subject %s event %s already committed with different content'%(subject,event_seq))
    head=one(db,'SELECT * FROM checkpoints WHERE subject=? ORDER BY num DESC,id DESC LIMIT 1',(subject,))
    num=(head['num']+1) if head else 1
    prev_digest=head['digest'] if head else GENESIS
    digest=cp_digest(subject,num,kind,ref,evidence,prev_digest)
    existing=one(db,'SELECT * FROM checkpoints WHERE subject=? AND num=?',(subject,num))
    if existing:
        if existing['digest']==digest and existing['kind']==kind and existing['ref']==ref and existing['event_seq']==event_seq:
            return existing
        raise CheckpointConflict('subject %s num %s already committed with different content'%(subject,num))
    cur=db.execute('INSERT INTO checkpoints(subject,num,kind,ref,evidence,prev_digest,digest,event_seq) VALUES(?,?,?,?,?,?,?,?)',(subject,num,kind,ref,json.dumps(evidence,sort_keys=True),prev_digest,digest,event_seq))
    return {'id':cur.lastrowid,'subject':subject,'num':num,'kind':kind,'ref':ref,'evidence':json.dumps(evidence,sort_keys=True),'prev_digest':prev_digest,'digest':digest,'event_seq':event_seq}
def verify(db):
    """Recompute every subject chain and cross-check committed events.
    Returns faults for: missing checkpoint, gap/broken predecessor, digest
    tamper, duplicate (forked) number, orphan checkpoint, tampered seal."""
    faults=[];heads={}
    subjects=[r['subject'] for r in many(db,'SELECT DISTINCT subject FROM checkpoints')]
    for subject in subjects:
        rows=many(db,'SELECT * FROM checkpoints WHERE subject=? ORDER BY num,id',(subject,))
        by_num={}
        for cp in rows:
            if cp['num'] in by_num:
                faults.append({'type':'forked_predecessor','subject':subject,'num':cp['num'],'id':cp['id']})
            by_num.setdefault(cp['num'],[]).append(cp)
        expected=1;prev_digest=GENESIS
        for num in sorted(by_num):
            cps=by_num[num]
            if num!=expected:
                faults.append({'type':'gap','subject':subject,'expected':expected,'found':num})
                break
            if len(cps)>1:
                expected+=1;prev_digest=cps[0]['digest'];continue
            cp=cps[0]
            if cp['prev_digest']!=prev_digest:
                faults.append({'type':'broken_predecessor','subject':subject,'num':num,'stored':cp['prev_digest'],'expected':prev_digest})
            recomputed=cp_digest(subject,cp['num'],cp['kind'],cp['ref'],json.loads(cp['evidence']),cp['prev_digest'])
            if recomputed!=cp['digest']:
                faults.append({'type':'digest_mismatch','subject':subject,'num':num})
            prev_digest=cp['digest'];expected+=1
        heads[subject]=max(by_num) if by_num else 0
    ev_rows=many(db,'SELECT * FROM events WHERE kind IN (%s)'%','.join('?'*len(CHAIN_KINDS)),CHAIN_KINDS)
    for ev in ev_rows:
        if ev['decision'] not in SUCCESS_DECISIONS.get(ev['kind'],()):continue
        ev_evidence=json.loads(ev['evidence']) if ev['evidence'] else {}
        if ev['kind']=='replica' and ev_evidence.get('idempotent'):continue
        cp=one(db,'SELECT * FROM checkpoints WHERE event_seq=?',(ev['seq'],))
        if not cp:
            faults.append({'type':'missing_checkpoint','event_seq':ev['seq'],'kind':ev['kind'],'ref':ev['subject']})
            continue
        if cp['kind']!=ev['kind'] or cp['ref']!=ev['subject']:
            faults.append({'type':'checkpoint_event_mismatch','event_seq':ev['seq'],'subject':cp['subject']})
    for cp in many(db,'SELECT * FROM checkpoints'):
        if not one(db,'SELECT seq FROM events WHERE seq=?',(cp['event_seq'],)):
            faults.append({'type':'orphan_checkpoint','subject':cp['subject'],'num':cp['num'],'event_seq':cp['event_seq']})
    for s in many(db,'SELECT * FROM seals'):
        recomputed=hashlib.sha256(canon({'at':s['at'],'heads':json.loads(s['heads']),'snapshot':json.loads(s['bundle_snapshot'])}).encode('utf-8')).hexdigest()
        if recomputed!=s['digest']:
            faults.append({'type':'seal_tampered','seal':s['seq']})
    return {'ok':not faults,'faults':faults,'heads':heads}
def faults(db,subjects=None):
    v=verify(db)
    if subjects is None:return v['faults']
    wanted=set(x for x in subjects if x is not None)
    # Subject-scoped checks still trip on every global fault (e.g. tampered seal)
    # and on cross-cutting faults that carry no single subject.
    return [f for f in v['faults'] if f.get('subject') in wanted or 'subject' not in f]
def quarantined(db,subjects=None):
    return bool(faults(db,subjects))
def seal(db,r):
    """Global sealing: records the actual committed chain-head number of every
    subject and a snapshot of every root bundle. Refuses while any predecessor
    is missing, broken or forked — a partial chain can never fake a seal."""
    v=verify(db)
    if not v['ok']:
        return event(db,'seal','global','chain_unverified',{'faults':v['faults']})
    at=r.get('at',0);heads=dict(v['heads'])
    snapshot={}
    for b in many(db,'SELECT * FROM bundles'):
        snapshot[b['id']]={'roots':json.loads(b['roots']),'status':b['status'],'start':b['start'],'expires':b['expires'],'head':heads.get(b['id'],0)}
    digest=hashlib.sha256(canon({'at':at,'heads':heads,'snapshot':snapshot}).encode('utf-8')).hexdigest()
    seq=db.execute('INSERT INTO seals(at,heads,bundle_snapshot,digest) VALUES(?,?,?,?)',(at,json.dumps(heads,sort_keys=True),json.dumps(snapshot,sort_keys=True),digest)).lastrowid
    return event(db,'seal','global','sealed',{'seal':seq,'at':at,'heads':heads,'snapshot':snapshot,'digest':digest})
def issuance_head_num(db,identity):
    """Highest checkpoint number of an issuance for this identity."""
    r=one(db,"SELECT MAX(num) n FROM checkpoints WHERE subject=? AND kind='issue'",(identity,))
    return r['n'] or 0 if r and r['n'] is not None else 0
def unsealed_issue_blocker(db,identity,cert_generation):
    """An unsealed issuance of a newer generation blocks revocation of an older
    certificate: revoke must not leap over an open issuance scene."""
    barrier=sealed_head(db,identity)
    blockers=[]
    for cp in many(db,"SELECT * FROM checkpoints WHERE subject=? AND kind='issue' AND num>? ORDER BY num",(identity,barrier)):
        gen=json.loads(cp['evidence']).get('generation')
        if gen is not None and gen>cert_generation:
            blockers.append({'num':cp['num'],'ref':cp['ref'],'generation':gen,'digest':cp['digest']})
    return blockers[0] if blockers else None
