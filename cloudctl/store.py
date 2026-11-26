import json,sqlite3,hashlib
from contextlib import contextmanager
SCHEMA="""
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS identities(id TEXT PRIMARY KEY,namespace TEXT,service TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS certificates(id TEXT PRIMARY KEY,identity TEXT,generation INTEGER,root TEXT,not_before INTEGER,expires INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS retirements(identity TEXT PRIMARY KEY,at INTEGER,reason TEXT);
CREATE TABLE IF NOT EXISTS bundles(id TEXT PRIMARY KEY,roots TEXT,start INTEGER,expires INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS receipts(bundle TEXT,replica TEXT,generation INTEGER,status TEXT,at INTEGER,PRIMARY KEY(bundle,replica));
CREATE TABLE IF NOT EXISTS deliveries(bundle TEXT,replica TEXT,generation INTEGER,status TEXT,attempts INTEGER,last_error TEXT,PRIMARY KEY(bundle,replica));
CREATE TABLE IF NOT EXISTS replicas(id TEXT PRIMARY KEY,identity TEXT,active INTEGER,cert TEXT);
CREATE TABLE IF NOT EXISTS handshakes(id TEXT PRIMARY KEY,caller TEXT,callee TEXT,at INTEGER,status TEXT,reason TEXT);
CREATE TABLE IF NOT EXISTS admissions(id TEXT PRIMARY KEY,handshake TEXT,decision TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS call_policies(caller TEXT,callee TEXT,purpose TEXT,expires INTEGER,PRIMARY KEY(caller,callee,purpose));
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,subject TEXT,decision TEXT,evidence TEXT);
CREATE TABLE IF NOT EXISTS legal_orders(id TEXT,version INTEGER,kind TEXT,identity TEXT,subject TEXT,scope TEXT,issued_at INTEGER,expires INTEGER,executor TEXT,custodian TEXT,original_ref TEXT,original_hash TEXT,require_original_ciphertext INTEGER,superseded INTEGER,PRIMARY KEY(id,version));
CREATE TABLE IF NOT EXISTS data_keys(id TEXT PRIMARY KEY,identity TEXT,generation INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS key_shares(id TEXT PRIMARY KEY,key_id TEXT,holder TEXT,present INTEGER);
CREATE TABLE IF NOT EXISTS physical_volumes(id TEXT PRIMARY KEY,identity TEXT,key_id TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS volume_copies(id TEXT PRIMARY KEY,volume TEXT,controller TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS physical_blocks(id TEXT,volume TEXT,cipher_digest TEXT,plain_digest TEXT,key_id TEXT,status TEXT,PRIMARY KEY(id,volume));
CREATE TABLE IF NOT EXISTS copy_block_erasure(copy_id TEXT,block_id TEXT,receipt_id TEXT,PRIMARY KEY(copy_id,block_id));
CREATE TABLE IF NOT EXISTS data_objects(id TEXT,identity TEXT,tenant TEXT,plain_digest TEXT,PRIMARY KEY(id,identity));
CREATE TABLE IF NOT EXISTS object_blocks(object_id TEXT,identity TEXT,block_id TEXT,volume TEXT,key_id TEXT,reachable INTEGER,PRIMARY KEY(object_id,block_id,volume));
CREATE TABLE IF NOT EXISTS custody_cases(identity TEXT PRIMARY KEY,mode TEXT,order_fingerprint TEXT,state TEXT,opened_at INTEGER,closed_at INTEGER);
CREATE TABLE IF NOT EXISTS custody_steps(identity TEXT,seq INTEGER,action TEXT,at INTEGER,detail TEXT,PRIMARY KEY(identity,seq));
CREATE TABLE IF NOT EXISTS erasure_receipts(id TEXT PRIMARY KEY,identity TEXT,copy_id TEXT,volume TEXT,scope TEXT,block_id TEXT,object_id TEXT,at INTEGER,receipt_hash TEXT);
CREATE TABLE IF NOT EXISTS key_shreds(id TEXT PRIMARY KEY,key_id TEXT,at INTEGER,receipt_hash TEXT);
CREATE TABLE IF NOT EXISTS migration_proofs(id TEXT PRIMARY KEY,identity TEXT,from_volume TEXT,to_volume TEXT,old_key TEXT,new_key TEXT,order_id TEXT,order_version INTEGER,preserved_digest TEXT,excluded TEXT,at INTEGER,receipt_hash TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS rearrangement_proofs(id TEXT PRIMARY KEY,identity TEXT,volume TEXT,order_id TEXT,order_version INTEGER,kept_digest TEXT,excluded_digest TEXT,at INTEGER,receipt_hash TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS court_deliveries(id TEXT PRIMARY KEY,identity TEXT,order_id TEXT,order_version INTEGER,custodian TEXT,volume TEXT,key_id TEXT,form TEXT,scope TEXT,byte_digest TEXT,at INTEGER,receipt_hash TEXT);
CREATE TABLE IF NOT EXISTS destruction_certificates(id TEXT PRIMARY KEY,identity TEXT,at INTEGER,basis TEXT,superseded_by TEXT,note TEXT);
CREATE TABLE IF NOT EXISTS manifests(id TEXT PRIMARY KEY,identity TEXT,at INTEGER,digest TEXT);
"""
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
def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode('utf-8')).hexdigest()
def event(db,kind,subject,decision,evidence):
    db.execute('INSERT INTO events(kind,subject,decision,evidence) VALUES(?,?,?,?)',(kind,subject,decision,json.dumps(evidence,sort_keys=True)))
    return {'subject':subject,'decision':decision,'evidence':evidence}
def step(db,identity,action,at,detail):
    row=one(db,'SELECT MAX(seq) m FROM custody_steps WHERE identity=?',(identity,))
    seq=(row['m'] or 0)+1
    db.execute('INSERT INTO custody_steps VALUES(?,?,?,?,?)',(identity,seq,action,at,json.dumps(detail,sort_keys=True)))
    return seq
