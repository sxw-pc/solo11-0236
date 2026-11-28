import json,sqlite3
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
CREATE TABLE IF NOT EXISTS handshakes(id TEXT PRIMARY KEY,caller TEXT,callee TEXT,at INTEGER,status TEXT,reason TEXT,caller_replica TEXT DEFAULT '',callee_replica TEXT DEFAULT '',purpose TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS admissions(id TEXT PRIMARY KEY,handshake TEXT,decision TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS call_policies(caller TEXT,callee TEXT,purpose TEXT,expires INTEGER,PRIMARY KEY(caller,callee,purpose));
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,subject TEXT,decision TEXT,evidence TEXT);
CREATE TABLE IF NOT EXISTS image_manifests(tag TEXT,manifest_digest TEXT,arch TEXT,sub_digest TEXT,signed_by TEXT,at INTEGER,PRIMARY KEY(tag,manifest_digest,arch));
CREATE TABLE IF NOT EXISTS image_layers(digest TEXT PRIMARY KEY,layers_json TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS image_scans(digest TEXT PRIMARY KEY,verdict TEXT,detail_json TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS builders(builder TEXT PRIMARY KEY,status TEXT,at INTEGER,reason TEXT);
CREATE TABLE IF NOT EXISTS image_revocations(subject TEXT PRIMARY KEY,kind TEXT,at INTEGER,reason TEXT);
CREATE TABLE IF NOT EXISTS verified_promotions(tag TEXT,manifest_digest TEXT,arch TEXT,digest TEXT,status TEXT,reasons_json TEXT,at INTEGER,PRIMARY KEY(tag,manifest_digest,arch));
CREATE TABLE IF NOT EXISTS release_batches(batch TEXT PRIMARY KEY,tag TEXT,manifest_digest TEXT,mode TEXT,status TEXT,at INTEGER,detail_json TEXT);
CREATE TABLE IF NOT EXISTS release_orders(batch TEXT,node TEXT,arch TEXT,identity TEXT,old_replica TEXT,new_replica TEXT,target_digest TEXT,retained INTEGER,startup_id TEXT,status TEXT,checked_digest TEXT,at INTEGER,PRIMARY KEY(batch,node));
CREATE TABLE IF NOT EXISTS release_checkouts(batch TEXT,node TEXT,startup_id TEXT,digest TEXT,at INTEGER,PRIMARY KEY(batch,node));
CREATE TABLE IF NOT EXISTS release_receipts(batch TEXT,node TEXT,startup_id TEXT,identity TEXT,replica TEXT,generation INTEGER,arch TEXT,digest TEXT,status TEXT,at INTEGER,PRIMARY KEY(batch,node));
CREATE TABLE IF NOT EXISTS release_probes(batch TEXT,node TEXT,handshake TEXT,at INTEGER,PRIMARY KEY(batch,node));
CREATE TABLE IF NOT EXISTS release_recalls(batch TEXT,node TEXT,digest TEXT,reason TEXT,status TEXT,at INTEGER,PRIMARY KEY(batch,node));
CREATE TABLE IF NOT EXISTS feature_gates(purpose TEXT PRIMARY KEY,digests_json TEXT);
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
def many(db,q,a=()):return [dict(r) for r in db.execute(q,a)]
def event(db,kind,subject,decision,evidence):
    db.execute('INSERT INTO events(kind,subject,decision,evidence) VALUES(?,?,?,?)',(kind,subject,decision,json.dumps(evidence,sort_keys=True)))
    return {'subject':subject,'decision':decision,'evidence':evidence}
