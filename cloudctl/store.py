import json,sqlite3
from contextlib import contextmanager
_EXTERNAL=set()
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
"""
def init(path):
    db=sqlite3.connect(path)
    try:db.executescript(SCHEMA)
    finally:db.close()
@contextmanager
def tx(path):
    db=sqlite3.connect(path);db.row_factory=sqlite3.Row
    # Mark the connection so module helpers do not commit midway through the
    # caller's explicit transaction (which would break all-or-nothing work).
    _EXTERNAL.add(id(db))
    try:
        db.execute('BEGIN IMMEDIATE');yield db;db.commit()
    except Exception:db.rollback();raise
    finally:
        _EXTERNAL.discard(id(db));db.close()
def commit(db):
    """Commit unless the connection is already inside a caller-owned transaction."""
    if id(db) not in _EXTERNAL:db.commit()
def one(db,q,a=()):
    r=db.execute(q,a).fetchone();return dict(r) if r else None
def many(db,q,a=()):return [dict(r) for r in db.execute(q,a)]
def event(db,kind,subject,decision,evidence):
    db.execute('INSERT INTO events(kind,subject,decision,evidence) VALUES(?,?,?,?)',(kind,subject,decision,json.dumps(evidence,sort_keys=True)))
    return {'subject':subject,'decision':decision,'evidence':evidence}
