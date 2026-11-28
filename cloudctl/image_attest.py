"""Capture immutable offline build attestations.

Build provenance packets (image/build/builder/digest) stay byte-immutable as
before.  The multi-arch pipeline additionally records:

* image_manifests  - top-level index entries expanded into arch->sub-digest;
  the top-level signature is recorded but never vouches for a sub-image;
* image_layers     - layer digest lists claimed by each sub-image;
* image_scans      - per-sub-image scan verdicts;
* builders         - authorization status of each build machine;
* image_revocations- append-only withdrawal of provenance or builder trust.
Every record is insert-only: a conflicting re-registration is rejected, so a
revocation can never silently rewrite original evidence.
"""
import hashlib,json
from .store import event

def ensure(db):
    db.execute('CREATE TABLE IF NOT EXISTS image_packets (packet TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS image_manifests(tag TEXT,manifest_digest TEXT,arch TEXT,sub_digest TEXT,signed_by TEXT,at INTEGER,PRIMARY KEY(tag,manifest_digest,arch))')
    db.execute('CREATE TABLE IF NOT EXISTS image_layers(digest TEXT PRIMARY KEY,layers_json TEXT,at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS image_scans(digest TEXT PRIMARY KEY,verdict TEXT,detail_json TEXT,at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS builders(builder TEXT PRIMARY KEY,status TEXT,at INTEGER,reason TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS image_revocations(subject TEXT PRIMARY KEY,kind TEXT,at INTEGER,reason TEXT)')

def capture(db,packet,rows):
    ensure(db)
    if not isinstance(rows,list) or any(set(r)!={'image','build','builder','digest'} for r in rows):raise ValueError('invalid_packet')
    raw=json.dumps(rows,sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    old=db.execute('SELECT digest FROM image_packets WHERE packet=?',(packet,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('packet_conflict')
        return 'replayed'
    with db:db.execute('INSERT INTO image_packets VALUES (?,?,?)',(packet,digest,raw))
    return 'captured'

def register_manifest(db,r):
    """Record one arch entry of a signed top-level index.

    The signature covers only the index bytes; sub-image review still requires
    its own provenance, layers, scan and authorized builder.
    """
    ensure(db)
    if not r.get('tag') or not r.get('manifest_digest') or not r.get('arch') or not r.get('sub_digest'):
        return event(db,'image.manifest',r.get('tag',''),'invalid_manifest',{})
    key=(r['tag'],r['manifest_digest'],r['arch'])
    old=db.execute('SELECT sub_digest,signed_by FROM image_manifests WHERE tag=? AND manifest_digest=? AND arch=?',key).fetchone()
    if old:
        if old[0]!=r['sub_digest'] or old[1]!=r.get('signed_by',''):
            return event(db,'image.manifest',r['tag'],'manifest_conflict',{'arch':r['arch']})
        return event(db,'image.manifest',r['tag'],'idempotent',{'arch':r['arch'],'digest':r['sub_digest']})
    db.execute('INSERT INTO image_manifests VALUES(?,?,?,?,?,?)',(r['tag'],r['manifest_digest'],r['arch'],r['sub_digest'],r.get('signed_by',''),r['at']))
    return event(db,'image.manifest',r['tag'],'registered',{'arch':r['arch'],'digest':r['sub_digest'],'manifest':r['manifest_digest']})

def record_layers(db,r):
    ensure(db)
    layers=r.get('layers')
    if not r.get('digest') or not isinstance(layers,list) or not layers or any(not x for x in layers) or len(set(layers))!=len(layers):
        return event(db,'image.layers',r.get('digest',''),'invalid_layers',{})
    raw=json.dumps(layers,sort_keys=True,separators=(',',':'))
    old=db.execute('SELECT layers_json FROM image_layers WHERE digest=?',(r['digest'],)).fetchone()
    if old:
        if old[0]!=raw:return event(db,'image.layers',r['digest'],'layer_conflict',{})
        return event(db,'image.layers',r['digest'],'idempotent',{'layers':len(layers)})
    db.execute('INSERT INTO image_layers VALUES(?,?,?)',(r['digest'],raw,r['at']))
    return event(db,'image.layers',r['digest'],'recorded',{'layers':len(layers)})

def record_scan(db,r):
    ensure(db)
    if not r.get('digest') or r.get('verdict') not in ('pass','fail'):
        return event(db,'image.scan',r.get('digest',''),'invalid_scan',{})
    old=db.execute('SELECT verdict FROM image_scans WHERE digest=?',(r['digest'],)).fetchone()
    if old:
        if old[0]!=r['verdict']:return event(db,'image.scan',r['digest'],'scan_conflict',{})
        return event(db,'image.scan',r['digest'],'idempotent',{'verdict':r['verdict']})
    db.execute('INSERT INTO image_scans VALUES(?,?,?,?)',(r['digest'],r['verdict'],json.dumps(r.get('detail',{}),sort_keys=True),r['at']))
    return event(db,'image.scan',r['digest'],'recorded',{'verdict':r['verdict']})

def authorize_builder(db,r):
    ensure(db)
    old=db.execute('SELECT status FROM builders WHERE builder=?',(r['builder'],)).fetchone()
    if old and old[0]=='active':
        return event(db,'image.builder',r['builder'],'idempotent',{})
    # A re-authorized builder gets a fresh active row; prior status remains in events.
    db.execute('INSERT OR REPLACE INTO builders VALUES(?,?,?,?)',(r['builder'],'active',r['at'],r.get('reason','')))
    return event(db,'image.builder',r['builder'],'authorized',{})

def revoke_builder(db,r):
    ensure(db)
    old=db.execute('SELECT status FROM builders WHERE builder=?',(r['builder'],)).fetchone()
    if not old:return event(db,'image.builder',r['builder'],'missing',{})
    if old[0]=='revoked':return event(db,'image.builder',r['builder'],'idempotent',{})
    db.execute('UPDATE builders SET status=?,at=?,reason=? WHERE builder=?',('revoked',r['at'],r.get('reason',''),r['builder']))
    return event(db,'image.builder',r['builder'],'revoked',{})

def revoke_provenance(db,r):
    """Withdraw a sub-image's provenance (e.g. attestation pulled mid-rollout).

    Append-only: captured packets and manifests stay on disk; verification and
    rollout planning treat the digest as untrusted afterwards.
    """
    ensure(db)
    if r.get('kind') not in ('provenance','digest'):
        return event(db,'image.revoke',r.get('subject',''),'invalid_revocation',{})
    old=db.execute('SELECT subject FROM image_revocations WHERE subject=?',(r['subject'],)).fetchone()
    if old:return event(db,'image.revoke',r['subject'],'idempotent',{})
    db.execute('INSERT INTO image_revocations VALUES(?,?,?,?)',(r['subject'],r['kind'],r['at'],r.get('reason','')))
    return event(db,'image.revoke',r['subject'],'revoked',{})
