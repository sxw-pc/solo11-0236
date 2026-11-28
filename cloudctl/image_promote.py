"""Provisional promotion from captured image attestations.

`promote` keeps the legacy provisional behaviour (last matching attestation
row).  Production promotion goes through `promote_manifest`, which expands a
top-level multi-arch index into its per-arch sub-digests and only admits an
architecture whose *own* provenance packet, layer list, clean scan and
authorized builder all verify.  A signed top-level index cannot promote an
unreviewed sub-image.
"""
import json
from .store import event
from . import image_attest

def ensure(db):
    image_attest.ensure(db)
    db.execute('CREATE TABLE IF NOT EXISTS verified_promotions(tag TEXT,manifest_digest TEXT,arch TEXT,digest TEXT,status TEXT,reasons_json TEXT,at INTEGER,PRIMARY KEY(tag,manifest_digest,arch))')

def _rows_for(db,digest):
    out=[]
    for (raw,) in db.execute('SELECT rows_json FROM image_packets'):
        for r in json.loads(raw):
            if r['digest']==digest:out.append(r)
    return out

def verify_digest(db,digest):
    """Verify one sub-image's own evidence chain. Returns (ok, reasons)."""
    ensure(db)
    reasons=[]
    rows=_rows_for(db,digest)
    if not rows:
        reasons.append('provenance_missing')
        return False,reasons
    builders={r['builder'] for r in rows}
    if db.execute('SELECT 1 FROM image_revocations WHERE subject=?',(digest,)).fetchone():
        reasons.append('provenance_revoked')
    layer=db.execute('SELECT 1 FROM image_layers WHERE digest=?',(digest,)).fetchone()
    if not layer:reasons.append('layers_missing')
    scan=db.execute('SELECT verdict FROM image_scans WHERE digest=?',(digest,)).fetchone()
    if not scan:reasons.append('scan_missing')
    elif scan[0]!='pass':reasons.append('scan_failed')
    bad=[b for b in builders if not db.execute('SELECT 1 FROM builders WHERE builder=? AND status=?',(b,'active')).fetchone() or db.execute('SELECT 1 FROM image_revocations WHERE subject=?',(b,)).fetchone()]
    if bad:reasons.append('builder_unauthorized:'+','.join(sorted(bad)))
    return not reasons,reasons

def promote(db,image):
    db.execute('CREATE TABLE IF NOT EXISTS image_promotions (image TEXT, build TEXT, digest TEXT)')
    rows=[r for (raw,) in db.execute('SELECT rows_json FROM image_packets') for r in json.loads(raw) if r['image']==image]
    if not rows:raise ValueError('missing_image')
    row=rows[-1]
    with db:db.execute('INSERT INTO image_promotions VALUES (?,?,?)',(image,row['build'],row['digest']))
    return {'image':image,'build':row['build'],'digest':row['digest']}

def promote_manifest(db,r):
    """Per-arch verified promotion ledger entry for a top-level index."""
    ensure(db)
    entries=db.execute('SELECT arch,sub_digest FROM image_manifests WHERE tag=? AND manifest_digest=?',(r['tag'],r['manifest_digest'])).fetchall()
    if not entries:return event(db,'image.promote',r['tag'],'manifest_unknown',{'manifest':r['manifest_digest']})
    arches={}
    all_ok=True
    for e in entries:
        arch=e[0];digest=e[1]
        ok,reasons=verify_digest(db,digest)
        all_ok=all_ok and ok
        arches[arch]={'digest':digest,'verified':ok,'reasons':reasons}
        db.execute('INSERT OR REPLACE INTO verified_promotions VALUES(?,?,?,?,?,?,?)',(r['tag'],r['manifest_digest'],arch,digest,'verified' if ok else 'rejected',json.dumps(reasons,sort_keys=True),r['at']))
    decision='verified' if all_ok else 'partial'
    return event(db,'image.promote',r['tag'],decision,{'manifest':r['manifest_digest'],'arches':arches})
