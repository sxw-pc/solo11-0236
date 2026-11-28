"""Durable message arrival for a small service event bus.

Every stored message is owned by its full identity: tenant, stream,
partition, offset, producer sequence and a digest of the canonical
payload.  The display business key is *not* unique and may repeat in
another tenant or stream; parent/child links therefore point at a
concrete message version instead of guessing by name.
"""
import hashlib,json

COLUMNS=('stream','partition_id','offset_id','tenant','producer','sequence_id',
         'business_key','parent_key','parent_ref','digest','payload')
REF_KEYS=('tenant','stream','partition','offset','producer','sequence','digest')

def canonical(payload):
    return json.dumps(payload,sort_keys=True,separators=(',',':'))

def digest_of(payload):
    return hashlib.sha256(canonical(payload).encode()).hexdigest()

def ensure_schema(db):
    db.execute('CREATE TABLE IF NOT EXISTS intake (stream TEXT,partition_id INTEGER,offset_id INTEGER,tenant TEXT,producer TEXT,sequence_id INTEGER,business_key TEXT,parent_key TEXT,parent_ref TEXT,digest TEXT,payload TEXT,PRIMARY KEY(stream,partition_id,offset_id))')
    cols={r[1] for r in db.execute('PRAGMA table_info(intake)')}
    for name,ddl in (('tenant','TEXT'),('parent_ref','TEXT')):
        if name not in cols:
            db.execute('ALTER TABLE intake ADD COLUMN %s %s'%(name,ddl))

def _row(found):
    if found is None:return None
    if isinstance(found,dict):return dict(found)
    return dict(zip(COLUMNS,found))

def accept(db,stream,partition,offset,producer,sequence,key,parent,payload,tenant=None,parent_ref=None):
    ensure_schema(db)
    raw=canonical(payload)
    digest=hashlib.sha256(raw.encode()).hexdigest()
    ref=as_ref(parent_ref) if parent_ref is not None else None
    old=_row(db.execute('SELECT %s FROM intake WHERE stream=? AND partition_id=? AND offset_id=?'%(','.join(COLUMNS),),
                        (stream,partition,offset)).fetchone())
    expected=(stream,partition,offset,tenant,producer,sequence,key,parent,
              json.dumps(ref,sort_keys=True,separators=(',',':')) if ref is not None else None,digest,raw)
    if old:
        if tuple(old[c] for c in COLUMNS)!=expected:raise ValueError('offset_conflict')
        return 'replayed'
    with db:
        db.execute('INSERT INTO intake (%s) VALUES (%s)'%(','.join(COLUMNS),','.join('?'*len(COLUMNS))),expected)
    return 'accepted'

def as_ref(ref):
    """Normalize an incoming version pointer; a malformed one is rejected."""
    if not isinstance(ref,dict):raise ValueError('bad_parent_ref')
    missing=[k for k in REF_KEYS if k not in ref]
    if missing:raise ValueError('bad_parent_ref')
    return {k:ref[k] for k in REF_KEYS}

def version_ref(row):
    """The concrete version identity of a stored intake row."""
    return {'tenant':row['tenant'],'stream':row['stream'],'partition':row['partition_id'],
            'offset':row['offset_id'],'producer':row['producer'],'sequence':row['sequence_id'],
            'digest':row['digest']}

def parse_parent_ref(row):
    if not row or not row.get('parent_ref'):return None
    return json.loads(row['parent_ref'])

def find_by_ref(db,ref):
    ref=as_ref(ref)
    return _row(db.execute(
        'SELECT %s FROM intake WHERE tenant IS ? AND stream=? AND partition_id=? AND offset_id=? AND producer=? AND sequence_id=? AND digest=?'%(','.join(COLUMNS),),
        (ref['tenant'],ref['stream'],ref['partition'],ref['offset'],ref['producer'],ref['sequence'],ref['digest'])).fetchone())

def locate(db,stream,partition,offset,tenant=None):
    ensure_schema(db)
    q='SELECT %s FROM intake WHERE stream=? AND partition_id=? AND offset_id=?'%(','.join(COLUMNS),)
    a=[stream,partition,offset]
    if tenant is not None:
        q+=' AND tenant=?';a.append(tenant)
    return _row(db.execute(q,a).fetchone())
