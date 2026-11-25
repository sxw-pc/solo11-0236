"""Durable message arrival for a small service event bus."""
import hashlib,json

def accept(db,stream,partition,offset,producer,sequence,key,parent,payload):
    db.execute('CREATE TABLE IF NOT EXISTS intake (stream TEXT,partition_id INTEGER,offset_id INTEGER,producer TEXT,sequence_id INTEGER,business_key TEXT,parent_key TEXT,digest TEXT,payload TEXT,PRIMARY KEY(stream,partition_id,offset_id))')
    raw=json.dumps(payload,sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    old=db.execute('SELECT producer,sequence_id,business_key,parent_key,digest FROM intake WHERE stream=? AND partition_id=? AND offset_id=?',(stream,partition,offset)).fetchone()
    expected=(producer,sequence,key,parent,digest)
    if old:
        if tuple(old)!=expected: raise ValueError('offset_conflict')
        return 'replayed'
    with db: db.execute('INSERT INTO intake VALUES (?,?,?,?,?,?,?,?,?)',(stream,partition,offset,producer,sequence,key,parent,digest,raw))
    return 'accepted'
