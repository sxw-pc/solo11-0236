"""Offline regional probe intake for service routing."""
import hashlib,json

def ensure_rows(db):
    db.execute('CREATE TABLE IF NOT EXISTS route_probe_rows (page_id TEXT,line_no INTEGER,source TEXT,prefix TEXT,region TEXT,at INTEGER,rtt_ms INTEGER,reachable INTEGER,PRIMARY KEY(page_id,line_no))')

def import_page(db,page_id,rows,received_at):
    db.execute('CREATE TABLE IF NOT EXISTS route_probe_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS route_probe_rows (page_id TEXT,line_no INTEGER,source TEXT,prefix TEXT,region TEXT,at INTEGER,rtt_ms INTEGER,reachable INTEGER,PRIMARY KEY(page_id,line_no))')
    keys={'source','prefix','region','at','rtt_ms','reachable'}
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!=keys or not isinstance(r['at'],int) or not isinstance(r['rtt_ms'],int) or r['rtt_ms']<0 or r['reachable'] not in (0,1) for r in rows):raise ValueError('invalid_probe_page')
    digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    old=db.execute('SELECT digest FROM route_probe_pages WHERE id=?',(page_id,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('probe_page_conflict')
        return {'status':'replayed','rows':len(rows)}
    with db:
        db.execute('INSERT INTO route_probe_pages VALUES (?,?,?)',(page_id,digest,received_at))
        for i,r in enumerate(rows,1):db.execute('INSERT INTO route_probe_rows VALUES (?,?,?,?,?,?,?,?)',(page_id,i,r['source'],r['prefix'],r['region'],r['at'],r['rtt_ms'],r['reachable']))
    return {'status':'captured','rows':len(rows)}
