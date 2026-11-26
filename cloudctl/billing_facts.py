"""Offline capture of the three billing fact segments.

Every original page keeps its device identity, whole-page digest, a single
clock skew that can only act on every row of that device page together, and
the storage time.  Each preserved original retains proxy instance, request
token, certificate generation, backend execution receipt, storage time and
the physical link counter where the segment has one.
"""
import hashlib,json

PROXY_STATUSES={'timeout','success'}
BACKEND_STATUSES={'success','failure'}

def ensure(db):
    db.execute('CREATE TABLE IF NOT EXISTS request_pages(page TEXT PRIMARY KEY,device TEXT,digest TEXT,clock_skew INTEGER NOT NULL DEFAULT 0,stored_at INTEGER NOT NULL DEFAULT 0)')
    db.execute('CREATE TABLE IF NOT EXISTS proxy_pages(page TEXT PRIMARY KEY,device TEXT,digest TEXT,clock_skew INTEGER NOT NULL DEFAULT 0,stored_at INTEGER NOT NULL DEFAULT 0)')
    db.execute('CREATE TABLE IF NOT EXISTS backend_pages(page TEXT PRIMARY KEY,device TEXT,digest TEXT,clock_skew INTEGER NOT NULL DEFAULT 0,stored_at INTEGER NOT NULL DEFAULT 0)')
    db.execute('CREATE TABLE IF NOT EXISTS request_facts(token TEXT PRIMARY KEY,page TEXT,tenant TEXT,path TEXT,units INTEGER,admission TEXT,cert_generation INTEGER,at INTEGER,at_norm INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS proxy_facts(proxy TEXT,token TEXT,page TEXT,status TEXT,units INTEGER,cert_generation INTEGER,receipt TEXT,link_counter INTEGER,at INTEGER,at_norm INTEGER,PRIMARY KEY(proxy,token))')
    db.execute('CREATE TABLE IF NOT EXISTS backend_facts(receipt TEXT,token TEXT,page TEXT,status TEXT,units INTEGER,at INTEGER,at_norm INTEGER,PRIMARY KEY(token,receipt))')

def _digest(rows):
    raw=json.dumps(rows,sort_keys=True,separators=(',',':'))
    return raw,hashlib.sha256(raw.encode()).hexdigest()

def _require(rows,fields,ints):
    if not isinstance(rows,list):
        raise ValueError('invalid_page')
    for r in rows:
        if not isinstance(r,dict) or set(r)!=fields:
            raise ValueError('invalid_page')
        for k in fields-ints:
            if not isinstance(r[k],str):
                raise ValueError('invalid_page')
        for k in ints:
            if isinstance(r[k],bool) or not isinstance(r[k],int) or r[k]<0:
                raise ValueError('invalid_page')

def _begin_page(db,page_table,fact_table,page,device,clock_skew,stored_at):
    ensure(db)
    old=db.execute('SELECT digest,device,clock_skew,stored_at FROM %s WHERE page=?'%page_table,(page,)).fetchone()
    if old:
        return old,True
    if not isinstance(device,str) or not device:
        raise ValueError('invalid_page')
    if isinstance(clock_skew,bool) or not isinstance(clock_skew,int) or isinstance(stored_at,bool) or not isinstance(stored_at,int):
        raise ValueError('invalid_page')
    return None,False

def _finish_page(db,page_table,fact_table,page,device,digest,clock_skew,stored_at,sql,args):
    old=db.execute('SELECT digest,device,clock_skew,stored_at FROM %s WHERE page=?'%page_table,(page,)).fetchone()
    if old:
        if old[0]!=digest or old[1]!=device or old[2]!=clock_skew or old[3]!=stored_at:
            raise ValueError('page_conflict')
        return 'replayed'
    with db:
        db.execute('INSERT INTO %s VALUES(?,?,?,?,?)'%page_table,(page,device,digest,clock_skew,stored_at))
        db.executemany(sql,args)
    return 'captured'

def capture_request(db,page,rows,device,clock_skew=0,stored_at=0):
    """Original request segment: one row per physical request token."""
    fields={'token','tenant','path','units','admission','cert_generation','at'}
    ints={'units','cert_generation','at'}
    _require(rows,fields,ints)
    raw,digest=_digest(rows)
    old,_=_begin_page(db,'request_pages','request_facts',page,device,clock_skew,stored_at)
    if old:
        if old[0]!=digest or old[1]!=device or old[2]!=clock_skew or old[3]!=stored_at:
            raise ValueError('page_conflict')
        return 'replayed'
    for r in rows:
        if db.execute('SELECT 1 FROM request_facts WHERE token=?',(r['token'],)).fetchone():
            raise ValueError('duplicate_request')
    args=[(r['token'],page,r['tenant'],r['path'],r['units'],r['admission'],r['cert_generation'],r['at'],r['at']+clock_skew) for r in rows]
    return _finish_page(db,'request_pages','request_facts',page,device,digest,clock_skew,stored_at,
        'INSERT INTO request_facts(token,page,tenant,path,units,admission,cert_generation,at,at_norm) VALUES(?,?,?,?,?,?,?,?,?)',args)

def capture_proxy(db,page,rows,device,clock_skew=0,stored_at=0):
    """Proxy forwarding segment: one row per physical transmission hop."""
    fields={'proxy','token','status','units','cert_generation','receipt','link_counter','at'}
    ints={'units','cert_generation','link_counter','at'}
    _require(rows,fields,ints)
    for r in rows:
        if r['status'] not in PROXY_STATUSES:
            raise ValueError('invalid_page')
        if r['status']=='success' and not r['receipt']:
            raise ValueError('invalid_page')
    raw,digest=_digest(rows)
    old,_=_begin_page(db,'proxy_pages','proxy_facts',page,device,clock_skew,stored_at)
    if old:
        if old[0]!=digest or old[1]!=device or old[2]!=clock_skew or old[3]!=stored_at:
            raise ValueError('page_conflict')
        return 'replayed'
    seen={}
    for r in rows:
        if (r['proxy'],r['token']) in seen:
            raise ValueError('duplicate_hop')
        seen[(r['proxy'],r['token'])]=True
        if db.execute('SELECT 1 FROM proxy_facts WHERE proxy=? AND token=?',(r['proxy'],r['token'])).fetchone():
            raise ValueError('duplicate_hop')
        # Physical link counters are cumulative per device and may never go backwards.
        prev=db.execute('SELECT MAX(f.link_counter) m FROM proxy_facts f JOIN proxy_pages p ON p.page=f.page WHERE p.device=?',(device,)).fetchone()[0]
        floor=prev if prev is not None else -1
        if r['link_counter']<floor:
            raise ValueError('link_counter_regression')
        floor=max(floor,r['link_counter'])
    args=[(r['proxy'],r['token'],page,r['status'],r['units'],r['cert_generation'],r['receipt'],r['link_counter'],r['at'],r['at']+clock_skew) for r in rows]
    return _finish_page(db,'proxy_pages','proxy_facts',page,device,digest,clock_skew,stored_at,
        'INSERT INTO proxy_facts(proxy,token,page,status,units,cert_generation,receipt,link_counter,at,at_norm) VALUES(?,?,?,?,?,?,?,?,?,?)',args)

def capture_backend(db,page,rows,device,clock_skew=0,stored_at=0):
    """Backend completion segment: one row per execution receipt."""
    fields={'receipt','token','status','units','at'}
    ints={'units','at'}
    _require(rows,fields,ints)
    for r in rows:
        if r['status'] not in BACKEND_STATUSES:
            raise ValueError('invalid_page')
    raw,digest=_digest(rows)
    old,_=_begin_page(db,'backend_pages','backend_facts',page,device,clock_skew,stored_at)
    if old:
        if old[0]!=digest or old[1]!=device or old[2]!=clock_skew or old[3]!=stored_at:
            raise ValueError('page_conflict')
        return 'replayed'
    for r in rows:
        other=db.execute('SELECT token FROM backend_facts WHERE receipt=?',(r['receipt'],)).fetchone()
        if other and other[0]!=r['token']:
            raise ValueError('receipt_conflict')
    args=[(r['receipt'],r['token'],page,r['status'],r['units'],r['at'],r['at']+clock_skew) for r in rows]
    return _finish_page(db,'backend_pages','backend_facts',page,device,digest,clock_skew,stored_at,
        'INSERT INTO backend_facts(receipt,token,page,status,units,at,at_norm) VALUES(?,?,?,?,?,?,?)',args)
