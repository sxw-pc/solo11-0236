"""Offline regional probe intake for service routing.

Every captured page is an immutable original: observation point, client
segment, upstream neighbor, service prefix, actual send minute, reply/loss
evidence and the probe machine's page-wide clock calibration. Retransmissions
from one observation point are one proof, not many. Late or recalibrated
pages only produce new evaluations; they never rewrite captured pages and
never erase announcements already published.
"""
import hashlib,json
from ipaddress import ip_network

LEGACY_KEYS={'source','prefix','region','at','rtt_ms','reachable'}
EXTENDED_KEYS={'source','segment','neighbor','prefix','region','sent_at','rtt_ms','reachable','sent','received'}

def ensure_rows(db):
    db.execute('CREATE TABLE IF NOT EXISTS route_probe_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL,clock_offset INTEGER NOT NULL DEFAULT 0)')
    db.execute('CREATE TABLE IF NOT EXISTS route_probe_rows (page_id TEXT,line_no INTEGER,source TEXT,segment TEXT,neighbor TEXT,prefix TEXT,region TEXT,at INTEGER,sent_at INTEGER,rtt_ms INTEGER,reachable INTEGER,sent INTEGER,received INTEGER,PRIMARY KEY(page_id,line_no))')

def _net(value):
    if not isinstance(value,str):return None
    try:return ip_network(value,strict=False)
    except ValueError:return None

def _normalize(rows,clock_offset):
    if not isinstance(rows,list) or not isinstance(clock_offset,int):raise ValueError('invalid_probe_page')
    norm=[]
    for r in rows:
        if not isinstance(r,dict):raise ValueError('invalid_probe_page')
        keys=set(r)
        if keys==LEGACY_KEYS:
            if not isinstance(r['at'],int) or not isinstance(r['rtt_ms'],int) or r['rtt_ms']<0 or r['reachable'] not in (0,1):raise ValueError('invalid_probe_page')
            norm.append({'source':r['source'],'segment':r['prefix'],'neighbor':'','prefix':r['prefix'],'region':r['region'],'sent_at':r['at'],'rtt_ms':r['rtt_ms'],'reachable':r['reachable'],'sent':1,'received':r['reachable']})
        elif keys==EXTENDED_KEYS:
            if not(isinstance(r['sent_at'],int) and isinstance(r['rtt_ms'],int) and r['rtt_ms']>=0
                   and isinstance(r['sent'],int) and isinstance(r['received'],int)
                   and r['sent']>=1 and 0<=r['received']<=r['sent']
                   and r['reachable']==(1 if r['received'] else 0)
                   and all(isinstance(r[k],str) and r[k] for k in ('source','segment','neighbor','prefix','region'))):raise ValueError('invalid_probe_page')
            seg,pfx=_net(r['segment']),_net(r['prefix'])
            if seg is None or pfx is None or not seg.subnet_of(pfx):raise ValueError('invalid_probe_page')
            norm.append({'source':r['source'],'segment':r['segment'],'neighbor':r['neighbor'],'prefix':r['prefix'],'region':r['region'],'sent_at':r['sent_at'],'rtt_ms':r['rtt_ms'],'reachable':r['reachable'],'sent':r['sent'],'received':r['received']})
        else:raise ValueError('invalid_probe_page')
    return norm

def import_page(db,page_id,rows,received_at,clock_offset=0):
    ensure_rows(db)
    norm=_normalize(rows,clock_offset)
    digest=hashlib.sha256(json.dumps({'rows':rows,'clock_offset':clock_offset},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    old=db.execute('SELECT digest FROM route_probe_pages WHERE id=?',(page_id,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('probe_page_conflict')
        return {'status':'replayed','rows':len(rows)}
    with db:
        db.execute('INSERT INTO route_probe_pages VALUES (?,?,?,?)',(page_id,digest,received_at,clock_offset))
        for i,r in enumerate(norm,1):
            db.execute('INSERT INTO route_probe_rows VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',(page_id,i,r['source'],r['segment'],r['neighbor'],r['prefix'],r['region'],r['sent_at']+clock_offset,r['sent_at'],r['rtt_ms'],r['reachable'],r['sent'],r['received']))
    return {'status':'captured','rows':len(rows)}

def _path_state(samples):
    """Current reachability of one (segment,region,source) path.

    A single latest failure marks the path failing. After a streak of two or
    more consecutive failures, one lower-latency success does not wash the
    streak out: two consecutive successes are required to recover.
    """
    state=None;fail_run=0;ok_run=0;hardened=False;last_rtt=None
    for s in samples:
        if s['reachable']:
            ok_run+=1;fail_run=0;last_rtt=s['rtt_ms']
            if not hardened or ok_run>=2:
                state=True
                if ok_run>=2:hardened=False
        else:
            fail_run+=1;ok_run=0;state=False
            if fail_run>=2:hardened=True
    return {'reachable':state,'rtt_ms':last_rtt,'fail_run':fail_run,'samples':len(samples)}

def evaluate(db,prefix=None):
    """Recompute per-segment regional evidence from all captured originals."""
    ensure_rows(db)
    want=_net(prefix) if prefix else None
    q=('SELECT r.page_id,r.line_no,r.source,r.segment,r.neighbor,r.prefix,r.region,r.at,r.rtt_ms,r.reachable,r.sent,r.received,p.received_at '
       'FROM route_probe_rows r JOIN route_probe_pages p ON p.id=r.page_id '
       'ORDER BY r.at,p.received_at,r.page_id,r.line_no')
    groups={}
    for page_id,line_no,source,segment,neighbor,pfx,region,at,rtt,reachable,sent,received,recv_at in db.execute(q):
        if want is not None:
            seg_net=_net(segment)
            if seg_net is None or not seg_net.subnet_of(want):continue
        groups.setdefault((segment,region,source),[]).append({'at':at,'reachable':reachable,'rtt_ms':rtt,'sent':sent,'received':received})
    segments={}
    for (segment,region,source),samples in groups.items():
        state=_path_state(samples)
        view=segments.setdefault(segment,{'regions':{}})['regions'].setdefault(region,{'sources':{}})
        view['sources'][source]=state
    for segment,seg in segments.items():
        for region,view in seg['regions'].items():
            ok=[s for s in view['sources'].values() if s['reachable']]
            rtts=[s['rtt_ms'] for s in ok if s['rtt_ms'] is not None]
            view['reachable']=bool(ok)
            view['rtt_ms']=min(rtts) if rtts else None
            view['proofs']=len(ok)
    return {'prefix':prefix,'segments':segments}
