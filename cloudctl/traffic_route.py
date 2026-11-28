"""Cross-region prefix failover: per-segment decisions and resumable switch plans.

Probe originals decide each client segment's real destination region; a
switch plan carries a route generation, the announcements to add and the old
announcements to withdraw. Both edges must return apply receipts matching the
plan generation and their current certificate generation before anything is
activated, and an old path is withdrawn only after its replacement is
confirmed and still has measured, in-contract, sufficiently provisioned
evidence. Coverage always follows longest-prefix match, so a stale
more-specific route can never secretly override a new aggregate.
"""
import json
from ipaddress import ip_network
from .route_probe import ensure_rows,evaluate

def ensure_tables(db):
    ensure_rows(db)
    db.execute('CREATE TABLE IF NOT EXISTS traffic_edges (edge TEXT PRIMARY KEY,region TEXT NOT NULL,cert_generation INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS traffic_announcements (prefix TEXT,region TEXT,observed_ms INTEGER,generation INTEGER,plan_id TEXT,status TEXT,activated_at INTEGER,withdrawn_at INTEGER,PRIMARY KEY(prefix,region,generation))')
    db.execute('CREATE TABLE IF NOT EXISTS traffic_plans (id TEXT PRIMARY KEY,prefix TEXT NOT NULL,mode TEXT NOT NULL,generation INTEGER NOT NULL,target TEXT,created_at INTEGER,status TEXT NOT NULL,request TEXT NOT NULL,snapshot TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS traffic_plan_routes (plan_id TEXT NOT NULL,prefix TEXT NOT NULL,region TEXT NOT NULL,action TEXT NOT NULL,edge TEXT,observed_ms INTEGER,PRIMARY KEY(plan_id,prefix,region,action))')
    db.execute('CREATE TABLE IF NOT EXISTS traffic_apply_receipts (plan_id TEXT NOT NULL,generation INTEGER NOT NULL,edge TEXT NOT NULL,prefix TEXT NOT NULL,action TEXT NOT NULL,edge_generation INTEGER NOT NULL,at INTEGER,PRIMARY KEY(plan_id,edge,prefix,action))')
    db.execute('CREATE TABLE IF NOT EXISTS traffic_events (seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,subject TEXT,prefix TEXT,decision TEXT,evidence TEXT)')

def _event(db,kind,subject,prefix,decision,evidence):
    db.execute('INSERT INTO traffic_events(kind,subject,prefix,decision,evidence) VALUES(?,?,?,?,?)',(kind,subject,prefix,decision,json.dumps(evidence,sort_keys=True)))

def _fail(db,plan_id,prefix,decision,evidence):
    _event(db,'plan',plan_id,prefix,decision,evidence)
    return {'decision':decision,'plan':plan_id,'evidence':evidence}

def _net(value):
    if not isinstance(value,str):return None
    try:return ip_network(value,strict=False)
    except ValueError:return None

def _rows(db,q,a=()):
    cur=db.execute(q,a);cols=[c[0] for c in cur.description]
    return [dict(zip(cols,r)) for r in cur.fetchall()]

def _row(db,q,a=()):
    r=_rows(db,q,a);return r[0] if r else None

def evaluate_segments(db,prefix,contract_ms=None):
    """Actual per-segment destination judgment, recomputed from originals."""
    out={}
    for seg,data in evaluate(db,prefix)['segments'].items():
        cand=[(rv['rtt_ms'],region) for region,rv in data['regions'].items() if rv['reachable'] and rv['rtt_ms'] is not None and (contract_ms is None or rv['rtt_ms']<=contract_ms)]
        out[seg]={'choice':min(cand)[1] if cand else None,'regions':data['regions']}
    return out

def _active(db):
    return _rows(db,"SELECT * FROM traffic_announcements WHERE status='active'")

def _effective(segment,announcements):
    seg=_net(segment);best=None
    if seg is None:return None
    for a in announcements:
        net=_net(a['prefix'])
        if net is None or not seg.subnet_of(net):continue
        key=(net.prefixlen,a['generation'])
        if best is None or key>best[0]:best=(key,a)
    return best[1] if best else None

def coverage(db,segment):
    """Effective route for a client segment by longest-prefix match."""
    ensure_tables(db)
    a=_effective(segment,_active(db))
    if not a:return {'decision':'blackhole','segment':segment}
    return {'decision':'routed','segment':segment,'prefix':a['prefix'],'region':a['region'],'generation':a['generation']}

def announce(db,prefix):
    """Provisional announcement; refuses to flatten disagreeing segments."""
    ensure_tables(db)
    ev=evaluate_segments(db,prefix)
    if not ev:return {'decision':'no_route','prefix':prefix}
    choices={seg:v['choice'] for seg,v in ev.items()}
    if any(c is None for c in choices.values()) or len(set(choices.values()))!=1:
        return {'decision':'segmented','prefix':prefix,'segments':choices}
    region=set(choices.values()).pop()
    gen=(_row(db,'SELECT MAX(generation) g FROM traffic_announcements WHERE prefix=?',(prefix,))['g'] or 0)+1
    worst=max((v['regions'][region]['rtt_ms'] for v in ev.values() if region in v['regions'] and v['regions'][region]['reachable'] and v['regions'][region]['rtt_ms'] is not None),default=None)
    with db:
        db.execute('INSERT INTO traffic_announcements VALUES (?,?,?,?,?,?,?,?)',(prefix,region,worst,gen,None,'active',None,None))
        _event(db,'announce',prefix,prefix,'announced',{'region':region,'generation':gen})
    return {'decision':'announced','prefix':prefix,'region':region}

def rotate_edge(db,edge,cert_generation):
    ensure_tables(db)
    row=_row(db,'SELECT * FROM traffic_edges WHERE edge=?',(edge,))
    if not row:return {'decision':'missing_edge','edge':edge}
    if cert_generation<=row['cert_generation']:
        _event(db,'edge',edge,'','stale_edge_generation',{'current':row['cert_generation']})
        return {'decision':'stale_edge_generation','edge':edge,'current':row['cert_generation']}
    with db:
        db.execute('UPDATE traffic_edges SET cert_generation=? WHERE edge=?',(cert_generation,edge))
        _event(db,'edge',edge,'','rotated',{'cert_generation':cert_generation})
    return {'decision':'rotated','edge':edge,'cert_generation':cert_generation}

def plan_switch(db,req):
    """Validate and record a switch plan; blocked plans leave only an event."""
    ensure_tables(db)
    plan_id=req.get('id');prefix=req.get('prefix');mode=req.get('mode');at=req.get('at',0)
    contract=req.get('contract_ms',40)
    old=_row(db,'SELECT * FROM traffic_plans WHERE id=?',(plan_id,))
    canon=json.dumps(req,sort_keys=True)
    if old:
        decision='replayed' if old['request']==canon else 'plan_conflict'
        _event(db,'plan',plan_id,old['prefix'],decision,{'status':old['status']})
        return {'decision':decision,'plan':plan_id,'status':old['status']}
    pfx=_net(prefix)
    if pfx is None or mode not in ('consolidate','surgical') or not isinstance(req.get('generation'),int):
        return _fail(db,plan_id,prefix,'invalid_plan',{})
    generation=req['generation']
    latest=_row(db,'SELECT MAX(g) g FROM (SELECT generation g FROM traffic_plans WHERE prefix=? UNION ALL SELECT generation g FROM traffic_announcements WHERE prefix=?)',(prefix,prefix))['g'] or 0
    if generation!=latest+1:
        return _fail(db,plan_id,prefix,'generation_confusion',{'expected':latest+1,'got':generation})
    busy=_row(db,"SELECT id FROM traffic_plans WHERE prefix=? AND status IN ('planned','applying','committed')",(prefix,))
    if busy:return _fail(db,plan_id,prefix,'plan_in_progress',{'blocking':busy['id']})
    segments=req.get('segments')
    if not isinstance(segments,list) or not segments:
        return _fail(db,plan_id,prefix,'invalid_plan',{'why':'segments'})
    seen=[]
    for s in segments:
        net=_net(s.get('segment')) if isinstance(s,dict) else None
        bw=s.get('bandwidth') if isinstance(s,dict) else None
        if net is None or not net.subnet_of(pfx) or not isinstance(bw,int) or bw<=0:
            return _fail(db,plan_id,prefix,'invalid_plan',{'why':'segment','segment':s})
        if any(net.overlaps(o) for o in seen):
            return _fail(db,plan_id,prefix,'invalid_plan',{'why':'overlap','segment':s['segment']})
        seen.append(net)
    edges=req.get('edges')
    if not isinstance(edges,list) or not edges:
        return _fail(db,plan_id,prefix,'invalid_plan',{'why':'edges'})
    for e in edges:
        if not isinstance(e,dict) or not isinstance(e.get('id'),str) or not isinstance(e.get('region'),str) or not isinstance(e.get('cert_generation'),int):
            return _fail(db,plan_id,prefix,'invalid_plan',{'why':'edge'})
    with db:
        for e in edges:
            cur=_row(db,'SELECT * FROM traffic_edges WHERE edge=?',(e['id'],))
            if cur:
                if e['cert_generation']>cur['cert_generation']:
                    db.execute('UPDATE traffic_edges SET cert_generation=? WHERE edge=?',(e['cert_generation'],e['id']))
            else:
                db.execute('INSERT INTO traffic_edges VALUES (?,?,?)',(e['id'],e['region'],e['cert_generation']))
    edge_by_region={}
    for e in _rows(db,'SELECT * FROM traffic_edges'):edge_by_region.setdefault(e['region'],e['edge'])
    egress=req.get('egress')
    if not isinstance(egress,dict) or not egress:
        return _fail(db,plan_id,prefix,'invalid_plan',{'why':'egress'})
    for region,cap in egress.items():
        if not isinstance(cap,dict) or not isinstance(cap.get('used'),int) or not isinstance(cap.get('limit'),int) or cap['used']<0 or cap['limit']<cap['used']:
            return _fail(db,plan_id,prefix,'invalid_capacity',{'region':region})
    ev=evaluate_segments(db,prefix,contract)
    active=_active(db)
    current={s['segment']:_effective(s['segment'],active) for s in segments}
    intended={};overrides={}
    if mode=='consolidate':
        target=req.get('target')
        if not isinstance(target,str) or not target:
            return _fail(db,plan_id,prefix,'invalid_plan',{'why':'target'})
        for s in segments:intended[s['segment']]=target
    else:
        ov=req.get('overrides')
        if not isinstance(ov,list) or not ov:
            return _fail(db,plan_id,prefix,'invalid_plan',{'why':'overrides'})
        names={s['segment'] for s in segments}
        for o in ov:
            onet=_net(o.get('segment')) if isinstance(o,dict) else None
            if onet is None or o['segment'] not in names or not isinstance(o.get('region'),str):
                return _fail(db,plan_id,prefix,'invalid_plan',{'why':'override'})
            if onet.prefixlen<=pfx.prefixlen:
                return _fail(db,plan_id,prefix,'invalid_override',{'segment':o['segment']})
            overrides[o['segment']]=o['region']
        for s in segments:
            seg=s['segment']
            if seg in overrides:intended[seg]=overrides[seg]
            elif current[seg]:intended[seg]=current[seg]['region']
            else:return _fail(db,plan_id,prefix,'no_measured_path',{'segment':seg,'why':'uncovered_segment_needs_override'})
    for s in segments:
        seg=s['segment'];region=intended[seg]
        rv=ev.get(seg,{}).get('regions',{}).get(region)
        if not rv or not rv['reachable'] or rv['rtt_ms'] is None or rv['rtt_ms']>contract:
            return _fail(db,plan_id,prefix,'no_measured_path',{'segment':seg,'region':region})
    new_routes=[]
    if mode=='consolidate':
        new_routes.append({'prefix':prefix,'region':req['target'],'segs':[s['segment'] for s in segments]})
    else:
        for seg,region in overrides.items():new_routes.append({'prefix':seg,'region':region,'segs':[seg]})
    for r in new_routes:
        if any(a['prefix']==r['prefix'] and a['region']==r['region'] for a in active):
            return _fail(db,plan_id,prefix,'duplicate_announcement',{'prefix':r['prefix'],'region':r['region']})
        if r['region'] not in edge_by_region:
            return _fail(db,plan_id,prefix,'missing_edge',{'region':r['region']})
    neighbors=req.get('neighbors') or []
    for region in {r['region'] for r in new_routes}:
        edge_id=edge_by_region.get(region);ok=False
        for n in neighbors:
            if not isinstance(n,dict) or n.get('region')!=region:continue
            via=n.get('via')
            if not isinstance(via,list) or len(set(via))!=len(via) or n.get('id') in via or (edge_id and edge_id in via):
                return _fail(db,plan_id,prefix,'neighbor_loop',{'region':region,'neighbor':n.get('id')})
            if n.get('forwarding')==1:ok=True
        if not ok:
            return _fail(db,plan_id,prefix,'neighbor_not_forwarding',{'region':region})
    needed_regions={intended[s['segment']] for s in segments}|{current[s['segment']]['region'] for s in segments if current[s['segment']]}
    for region in needed_regions:
        if region not in egress:
            return _fail(db,plan_id,prefix,'missing_egress',{'region':region})
    inbound={r:0 for r in egress};outbound={r:0 for r in egress}
    for s in segments:
        seg=s['segment'];cur=current[seg];cur_region=cur['region'] if cur else None
        new_region=intended[seg]
        if cur_region!=new_region:
            inbound[new_region]+=s['bandwidth']
            if cur_region in outbound:outbound[cur_region]+=s['bandwidth']
    for region,cap in egress.items():
        final=cap['used']+inbound.get(region,0)-outbound.get(region,0)
        if final>cap['limit']:
            return _fail(db,plan_id,prefix,'insufficient_capacity',{'region':region,'final':final,'limit':cap['limit']})
    keep=set()
    if mode=='surgical':
        for s in segments:
            seg=s['segment']
            if seg not in overrides and current[seg]:
                a=current[seg];keep.add((a['prefix'],a['region'],a['generation']))
    withdrawals=[]
    for a in active:
        anet=_net(a['prefix'])
        if anet is None or not anet.overlaps(pfx):continue
        if (a['prefix'],a['region'],a['generation']) in keep:continue
        withdrawals.append(a)
    for w in withdrawals:
        if w['region'] not in edge_by_region:
            return _fail(db,plan_id,prefix,'missing_edge',{'region':w['region']})
    post=[a for a in active if (a['prefix'],a['region'],a['generation']) in keep]
    post+=[{'prefix':r['prefix'],'region':r['region'],'generation':generation} for r in new_routes]
    for s in segments:
        seg=s['segment'];eff=_effective(seg,post)
        if not eff or eff['region']!=intended[seg]:
            return _fail(db,plan_id,prefix,'shadowed_route',{'segment':seg})
    def observed(r):
        rtts=[]
        for s in r['segs']:
            rv=ev.get(s,{}).get('regions',{}).get(r['region'])
            if rv and rv['rtt_ms'] is not None:rtts.append(rv['rtt_ms'])
        return max(rtts) if rtts else None
    snapshot={'segments':{s['segment']:{'bandwidth':s['bandwidth'],'intended':intended[s['segment']],'evidence':ev.get(s['segment'])} for s in segments},
              'current':{s['segment']:({'prefix':current[s['segment']]['prefix'],'region':current[s['segment']]['region']} if current[s['segment']] else None) for s in segments},
              'egress':egress,'contract_ms':contract}
    with db:
        db.execute('INSERT INTO traffic_plans VALUES (?,?,?,?,?,?,?,?,?)',(plan_id,prefix,mode,generation,req.get('target'),at,'planned',canon,json.dumps(snapshot,sort_keys=True)))
        for r in new_routes:
            db.execute('INSERT INTO traffic_plan_routes VALUES (?,?,?,?,?,?)',(plan_id,r['prefix'],r['region'],'announce',edge_by_region[r['region']],observed(r)))
        for w in withdrawals:
            db.execute('INSERT INTO traffic_plan_routes VALUES (?,?,?,?,?,?)',(plan_id,w['prefix'],w['region'],'withdraw',edge_by_region[w['region']],None))
        _event(db,'plan',plan_id,prefix,'planned',{'generation':generation,'mode':mode,'announce':[(r['prefix'],r['region']) for r in new_routes],'withdraw':[(w['prefix'],w['region']) for w in withdrawals]})
    return {'decision':'planned','plan':plan_id,'generation':generation,'mode':mode,
            'announce':[{'prefix':r['prefix'],'region':r['region']} for r in new_routes],
            'withdraw':[{'prefix':w['prefix'],'region':w['region']} for w in withdrawals]}

def _valid_receipt(db,plan,route):
    edge=_row(db,'SELECT * FROM traffic_edges WHERE edge=?',(route['edge'],))
    if not edge:return None
    rec=_row(db,'SELECT * FROM traffic_apply_receipts WHERE plan_id=? AND edge=? AND prefix=? AND action=?',(plan['id'],route['edge'],route['prefix'],route['action']))
    if not rec:return None
    if rec['generation']!=plan['generation'] or rec['edge_generation']!=edge['cert_generation']:return None
    return rec

def apply_receipt(db,plan_id,edge,prefix,action,generation,edge_generation,at):
    ensure_tables(db)
    plan=_row(db,'SELECT * FROM traffic_plans WHERE id=?',(plan_id,))
    if not plan:return {'decision':'missing_plan','plan':plan_id}
    route=_row(db,'SELECT * FROM traffic_plan_routes WHERE plan_id=? AND prefix=? AND action=? AND edge=?',(plan_id,prefix,action,edge))
    if not route:
        _event(db,'receipt',plan_id,plan['prefix'],'unexpected_receipt',{'edge':edge,'prefix':prefix,'action':action})
        return {'decision':'unexpected_receipt','plan':plan_id}
    if generation!=plan['generation']:
        _event(db,'receipt',plan_id,plan['prefix'],'stale_receipt',{'current':plan['generation'],'got':generation})
        return {'decision':'stale_receipt','plan':plan_id,'current':plan['generation']}
    edge_row=_row(db,'SELECT * FROM traffic_edges WHERE edge=?',(edge,))
    if not edge_row:return {'decision':'unknown_edge','plan':plan_id}
    if edge_generation!=edge_row['cert_generation']:
        _event(db,'receipt',plan_id,plan['prefix'],'stale_edge_certificate',{'edge':edge,'current':edge_row['cert_generation'],'got':edge_generation})
        return {'decision':'stale_edge_certificate','plan':plan_id,'current':edge_row['cert_generation']}
    old=_row(db,'SELECT * FROM traffic_apply_receipts WHERE plan_id=? AND edge=? AND prefix=? AND action=?',(plan_id,edge,prefix,action))
    if old and old['generation']==plan['generation'] and old['edge_generation']==edge_row['cert_generation']:
        return {'decision':'replayed','plan':plan_id,'edge':edge,'prefix':prefix}
    with db:
        db.execute('INSERT OR REPLACE INTO traffic_apply_receipts VALUES (?,?,?,?,?,?,?)',(plan_id,generation,edge,prefix,action,edge_generation,at))
        _event(db,'receipt',plan_id,plan['prefix'],'recorded',{'edge':edge,'prefix':prefix,'action':action,'generation':generation,'edge_generation':edge_generation})
    return {'decision':'recorded','plan':plan_id,'edge':edge,'prefix':prefix,'action':action}

def commit(db,plan_id,at):
    """Advance a plan as far as persisted receipts allow; safe to re-run after a crash."""
    ensure_tables(db)
    plan=_row(db,'SELECT * FROM traffic_plans WHERE id=?',(plan_id,))
    if not plan:return {'decision':'missing_plan','plan':plan_id}
    if plan['status']=='aborted':return {'decision':'aborted','plan':plan_id}
    routes=_rows(db,'SELECT * FROM traffic_plan_routes WHERE plan_id=?',(plan_id,))
    if plan['status']=='planned':
        with db:
            db.execute("UPDATE traffic_plans SET status='applying' WHERE id=?",(plan_id,))
            for r in routes:
                if r['action']=='announce':
                    _event(db,'order',r['edge'],plan['prefix'],'issued',{'plan':plan_id,'prefix':r['prefix'],'region':r['region'],'action':'announce','generation':plan['generation']})
        plan['status']='applying'
    if plan['status']=='applying':
        missing=[{'edge':r['edge'],'prefix':r['prefix'],'action':'announce'} for r in routes if r['action']=='announce' and not _valid_receipt(db,plan,r)]
        if missing:
            _event(db,'commit',plan_id,plan['prefix'],'awaiting_receipts',{'missing':missing})
            return {'decision':'awaiting_receipts','plan':plan_id,'missing':missing}
        with db:
            for r in routes:
                if r['action']!='announce':continue
                db.execute('INSERT INTO traffic_announcements VALUES (?,?,?,?,?,?,?,?)',(r['prefix'],r['region'],r['observed_ms'],plan['generation'],plan_id,'active',at,None))
                _event(db,'announcement',r['prefix'],plan['prefix'],'activated',{'region':r['region'],'generation':plan['generation'],'plan':plan_id})
            for r in routes:
                if r['action']=='withdraw':
                    _event(db,'order',r['edge'],plan['prefix'],'issued',{'plan':plan_id,'prefix':r['prefix'],'region':r['region'],'action':'withdraw','generation':plan['generation']})
            db.execute("UPDATE traffic_plans SET status='committed' WHERE id=?",(plan_id,))
        plan['status']='committed'
    if plan['status']=='committed':
        missing=[{'edge':r['edge'],'prefix':r['prefix'],'action':'withdraw'} for r in routes if r['action']=='withdraw' and not _valid_receipt(db,plan,r)]
        if missing:
            _event(db,'commit',plan_id,plan['prefix'],'awaiting_withdrawal_receipts',{'missing':missing})
            return {'decision':'awaiting_withdrawal_receipts','plan':plan_id,'missing':missing}
        snapshot=json.loads(plan['snapshot']);contract=snapshot.get('contract_ms',40)
        withdraws=[r for r in routes if r['action']=='withdraw']
        remaining=[a for a in _active(db) if not any(a['prefix']==w['prefix'] and a['region']==w['region'] for w in withdraws)]
        ev=evaluate_segments(db,plan['prefix'],contract)
        blocked=[]
        for seg in snapshot['segments']:
            eff=_effective(seg,remaining)
            rv=ev.get(seg,{}).get('regions',{}).get(eff['region']) if eff else None
            if not eff or not rv or not rv['reachable'] or rv['rtt_ms'] is None or rv['rtt_ms']>contract:
                blocked.append(seg)
        if blocked:
            _event(db,'commit',plan_id,plan['prefix'],'withdrawal_blocked',{'segments':blocked})
            return {'decision':'withdrawal_blocked','plan':plan_id,'segments':blocked}
        with db:
            for w in withdraws:
                db.execute("UPDATE traffic_announcements SET status='withdrawn',withdrawn_at=? WHERE prefix=? AND region=? AND status='active'",(at,w['prefix'],w['region']))
                _event(db,'announcement',w['prefix'],plan['prefix'],'withdrawn',{'region':w['region'],'plan':plan_id})
            db.execute("UPDATE traffic_plans SET status='completed' WHERE id=?",(plan_id,))
            _event(db,'commit',plan_id,plan['prefix'],'completed',{'generation':plan['generation']})
        return {'decision':'completed','plan':plan_id,'generation':plan['generation']}
    return {'decision':plan['status'],'plan':plan_id}

def abort(db,plan_id,at,reason='operator'):
    ensure_tables(db)
    plan=_row(db,'SELECT * FROM traffic_plans WHERE id=?',(plan_id,))
    if not plan:return {'decision':'missing_plan','plan':plan_id}
    if plan['status'] not in ('planned','applying'):
        _event(db,'abort',plan_id,plan['prefix'],'cannot_abort',{'status':plan['status']})
        return {'decision':'cannot_abort','plan':plan_id,'status':plan['status']}
    with db:
        db.execute("UPDATE traffic_plans SET status='aborted' WHERE id=?",(plan_id,))
        _event(db,'abort',plan_id,plan['prefix'],'aborted',{'reason':reason,'at':at})
    return {'decision':'aborted','plan':plan_id}

def plan_status(db,plan_id):
    ensure_tables(db)
    plan=_row(db,'SELECT * FROM traffic_plans WHERE id=?',(plan_id,))
    if not plan:return {'decision':'missing_plan','plan':plan_id}
    routes=_rows(db,'SELECT * FROM traffic_plan_routes WHERE plan_id=?',(plan_id,))
    snapshot=json.loads(plan['snapshot'])
    active=_active(db)
    segments={}
    for seg,info in snapshot['segments'].items():
        eff=_effective(seg,active)
        segments[seg]={'intended':info['intended'],
                       'effective':({'prefix':eff['prefix'],'region':eff['region'],'generation':eff['generation']} if eff else None),
                       'switched':bool(eff) and eff['region']==info['intended']}
    pending=[{'edge':r['edge'],'prefix':r['prefix'],'action':r['action']} for r in routes if not _valid_receipt(db,plan,r)]
    return {'decision':plan['status'],'plan':plan_id,'generation':plan['generation'],'segments':segments,'pending_receipts':pending}

def history(db,prefix):
    """Switchover record: announcements, plans, receipts and events for a prefix."""
    ensure_tables(db)
    net=_net(prefix)
    announcements=[a for a in _rows(db,'SELECT * FROM traffic_announcements ORDER BY generation') if (lambda n:n and net and n.subnet_of(net))(_net(a['prefix']))]
    plans=[{k:p[k] for k in ('id','mode','generation','status','created_at')} for p in _rows(db,'SELECT * FROM traffic_plans WHERE prefix=? ORDER BY generation',(prefix,))]
    receipts=_rows(db,'SELECT * FROM traffic_apply_receipts WHERE plan_id IN (SELECT id FROM traffic_plans WHERE prefix=?)',(prefix,))
    events=_rows(db,'SELECT * FROM traffic_events WHERE prefix=? ORDER BY seq',(prefix,))
    return {'announcements':announcements,'plans':plans,'receipts':receipts,'events':events}
