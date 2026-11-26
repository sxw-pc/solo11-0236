"""Leader leases derived from a proven commit prefix plus physical fencing.

A lease is only valid when all three facts hold together:

1. the candidate holds the *whole provable commit prefix* (every client
   confirmed entry), so a confirmed endpoint change cannot be lost;
2. no confirmed log position is contested by a higher term (the confirmed
   digest wins; the competing entry is retained as fork evidence but never
   promoted);
3. every write entry point that can still reach any node has been physically
   fenced before the lease is issued.  A lease row written by the control
   plane is not a fence.

Reads during the outage are served from the same proven prefix and are exposed
through :func:`read` with a stable view digest.  Once writes are opened, reads
and writes are bound to the same issued term.
"""
import hashlib,json
from .store import commit
from . import wal_capture as wal
from . import gateway_fence as gw

def canon(obj):
    return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False)

def digest_of(obj):
    return hashlib.sha256(canon(obj).encode('utf-8')).hexdigest()

def ensure(db):
    wal.ensure(db)
    gw.ensure(db)
    db.execute('CREATE TABLE IF NOT EXISTS leader_leases (seq INTEGER PRIMARY KEY AUTOINCREMENT,'
               'node TEXT,term INTEGER,idx INTEGER,digest TEXT,status TEXT,at INTEGER,evidence TEXT)')
    _migrate_leases(db)
    db.execute('CREATE TABLE IF NOT EXISTS cluster_state (id INTEGER PRIMARY KEY,mode TEXT,node TEXT,'
               'term INTEGER,idx INTEGER,digest TEXT,endpoint TEXT,updated_at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS applied_changes (request_id TEXT PRIMARY KEY,node TEXT,'
               'term INTEGER,idx INTEGER,digest TEXT,content_json TEXT,at INTEGER)')

def _migrate_leases(db):
    """Rebuild a pre-existing 3-column ``leader_leases`` table in place.

    The original module created ``leader_leases(node,term,idx)`` with no status
    or evidence.  Those legacy rows are imported as ``observed`` leases: they
    record what was seen before the failover rules existed and can never be
    mistaken for an issued lease or a fence.
    """
    cols=[row[1] for row in db.execute('PRAGMA table_info(leader_leases)')]
    if not cols or 'seq' in cols:return
    legacy=[dict(zip(cols,row)) for row in db.execute('SELECT * FROM leader_leases')]
    db.execute('ALTER TABLE leader_leases RENAME TO leader_leases_legacy')
    db.execute('CREATE TABLE leader_leases (seq INTEGER PRIMARY KEY AUTOINCREMENT,'
               'node TEXT,term INTEGER,idx INTEGER,digest TEXT,status TEXT,at INTEGER,evidence TEXT)')
    for row in legacy:
        db.execute('INSERT INTO leader_leases(node,term,idx,digest,status,at,evidence) '
                   'VALUES (?,?,?,?,?,?,?)',
                   (row.get('node'),row.get('term'),row.get('idx'),row.get('digest'),'observed',
                    int(row.get('at') or 0),canon({'migrated':True})))
    db.execute('DROP TABLE leader_leases_legacy')

def _state(db):
    row=db.execute('SELECT * FROM cluster_state WHERE id=1').fetchone()
    if not row:return None
    return {'mode':row[1],'node':row[2],'term':row[3],'idx':row[4],'digest':row[5],
            'endpoint':json.loads(row[6]) if row[6] else {},'updated_at':row[7]}

def _set_state(db,mode,node,term,idx,digest,endpoint,at):
    db.execute('INSERT OR REPLACE INTO cluster_state VALUES (1,?,?,?,?,?,?,?)',
               (mode,node,term,idx,digest,canon(endpoint),int(at or 0)))

def _content_endpoint(content):
    """Best-effort endpoint change carried by a WAL entry's content."""
    if isinstance(content,dict):
        for key in ('endpoint','value','new','target','to'):
            if key in content:return content.get('service','api'),content[key]
        if len(content)==1:
            service,value=next(iter(content.items()))
            if isinstance(value,str):return service,value
    if isinstance(content,str):
        return 'api',content
    return None

def endpoint_directory(prefix=None,db=None):
    """Endpoint directory built only from the proven prefix, ordered by index."""
    if prefix is None:prefix=wal.proven_prefix(db)
    directory={}
    for entry in prefix['entries']:
        parsed=_content_endpoint(entry.get('content'))
        if parsed:directory[parsed[0]]=parsed[1]
    return directory

def _prefix_support(db,prefix):
    """How many distinct sources/nodes attest each prefix digest."""
    support={}
    for e in wal.entries(db):
        if not wal.confirmed(e):continue
        support.setdefault(e['index'],{}).setdefault(e['digest'],set()).add(e['node'])
        if e['source']:support[e['index']][e['digest']].add('%s:%s'%(e['node'],e['source']))
    return support

def _authority_ok(db,prefix,witness,previous):
    if not prefix['entries']:return False,[]
    head=prefix['entries'][-1]
    auth=[x for x in (witness,previous) if x]
    if not auth:return True,[]  # no authority configured: prefix stands on its own
    support=_prefix_support(db,prefix).get(head['index'],{}).get(head['digest'],set())
    tokens={s.lower() for s in support}|{s.split(':')[0].lower() for s in support}
    attested=sorted(a for a in auth if a.lower() in tokens)
    return bool(attested),support

def _node_latest(db,node,request):
    """The candidate's claimed (term,index,digest), preferring the request."""
    if isinstance(request.get('latest'),dict):
        latest=request['latest']
        return {'term':latest.get('term',request.get('term')),
                'index':latest.get('index',latest.get('idx',request.get('index'))),
                'digest':latest.get('digest',request.get('digest'))}
    if request.get('term') is not None or request.get('index') is not None or request.get('digest'):
        return {'term':request.get('term'),'index':request.get('index',request.get('idx')),
                'digest':request.get('digest')}
    own=[e for e in wal.entries(db,node) if wal.confirmed(e)]
    if not own:return None
    top=max(own,key=lambda e:(e['term'],e['index']))
    return {'term':top['term'],'index':top['index'],'digest':top['digest']}

def _record(db,node,term,idx,digest,status,at,evidence):
    db.execute('INSERT INTO leader_leases(node,term,idx,digest,status,at,evidence) VALUES (?,?,?,?,?,?,?)',
               (node,term,idx,digest,status,int(at or 0),canon(evidence)))

def _supersede_candidates(db,node):
    db.execute("UPDATE leader_leases SET status='superseded' WHERE node=? AND status='candidate'",(node,))

def issue(db,node=None,at=0,**request):
    """Assess and, when safe, issue a leader lease.

    ``issue(db, 'a')`` keeps the historical shape.  A request dict is accepted
    too and carries the candidate ticket: ``term``/``index``/``digest`` (or
    ``latest``), ``at`` and an optional ``requested`` intent (``write``).
    """
    if isinstance(node,dict):
        request=dict(node);node=request.get('node',request.get('candidate'))
    else:
        node=request.pop('node',node) if 'node' in request else node
        request=dict(request,node=node)
    if 'at' not in request or request.get('at') is None:request['at']=at
    at=request.get('at',0)
    if not isinstance(node,str) or not node:raise ValueError('missing_node')
    ensure(db)
    own=wal.entries(db,node)
    if not own and not request.get('term'):raise ValueError('missing_node')
    prefix=wal.proven_prefix(db)
    latest=_node_latest(db,node,request) or {'term':0,'index':0,'digest':None}
    evidence={'node':node,'at':at,'claimed':latest}

    if prefix['blocked']:
        _record(db,node,latest['term'],latest['index'],latest['digest'],'rejected',at,
                dict(evidence,reason='confirmed_conflict',conflicts=prefix['conflicts']))
        return {'decision':'rejected','node':node,'reason':'confirmed_conflict',
                'conflicts':prefix['conflicts'],'term':latest['term'],'index':latest['index']}

    # A lease that was explicitly fenced must not be re-issued unchanged.
    fenced=db.execute("SELECT 1 FROM leader_leases WHERE node=? AND term=? AND status='fenced'",
                      (node,latest['term'])).fetchone()
    if fenced and not request.get('force'):
        _record(db,node,latest['term'],latest['index'],latest['digest'],'rejected',at,
                dict(evidence,reason='lease_fenced'))
        return {'decision':'rejected','node':node,'reason':'lease_fenced','term':latest['term']}

    state=_state(db)
    if state and state['mode']=='write' and state['node']==node:
        holds=state['idx'] in prefix['digests'] and prefix['digests'][state['idx']]==state['digest']
        if holds:
            return {'decision':'issued','node':node,'term':state['term'],'index':state['idx'],
                    'digest':state['digest'],'idempotent':True,'basis':'provable_prefix'}

    # A higher term may not overwrite confirmed content at the same position.
    claimed_idx=latest.get('index')
    if claimed_idx is not None and claimed_idx in prefix['digests'] and latest.get('digest'):
        proven=prefix['digests'][claimed_idx]
        if latest['digest']!=proven:
            _record(db,node,latest['term'],claimed_idx,latest['digest'],'rejected',at,
                    dict(evidence,reason='confirmed_content_protected',proven_digest=proven))
            return {'decision':'rejected','node':node,'reason':'confirmed_content_protected',
                    'index':claimed_idx,'claimed':latest['digest'],'proven':proven,
                    'term':latest['term']}

    missing=wal.node_contains(db,node,prefix)
    if missing:
        _record(db,node,latest['term'],latest['index'],latest['digest'],'candidate',at,
                dict(evidence,reason='prefix_incomplete',missing=missing))
        return {'decision':'candidate','node':node,'reason':'prefix_incomplete','missing':missing,
                'term':latest['term'],'index':latest['index'],'prefix_head':prefix['head_index']}

    pending=gw.unfenced(db,at,exclude=node)
    if pending:
        _record(db,node,latest['term'],latest['index'],latest['digest'],'candidate',at,
                dict(evidence,reason='unfenced_writers',pending=pending))
        return {'decision':'candidate','node':node,'reason':'unfenced_writers','pending_writers':pending,
                'term':latest['term'],'index':latest['index'],'prefix_head':prefix['head_index']}

    # A ticket is the candidate's own new term.  Without one there is no new
    # term to issue under, so the observation is only registered as a
    # candidate -- the control plane never invents writable authority.
    ticket_term=request.get('term')
    if ticket_term is None or request.get('ticketed') is False:
        _record(db,node,latest['term'],latest['index'],latest['digest'],'candidate',at,
                dict(evidence,reason='no_new_term_ticket'))
        return {'decision':'candidate','node':node,'reason':'no_new_term_ticket',
                'term':latest['term'],'index':latest['index'],
                'prefix_head':prefix['head_index'],'prefix_digest':prefix['head_digest']}

    new_term=ticket_term
    if state and state['term'] is not None and state['node']!=node and new_term<=state['term']:
        new_term=state['term']+1
    # Any lease that could still be primary at or above this term blocks:
    # an issued lease, or a candidate that was never fenced.  Only fenced
    # candidates and superseded leases are safely behind us.
    blocking=db.execute("SELECT node,term,status FROM leader_leases WHERE status IN ('issued','candidate') "
                        "AND node<>? AND term>=? ORDER BY term",(node,new_term)).fetchall()
    if blocking:
        _record(db,node,new_term,prefix['head_index'],prefix['head_digest'],'candidate',at,
                dict(evidence,reason='term_not_advanced',blocking=[{'node':b[0],'term':b[1]} for b in blocking]))
        return {'decision':'candidate','node':node,'reason':'term_not_advanced',
                'blocking_leases':[{'node':b[0],'term':b[1]} for b in blocking],'term':new_term}

    idx=prefix['head_index'];digest=prefix['head_digest'];endpoint=endpoint_directory(prefix)
    _supersede_candidates(db,node)
    db.execute("UPDATE leader_leases SET status='superseded' WHERE status='issued' AND node<>? AND term<?",
               (node,new_term))
    _record(db,node,new_term,idx,digest,'issued',at,
            dict(evidence,term=new_term,index=idx,digest=digest,basis='provable_prefix',
                 ignored_forks=prefix['ignored_forks'],fenced_writers=[]))
    _set_state(db,'write',node,new_term,idx,digest,endpoint,at)
    return {'decision':'issued','node':node,'term':new_term,'index':idx,'digest':digest,
            'basis':'provable_prefix','endpoint':endpoint,
            'prefix_head':idx,'prefix_digest':digest,
            'ignored_forks':prefix['ignored_forks']}

def fence_lease(db,node=None,term=None,reason='candidate_fenced',request=None):
    """Fence a candidate lease so it cannot become primary."""
    if isinstance(node,dict) and request is None:
        request=node;node=None;term=None
    if isinstance(request,dict):
        node=request.get('node',request.get('candidate'));term=request.get('term')
        reason=request.get('reason',reason)
    ensure(db)
    rows=db.execute("SELECT seq,node,term,digest FROM leader_leases WHERE status='candidate' "
                    "AND (? IS NULL OR node=?) AND (? IS NULL OR term=?) ORDER BY seq",(node,node,term,term)).fetchall()
    for seq,n,t,d in rows:db.execute("UPDATE leader_leases SET status='fenced' WHERE seq=?",(seq,))
    return {'decision':'fenced' if rows else 'no_candidate','node':node,'term':term,
            'fenced':[{'node':n,'term':t,'digest':d} for _,n,t,d in rows],'reason':reason}

def status(db,node=None):
    ensure(db)
    rows=db.execute('SELECT node,term,idx,digest,status,at FROM leader_leases ORDER BY at,seq')
    leases=[{'node':r[0],'term':r[1],'index':r[2],'digest':r[3],'status':r[4],'at':r[5]} for r in rows
            if node is None or r[0]==node]
    return {'state':_state(db),'leases':leases}

def recover(db,request=None,**kw):
    """Failover decision: promote a candidate behind a proven prefix and fence.

    The decision is deliberately all-or-nothing: prefix, candidate replay,
    witness authority and physical fencing are re-checked in one call.  While
    any check fails the cluster stays ``read_only`` on the proven prefix, so
    the confirmed endpoint (``east``) keeps being served and no second primary
    becomes reachable.
    """
    if isinstance(request,dict):
        r=dict(request)
    else:
        r=dict(kw,node=request)
    ensure(db)
    at=int(r.get('at',0) or 0)
    policy=r.get('policy','replay')
    candidate=r.get('candidate',r.get('node',r.get('preferred')))
    witness=r.get('witness')
    previous=r.get('previous')
    prefix=wal.proven_prefix(db)
    directory=endpoint_directory(prefix)
    base={'policy':policy,'at':at,'prefix_head':prefix['head_index'],
          'prefix_digest':prefix['head_digest'],'endpoint':directory}

    def read_only(decision,reason,**extra):
        _set_state(db,'read_only',None,None,prefix['head_index'],prefix['head_digest'],directory,at)
        out={'decision':decision,'reason':reason,'mode':'read_only','view':{'mode':'read_only',
             'term':None,'prefix_head':prefix['head_index'],'prefix_digest':prefix['head_digest'],
             'endpoint':directory}}
        out.update(base);out.update(extra)
        return out

    if prefix['blocked']:
        return read_only('blocked','confirmed_conflict',conflicts=prefix['conflicts'])
    if not prefix['entries']:
        return read_only('blocked','no_proven_prefix')
    if not candidate:
        return read_only('blocked','no_candidate')

    ok,support=_authority_ok(db,prefix,witness,previous)
    if not ok:
        return read_only('waiting_witness','prefix_head_not_attested',
                         witness=witness,previous=previous,support=sorted(support))

    missing=wal.node_contains(db,candidate,prefix)
    if missing:
        if witness and r.get('replay',True):
            rp=wal.replay(db,candidate,source=witness,at=at)
            if rp['decision']=='prefix_conflict':return read_only('blocked','prefix_conflict')
            missing=wal.node_contains(db,candidate,prefix)
        if missing:
            return read_only('prefix_incomplete','candidate_missing_prefix',missing=missing)

    pending=gw.unfenced(db,at,exclude=candidate)
    if pending:
        return read_only('fenced_out','unfenced_writers',pending_writers=pending)

    previous_primary=previous
    if previous_primary and previous_primary!=candidate:
        still=gw.reachable(db,previous_primary,at)
        if still:return read_only('fenced_out','previous_primary_reachable',pending_writers=still)

    requested_term=r.get('term')
    lease=issue(db,{'node':candidate,'at':at,'term':requested_term,
                    'digest':prefix['head_digest'],'index':prefix['head_index'],
                    'latest':{'term':requested_term,'index':prefix['head_index'],
                              'digest':prefix['head_digest']}})
    if lease['decision']!='issued':
        return read_only('blocked' if lease.get('reason')=='confirmed_content_protected' else 'lease_pending',
                         lease.get('reason','lease_not_issued'),lease=lease)
    _set_state(db,'write',candidate,lease['term'],lease['index'],lease['digest'],
               endpoint_directory(prefix),at)
    if r.get('reopen',True):
        gateway=r.get('gateway',candidate+'-gw')
        gw.link(db,gateway,candidate,writes=True,at=at)
    mode='write'
    return {'decision':'promoted','reason':'fenced_and_proven','mode':mode,'node':candidate,
            'term':lease['term'],'index':lease['index'],'digest':lease['digest'],
            'endpoint':directory,'prefix_head':prefix['head_index'],
            'prefix_digest':prefix['head_digest'],'policy':policy,'at':at,'read_only':False,
            'view':{'mode':'write','term':lease['term'],'prefix_head':lease['index'],
                    'prefix_digest':lease['digest'],'endpoint':directory}}

def _view_digest(view):
    return digest_of({'mode':view['mode'],'term':view['term'],'prefix_head':view['prefix_head'],
                      'prefix_digest':view['prefix_digest'],'endpoint':view['endpoint']})

def read(db,request=None,**kw):
    """Consistent read.  During recovery every reader sees the proven prefix.

    Once writes are open, a reader must present the current term so a retry
    cannot be served from a different primary.
    """
    r=dict(request) if isinstance(request,dict) else dict(kw)
    ensure(db)
    at=int(r.get('at',0) or 0)
    state=_state(db)
    if state and state['mode']=='write':
        term=r.get('term')
        if term is not None and term!=state['term']:
            return {'decision':'term_mismatch','reason':'reader_bound_to_stale_term',
                    'reader_term':term,'primary_term':state['term']}
        prefix=wal.proven_prefix(db)
        if prefix['blocked']:
            return {'decision':'blocked','reason':'confirmed_conflict','conflicts':prefix['conflicts']}
        if prefix['digests'].get(state['idx'])!=state['digest']:
            return {'decision':'prefix_changed','reason':'committed_prefix_diverged'}
        directory=endpoint_directory(prefix)
        view={'mode':'write','term':state['term'],'prefix_head':state['idx'],
              'prefix_digest':state['digest'],'endpoint':directory}
    else:
        prefix=wal.proven_prefix(db)
        if prefix['blocked']:
            return {'decision':'blocked','reason':'confirmed_conflict','conflicts':prefix['conflicts']}
        directory=endpoint_directory(prefix)
        view={'mode':'read_only','term':None,'prefix_head':prefix['head_index'],
              'prefix_digest':prefix['head_digest'],'endpoint':directory}
    vd=_view_digest(view)
    expected=r.get('expected_view')
    if expected is not None and expected!=vd:
        return {'decision':'view_moved','reason':'retry_must_not_reroute',
                'expected':expected,'current':vd,'view':view}
    out={'decision':'read','mode':view['mode'],'term':view['term'],'endpoint':directory,
         'prefix_head':view['prefix_head'],'prefix_digest':view['prefix_digest'],
         'view_digest':vd,'view':view,'at':at}
    if r.get('client') is not None:out['client']=r['client']
    return out

def write(db,request=None,**kw):
    """Apply an endpoint change exactly once, only under the issued term.

    Retries carry the same ``request_id`` and are answered from
    ``applied_changes`` without appending a second WAL entry.
    """
    r=dict(request) if isinstance(request,dict) else dict(kw)
    ensure(db)
    at=int(r.get('at',0) or 0);request_id=r.get('request_id')
    if not request_id:raise ValueError('missing_request_id')
    state=_state(db)
    if not state or state['mode']!='write' or state['term'] is None:
        return {'decision':'rejected','reason':'no_write_lease'}
    if r.get('term') is not None and r['term']!=state['term']:
        return {'decision':'rejected','reason':'term_mismatch','primary_term':state['term']}
    if wal.proven_prefix(db)['blocked']:
        return {'decision':'rejected','reason':'confirmed_conflict','primary_term':state['term']}
    pending=gw.unfenced(db,at,exclude=state['node'])
    if pending:
        return {'decision':'rejected','reason':'split_brain_risk','pending_writers':pending,
                'primary_term':state['term']}
    content=r.get('content',r.get('change'))
    cjson=canon(content)
    existing=db.execute('SELECT node,term,idx,digest,content_json FROM applied_changes WHERE request_id=?',
                        (request_id,)).fetchone()
    if existing:
        if existing[4]!=cjson:
            return {'decision':'conflict','reason':'request_id_reused','request_id':request_id}
        return {'decision':'duplicate','reason':'already_applied','request_id':request_id,
                'node':existing[0],'term':existing[1],'index':existing[2],'digest':existing[3]}
    digest=digest_of({'content':content,'request_id':request_id})
    idx=state['idx']+1;term=state['term'];node=state['node']
    filename='apply:%s'%request_id
    row={'node':node,'term':term,'index':idx,'digest':digest,'prev_digest':state['digest'],
         'source':'client','ack':True,'ticket':request_id,'content':content}
    wal.capture(db,filename,[row],received_at=at)
    db.execute('INSERT INTO applied_changes VALUES (?,?,?,?,?,?,?)',
               (request_id,node,term,idx,digest,cjson,at))
    directory=endpoint_directory(wal.proven_prefix(db))
    _set_state(db,'write',node,term,idx,digest,directory,at)
    commit(db)
    return {'decision':'applied','request_id':request_id,'node':node,'term':term,
            'index':idx,'digest':digest,'endpoint':directory}

def verify(db,request=None):
    """State invariants: at most one reachable primary and no confirmed conflict."""
    ensure(db)
    prefix=wal.proven_prefix(db)
    faults=list(prefix['faults'])
    if prefix['blocked']:
        faults.append({'type':'confirmed_conflict','conflicts':prefix['conflicts']})
    # Two reachable nodes are a split brain if either carries a live write
    # capability (an issued lease or an open write link), regardless of which
    # one cluster_state currently points at.
    primaries=set()
    for r in status(db)['leases']:
        if r['status']=='issued' and gw.reachable(db,r['node']):
            primaries.add(r['node'])
    for (node,) in db.execute('SELECT DISTINCT node FROM gateway_links WHERE writable=1'):
        if gw.reachable(db,node):primaries.add(node)
    state=_state(db)
    if state and state['mode']=='write':primaries.add(state['node'])
    primaries=sorted(primaries)
    if len(primaries)>1:
        faults.append({'type':'dual_primary','nodes':primaries})
    return {'ok':not faults,'faults':faults,'prefix_head':prefix['head_index'],
            'prefix_digest':prefix['head_digest'],'primaries':primaries,
            'state':state,'endpoint':endpoint_directory(prefix)}
