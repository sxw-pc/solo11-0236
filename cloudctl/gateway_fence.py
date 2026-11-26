"""Physical fencing evidence for database write entry points.

A lease row written by the control plane is *not* a fence.  A node is only
isolated when every write path that can actually reach it has been physically
closed: a connection terminated, a listener stopped, a route withdrawn at the
gateway that held it.  Fences are timestamped, so a fence recorded at a later
minute cannot justify a lease issued earlier.

Gateways keep two independent pieces of state:

* ``gateway_links`` -- the live write capability between a gateway and a node.
  Rerouting the gateway does **not** close an old link; the link must be
  fenced explicitly.
* ``gateway_fences`` -- physical evidence that the link was closed.
"""
import json
from .store import commit

PHYSICAL_KINDS={'connection_closed','connection_reset','route_withdrawn',
                'listener_stopped','gateway_isolated','gateway_quarantined',
                'network_partition','interface_down','power_cut','physical'}
NON_PHYSICAL_KINDS={'lease','control_plane','controlplane','policy','advisory',
                    'intent','planned','planned_fence','drain'}

def _decide(decision,**evidence):
    out={'decision':decision};out.update(evidence);return out

def ensure(db):
    db.execute('CREATE TABLE IF NOT EXISTS gateways(id TEXT PRIMARY KEY,route TEXT,mode TEXT,at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS gateway_links(gateway TEXT,node TEXT,'
               'writable INTEGER,opened_at INTEGER,closed_at INTEGER,PRIMARY KEY(gateway,node))')
    db.execute('CREATE TABLE IF NOT EXISTS gateway_fences(gateway TEXT,node TEXT,at INTEGER,'
               'kind TEXT,evidence TEXT,physical INTEGER,PRIMARY KEY(gateway,node))')
    cols={row[1] for row in db.execute('PRAGMA table_info(gateway_links)')}
    if 'closed_at' not in cols:
        db.execute('ALTER TABLE gateway_links ADD COLUMN closed_at INTEGER')
    db.execute('UPDATE gateway_links SET closed_at=(SELECT f.at FROM gateway_fences f '
               'WHERE f.gateway=gateway_links.gateway AND f.node=gateway_links.node AND f.physical=1) '
               'WHERE writable=0 AND closed_at IS NULL')

def _physical(kind,evidence):
    kind=(kind or '').strip().lower().replace(' ','_')
    detail=(evidence or '') if isinstance(evidence,str) else str((evidence or {}).get('kind') or
           (evidence or {}).get('method') or (evidence or {}).get('note') or '')
    detail=detail.strip().lower().replace(' ','_')
    if not kind:kind=detail
    # A lease, control-plane record or plan never counts, even if the caller
    # also stamps the evidence ``physical``: only a real closure is a fence.
    if kind in NON_PHYSICAL_KINDS or detail in NON_PHYSICAL_KINDS:return False,kind
    if any(word in kind for word in ('lease','control_plane','controlplane')):return False,kind
    if isinstance(evidence,dict) and evidence.get('physical') is True:
        return True,kind or 'physical'
    return kind in PHYSICAL_KINDS,kind

def open(db,gateway=None,node=None,writes=True,at=0,request=None):
    """Register a gateway and a live (physical) link to ``node``."""
    if isinstance(gateway,dict) and request is None:
        request=gateway;gateway=None
    if isinstance(request,dict):
        node=request.get('node');writes=request.get('writes',request.get('writable',True))
        at=request.get('at',at);gateway=request.get('gateway',request.get('id'))
    if not isinstance(gateway,str) or not gateway:raise ValueError('missing_gateway')
    if not isinstance(node,str) or not node:raise ValueError('missing_node')
    ensure(db)
    mode='write' if writes else 'read'
    db.execute('INSERT OR REPLACE INTO gateways VALUES (?,?,?,?)',(gateway,node,mode,int(at or 0)))
    # Re-opening after a close starts a fresh live interval.
    db.execute('INSERT INTO gateway_links VALUES (?,?,?,?,?) ON CONFLICT(gateway,node) '
               'DO UPDATE SET writable=MAX(writable,excluded.writable),'
               'closed_at=CASE WHEN excluded.opened_at>COALESCE(closed_at,-1) THEN NULL ELSE closed_at END',
               (gateway,node,1 if writes else 0,int(at or 0),None))
    commit(db)
    return _decide('linked',gateway=gateway,node=node,writes=bool(writes),at=int(at or 0))

def link(db,gateway,node,writes=True,at=0):
    if isinstance(gateway,dict):return open(db,gateway)
    return open(db,gateway,node,writes,at)

def route(db,gateway=None,node=None,mode='write',at=0,request=None):
    """Change a gateway's logical route.

    Routing to another node is not isolation: any previously opened write link
    stays live until :func:`fence` records physical evidence for it.
    """
    if isinstance(gateway,dict) and request is None:
        request=gateway;gateway=None
    if isinstance(request,dict):
        gateway=request.get('gateway',request.get('id'));node=request.get('node')
        mode=request.get('mode','write');at=request.get('at',at)
    if not isinstance(gateway,str) or not gateway:raise ValueError('missing_gateway')
    ensure(db)
    db.execute('INSERT OR REPLACE INTO gateways VALUES (?,?,?,?)',(gateway,node,mode,int(at or 0)))
    if mode=='write' and node:
        # A new route carries live write traffic, but it must not retroactively
        # re-open a link that was physically closed earlier.
        closed=db.execute('SELECT physical FROM gateway_fences WHERE gateway=? AND node=?',(gateway,node)).fetchone()
        if not (closed and int(closed[0])):
            db.execute('INSERT INTO gateway_links VALUES (?,?,?,?,?) ON CONFLICT(gateway,node) '
                       'DO UPDATE SET writable=1,opened_at=MIN(opened_at,excluded.opened_at)',
                       (gateway,node,1,int(at or 0),None))
    commit(db)
    return _decide('routed',gateway=gateway,node=node,mode=mode,at=int(at or 0))

def fence(db,gateway=None,node=None,at=0,evidence=None,kind=None,request=None):
    """Record physical isolation of ``gateway`` from ``node``.

    Accepts either ``fence(db, gateway, node, at, kind)`` or a request dict.
    Non-physical evidence (including a control-plane lease) is refused and the
    live link is left writable, so the refusal cannot be mistaken for a fence.
    """
    if isinstance(gateway,dict) and request is None:
        request=gateway;gateway=None
    if isinstance(request,dict):
        gateway=request.get('gateway',request.get('id'));node=request.get('node')
        at=request.get('at',at);evidence=request.get('evidence',evidence)
        kind=request.get('kind',request.get('method',kind))
    if not isinstance(gateway,str) or not gateway:raise ValueError('missing_gateway')
    if not isinstance(node,str) or not node:raise ValueError('missing_node')
    ensure(db)
    ok,kind=_physical(kind,evidence)
    live=db.execute('SELECT writable FROM gateway_links WHERE gateway=? AND node=?',(gateway,node)).fetchone()
    if live and int(live[0]) and not ok:
        return _decide('not_physical',gateway=gateway,node=node,kind=kind)
    if live:db.execute('UPDATE gateway_links SET closed_at=?,opened_at=MIN(opened_at,?) WHERE gateway=? AND node=?',
                       (int(at or 0),int(at or 0),gateway,node))
    db.execute('INSERT OR REPLACE INTO gateway_fences VALUES (?,?,?,?,?,?)',
               (gateway,node,int(at or 0),kind,json.dumps(evidence,sort_keys=True,ensure_ascii=False) if isinstance(evidence,dict) else (evidence or ''),1 if ok else 0))
    commit(db)
    return _decide('fenced' if ok else 'fenced_nonphysical',gateway=gateway,node=node,at=int(at or 0),kind=kind)

def fence_node(db,node=None,at=0,evidence=None,kind=None,request=None):
    """Fence every live link that reaches ``node`` (``fence_node(db,'a',...)``
    and the request-dict form are both accepted)."""
    if isinstance(node,dict) and request is None:
        request=node;node=None
    if isinstance(request,dict):
        node=request.get('node');at=request.get('at',at)
        evidence=request.get('evidence',evidence);kind=request.get('kind',kind)
    if not isinstance(node,str) or not node:raise ValueError('missing_node')
    ensure(db)
    gateways=[r[0] for r in db.execute('SELECT gateway FROM gateway_links WHERE node=? AND writable=1',(node,))]
    results=[fence(db,gw,node,at,evidence,kind) for gw in gateways]
    return _decide('fenced' if all(r['decision']=='fenced' for r in results) else 'fence_incomplete',
                   node=node,at=int(at or 0),fences=results)

def links(db,node=None):
    ensure(db)
    q='SELECT * FROM gateway_links';args=[]
    if node is not None:q+=' WHERE node=?';args.append(node)
    rows=list(db.execute(q,args))
    return [dict(r) if hasattr(r,'keys') else {'gateway':r[0],'node':r[1],'writable':bool(r[2]),
            'opened_at':r[3],'closed_at':r[4] if len(r)>4 else None} for r in rows]

def reachable(db,node,at=None):
    """Live write links to ``node`` that are not physically fenced by ``at``."""
    ensure(db)
    rows=db.execute('SELECT gateway,node,writable,opened_at,closed_at FROM gateway_links WHERE node=? AND writable=1',(node,))
    out=[]
    for gateway,subject,writable,opened_at,closed_at in rows:
        if at is not None and int(opened_at)>int(at):continue
        # A closed link only stops counting once the close timestamp is reached;
        # a fence recorded later cannot explain away earlier reachability.
        if closed_at is not None and (at is None or int(closed_at)<=int(at)):continue
        fence_row=db.execute('SELECT at,physical FROM gateway_fences WHERE gateway=? AND node=?',(gateway,subject)).fetchone()
        if fence_row and int(fence_row[1]) and fence_row[0] is not None and (at is None or int(fence_row[0])<=int(at)):
            continue
        out.append({'gateway':gateway,'node':subject,'opened_at':int(opened_at),
                    **({'closed_at':int(closed_at)} if closed_at is not None else {})})
    return out

def unfenced(db,at=None,exclude=None):
    """Every reachable write link whose node is not ``exclude``."""
    ensure(db)
    out=[]
    for row in db.execute('SELECT DISTINCT node FROM gateway_links WHERE writable=1'):
        node=row[0]
        if node==exclude:continue
        for link in reachable(db,node,at):out.append(link)
    return out

def fence_history(db):
    ensure(db)
    return [{'gateway':g,'node':n,'at':a,'kind':k,'physical':bool(p)}
            for g,n,a,k,ev,p in db.execute('SELECT gateway,node,at,kind,physical FROM gateway_fences ORDER BY at,gateway')]
