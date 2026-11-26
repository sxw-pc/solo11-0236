"""Import offline database WAL pages and derive a provable commit prefix.

A captured page carries the five legacy columns (``node``, ``term``,
``index``, ``digest``, ``ack``) plus the evidence the failover path needs:

* ``prev_digest`` -- digest of the immediately preceding log position;
* ``boot``        -- node startup generation;
* ``source``      -- where the acknowledgement actually came from
                     (leader, witness disk, replica hand-off, ...);
* ``ticket``      -- the client confirmation ticket (``client_ticket`` and
                     ``confirm_ticket`` are accepted aliases).

An identical page is only a replay.  A *different* page is rejected, but two
different pages that claim the same log position are both retained as fork
evidence.  A higher term never replaces content that carries a client
confirmation: :func:`proven_prefix` picks the confirmed digest and records the
unconfirmed competitor as an ignored fork.

The proven prefix is built from confirmed entries only, linked by
``prev_digest``.  It deliberately ignores unconfirmed suffixes -- that is what
keeps a diverged replica's ``west`` entry from becoming an endpoint.
"""
import hashlib,json
from .store import commit

CORE=('node','term','index','digest')
OPTIONAL=('prev_digest','boot','source','ticket','client_ticket','confirm_ticket','content')
CONTENT_KEYS=('content','change','payload','update','record','endpoint_change')
GENESIS=hashlib.sha256(b'cloudctl-wal-genesis').hexdigest()

def canon(obj):
    return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False)

def ensure(db):
    db.execute('CREATE TABLE IF NOT EXISTS wal_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS wal_captures (page TEXT PRIMARY KEY,received_at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS wal_entries (page TEXT,line INTEGER,node TEXT,'
               'term INTEGER,idx INTEGER,digest TEXT,prev_digest TEXT,boot INTEGER,'
               'source TEXT,ticket TEXT,ack INTEGER,content_json TEXT,extras TEXT,'
               'raw_json TEXT,PRIMARY KEY(page,line))')

def _norm_row(r):
    if not isinstance(r,dict) or not set(CORE)<=set(r):raise ValueError('invalid_wal_page')
    if not isinstance(r['node'],str) or not r['node']:raise ValueError('invalid_wal_page')
    # bool is an int subclass in Python; keep the original strict integer check.
    if type(r['term']) is not int or type(r['index']) is not int or r['index']<0:raise ValueError('invalid_wal_page')
    if not isinstance(r['digest'],str) or not r['digest']:raise ValueError('invalid_wal_page')
    prev=r.get('prev_digest')
    if prev is not None and (not isinstance(prev,str) or not prev):raise ValueError('invalid_wal_page')
    boot=r.get('boot')
    if boot is not None and type(boot) is not int:raise ValueError('invalid_wal_page')
    source=r.get('source')
    if source is not None and not isinstance(source,str):raise ValueError('invalid_wal_page')
    ack=r.get('ack')
    if ack is not None and type(ack) is not bool:raise ValueError('invalid_wal_page')
    ticket=r.get('ticket') or r.get('client_ticket') or r.get('confirm_ticket')
    if ticket is not None and not isinstance(ticket,str):raise ValueError('invalid_wal_page')
    known=set(CORE)|set(OPTIONAL)|set(CONTENT_KEYS)
    content=None
    for key in CONTENT_KEYS:
        if key in r:content=r[key];break
    return {'node':r['node'],'term':r['term'],'index':r['index'],'digest':r['digest'],
            'prev_digest':prev,'boot':boot,'source':source,'ticket':ticket,'ack':ack,
            'content':content,
            'extras':{k:v for k,v in r.items() if k not in known}}

def capture(db,page=None,rows=None,received_at=None):
    """Capture one WAL page.

    ``capture(db,page,rows)`` is the original public shape.  A request dict is
    also accepted so the operation can be dispatched from ``__main__``.
    """
    if isinstance(page,dict) and rows is None:
        request=page;page=request.get('page');rows=request.get('rows');received_at=request.get('received_at',received_at)
    ensure(db)
    if not isinstance(page,str) or not page:raise ValueError('invalid_wal_page')
    if not isinstance(rows,list) or any(not isinstance(r,dict) or not set(CORE)<=set(r) for r in rows):raise ValueError('invalid_wal_page')
    normalised=[_norm_row(r) for r in rows]
    raw=json.dumps(rows,sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    old=db.execute('SELECT digest FROM wal_pages WHERE page=?',(page,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('wal_page_conflict')
        return 'replayed'
    db.execute('INSERT INTO wal_pages VALUES (?,?,?)',(page,digest,raw))
    db.execute('INSERT OR REPLACE INTO wal_captures VALUES (?,?)',(page,int(received_at or 0)))
    for line,row in enumerate(normalised,1):
        db.execute('INSERT INTO wal_entries VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (page,line,row['node'],row['term'],row['index'],row['digest'],
                    row['prev_digest'],row['boot'],row['source'],row['ticket'],
                    1 if row['ack'] else 0,
                    canon(row['content']) if row['content'] is not None else None,
                    canon(row['extras']) if row['extras'] else None,canon(row)))
    commit(db)
    return 'captured'

def _from_legacy(page,raw):
    out=[]
    for line,row in enumerate(json.loads(raw),1):
        r=_norm_row(row)
        r.update({'page':page,'line':line})
        out.append(r)
    return out

def entries(db,node=None):
    """Every distinct captured entry, retaining same-position forks."""
    ensure(db)
    q='SELECT * FROM wal_entries'
    args=[]
    if node is not None:
        q+=' WHERE node=?';args.append(node)
    q+=' ORDER BY page,line'
    stored={}
    for r in db.execute(q,args):
        page,line,node,term,idx,digest,prev,boot,source,ticket,ack,content,extras,raw=(tuple(r)+tuple([None]*14))[:14]
        item={'page':page,'line':line,'node':node,'term':term,
              'index':idx,'digest':digest,'prev_digest':prev,
              'boot':boot,'source':source,'ticket':ticket,
              'ack':bool(ack),
              'content':json.loads(content) if content else None,
              'extras':json.loads(extras) if extras else {}}
        stored[(page,line)]=item
    # Legacy pages written before the row table existed contain no wal_entries
    # rows at all; only those need the JSON fallback.  A page that merely has
    # no row for the requested node must not leak other pages back in.
    have={row[0] for row in db.execute('SELECT DISTINCT page FROM wal_entries')}
    for page,digest,raw in db.execute('SELECT page,digest,rows_json FROM wal_pages'):
        if page in have:continue
        for item in _from_legacy(page,raw):stored.setdefault((page,item['line']),item)
    return [stored[k] for k in sorted(stored)]

def confirmed(entry):
    source=(entry.get('source') or '').lower()
    return bool(entry.get('ack')) or bool(entry.get('ticket')) or source in ('witness','client','customer','confirmed')

def forks(db):
    """Log positions where different content was written.

    A fork is any ``index`` carrying more than one distinct digest, whether the
    copies were written under one term or competing terms.  "Log position" is
    the index, precisely because a higher term at the same index is the case
    that must not overwrite client-confirmed content.
    """
    grouped={}
    for e in entries(db):
        grouped.setdefault(e['index'],{}).setdefault(e['digest'],[]).append(e)
    out=[]
    for index,digests in sorted(grouped.items()):
        if len(digests)>1:
            out.append({'index':index,'digests':sorted(digests),
                        'terms':{d:sorted({x['term'] for x in digests[d]}) for d in digests},
                        'nodes':sorted({x['node'] for d in digests for x in digests[d]}),
                        'confirmed':sorted(d for d in digests if any(confirmed(x) for x in digests[d]))})
    return out

def _merge_candidates(all_entries):
    """Merge copies of the same position/digest from different pages/nodes.

    Two identical digests are the same committed value even when observed on
    several nodes or on the witness; confirmation is the OR of the copies.
    """
    by_index={}
    faults=[]
    for e in all_entries:
        slot=by_index.setdefault(e['index'],{}).setdefault(e['digest'],{
            'index':e['index'],'digest':e['digest'],'confirmed':False,'entries':[],
            'terms':set(),'nodes':set(),'sources':set(),'prevs':set(),
            'content':None,'ticket':None,'boot':None})
        slot['entries'].append(e);slot['terms'].add(e['term']);slot['nodes'].add(e['node'])
        slot['sources'].add(e['source']);slot['confirmed']=slot['confirmed'] or confirmed(e)
        if e['prev_digest'] is not None:slot['prevs'].add(e['prev_digest'])
        if slot['ticket'] is None and e['ticket'] is not None:slot['ticket']=e['ticket']
        if slot['content'] is None and e['content'] is not None:slot['content']=e['content']
        if slot['boot'] is None and e['boot'] is not None:slot['boot']=e['boot']
    for index,digests in by_index.items():
        for digest,slot in digests.items():
            if len(slot['prevs'])>1:
                faults.append({'type':'predecessor_conflict','index':index,'digest':digest,
                               'predecessors':sorted(slot['prevs'])})
            slot['prev_digest']=sorted(slot['prevs'])[0] if slot['prevs'] else None
            slot['term']=max(slot['terms']);slot['node']=sorted(slot['nodes'])[0]
    return by_index,faults

def proven_prefix(db,node=None):
    """Longest linked chain of client-confirmed entries.

    Returns the chain plus any confirmed conflicts and the unconfirmed forks
    that were deliberately ignored.  ``blocked`` is true when two *confirmed*
    digests claim the same position: no term may choose between them.
    """
    if isinstance(node,dict):node=node.get('node')
    all_entries=entries(db,node)
    by_index,faults=_merge_candidates(all_entries)
    canonical={};conflicts=[];ignored=[]
    for index,digests in sorted(by_index.items()):
        conf=[d for d in digests if digests[d]['confirmed']]
        if len(conf)>1:
            conflicts.append({'type':'confirmed_conflict','index':index,
                              'digests':sorted(conf),
                              'terms':{d:max(digests[d]['terms']) for d in conf},
                              'nodes':{d:sorted(digests[d]['nodes']) for d in conf}})
            canonical[index]=None
        elif len(conf)==1:
            canonical[index]=digests[conf[0]]
            for d in digests:
                if d!=conf[0]:
                    ignored.append({'index':index,'ignored_digest':d,
                                    'ignored_terms':sorted(digests[d]['terms']),
                                    'kept_digest':conf[0],'reason':'unconfirmed_higher_term'})
        else:
            canonical[index]=None
    chain_ending={};best=None;best_score=None
    for index in sorted(canonical):
        entry=canonical[index]
        if entry is None:continue
        prev=canonical.get(index-1) if index>1 else None
        if prev is not None and entry['prev_digest'] is not None and prev['digest']==entry['prev_digest']:
            chain=chain_ending[index-1]+[entry]
        else:
            chain=[entry]
            if index>1 and entry['prev_digest'] is not None and prev is not None:
                faults.append({'type':'broken_link','index':index,
                               'expected':entry['prev_digest'],'previous':prev['digest']})
        chain_ending[index]=chain
        score=(len(chain),index,entry['digest'])
        if best_score is None or score>best_score:
            best_score=score;best=chain
    if not best:
        return {'entries':[],'head_index':0,'head_digest':None,'base_index':0,
                'base_digest':None,'anchored':False,'conflicts':conflicts,
                'ignored_forks':ignored,'faults':faults,
                'blocked':bool(conflicts),'digests':{}}
    first=best[0]
    anchored=first['index']==1 or first['prev_digest'] in (None,'',GENESIS)
    serial=[]
    for e in best:
        serial.append({'index':e['index'],'digest':e['digest'],'term':e['term'],
                       'prev_digest':e['prev_digest'],'node':e['node'],
                       'content':e['content'],'ticket':e['ticket'],'boot':e['boot'],
                       'sources':sorted(x for x in e['sources'] if x)})
    return {'entries':serial,'head_index':best[-1]['index'],'head_digest':best[-1]['digest'],
            'base_index':first['index'],'base_digest':first['prev_digest'],
            'anchored':anchored,'conflicts':conflicts,'ignored_forks':ignored,
            'faults':faults,'blocked':bool(conflicts),
            'digests':{e['index']:e['digest'] for e in serial}}

def node_contains(db,node,prefix):
    """Whether ``node`` holds every entry of the proven prefix."""
    own={}
    for e in entries(db,node):own.setdefault(e['index'],set()).add(e['digest'])
    missing=[]
    for e in prefix['entries']:
        if e['digest'] not in own.get(e['index'],set()):
            missing.append({'index':e['index'],'digest':e['digest']})
    return missing

def replay(db,node=None,source='witness',at=None,page=None):
    """Copy the proven prefix onto ``node`` from the witness.

    The copy is written as ordinary confirmed entries.  Divergent unconfirmed
    entries already on the node are left untouched: both same-position rows
    remain, and :func:`proven_prefix` keeps the confirmed value.
    """
    if isinstance(node,dict):
        request=node;node=request.get('node');source=request.get('source',source)
        at=request.get('at',at);page=request.get('page',page)
    if not isinstance(node,str) or not node:raise ValueError('missing_node')
    prefix=proven_prefix(db)
    if prefix['blocked']:return {'decision':'prefix_conflict','node':node,'conflicts':prefix['conflicts']}
    if not prefix['entries']:return {'decision':'nothing_to_replay','node':node}
    present=entries(db,node)
    have={(e['index'],e['digest']) for e in present}
    copied=[]
    for e in prefix['entries']:
        if (e['index'],e['digest']) in have:continue
        pid=page or ('replay:%s:%s:%s'%(node,e['index'],e['digest'][:12]))
        row={'node':node,'term':e['term'],'index':e['index'],'digest':e['digest'],
             'prev_digest':e.get('prev_digest'),'boot':e.get('boot'),
             'source':source,'ack':True,'content':e.get('content')}
        if e.get('ticket') is not None:row['ticket']=e['ticket']
        capture(db,pid,[row],received_at=at)
        copied.append({'index':e['index'],'digest':e['digest']})
    return {'decision':'replayed' if copied else 'idempotent','node':node,
            'replayed':copied,'index':prefix['head_index'],
            'prefix_digest':prefix['head_digest'],
            'missing_after':node_contains(db,node,prefix)}
