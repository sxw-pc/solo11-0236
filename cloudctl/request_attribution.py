"""Associate request facts with a billable entity.

The billing question and the physical traffic question never share a single
flag.  Resolution therefore keeps three numbers apart:

* physical transmissions - one per proxy hop, retries included,
* business executions - one per successful backend receipt per token,
* billable units - charged at most once per request token, only when the
  request was admitted and really executed exactly once.

Identity attribution is only fixed by independent certificate binding
evidence.  When two tenant worlds stay compatible with every original, the
charge is held back instead of being guessed from page ordering or a digest.
"""
from .store import one,many
from . import billing_facts

# Resolution outcomes.  Only 'attributed' is directly billable to a tenant.
ATTRIBUTED='attributed'
AMBIGUOUS='ambiguous'
DENIED='denied'
NOT_EXECUTED='not_executed'
MULTIPLE_EXECUTIONS='multiple_executions'
RECEIPT_MISMATCH='receipt_mismatch'
MISSING_REQUEST='missing_request'
UNRESOLVED='unresolved'

def _tables(db):
    db.execute('CREATE TABLE IF NOT EXISTS cert_bindings(token TEXT PRIMARY KEY,tenant TEXT,evidence TEXT,at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS request_resolutions(token TEXT PRIMARY KEY,state TEXT,tenant TEXT,units INTEGER,transmissions INTEGER,executions INTEGER,detail TEXT)')

def bind_evidence(db,token,tenant,evidence,at):
    """Record independent evidence binding a request token to a tenant."""
    _tables(db)
    if not isinstance(token,str) or not token or not isinstance(tenant,str) or not tenant or not isinstance(evidence,str) or not evidence:
        raise ValueError('invalid_binding')
    if isinstance(at,bool) or not isinstance(at,int):
        raise ValueError('invalid_binding')
    old=one(db,'SELECT * FROM cert_bindings WHERE token=?',(token,))
    if old:
        if old['tenant']!=tenant:
            raise ValueError('binding_conflict')
        return 'replayed'
    with db:
        db.execute('INSERT INTO cert_bindings VALUES(?,?,?,?)',(token,tenant,evidence,at))
    return 'bound'

def _physical_transmissions(db,token):
    return db.execute('SELECT COUNT(*),COALESCE(SUM(units),0) FROM proxy_facts WHERE token=?',(token,)).fetchone()

def resolve(db,token):
    billing_facts.ensure(db)
    _tables(db)
    db.execute('CREATE TABLE IF NOT EXISTS admissions(id TEXT PRIMARY KEY,handshake TEXT,decision TEXT,at INTEGER)')
    req=one(db,'SELECT * FROM request_facts WHERE token=?',(token,))
    transmissions,physical_units=_physical_transmissions(db,token)
    if not req:
        return _store(db,token,MISSING_REQUEST,None,0,transmissions,0,{})
    admission_row=one(db,'SELECT decision FROM admissions WHERE handshake=?',(token,))
    # The meter page carries the admission decision; a control-plane admission
    # record, when present, must not contradict the original.
    if req['admission']!='allowed' or (admission_row is not None and admission_row['decision']!='allowed'):
        return _store(db,token,DENIED,None,0,transmissions,0,{'admission':req['admission']})
    proxy_success=many(db,"SELECT receipt FROM proxy_facts WHERE token=? AND status='success'",(token,))
    backend_success=many(db,"SELECT receipt,units FROM backend_facts WHERE token=? AND status='success'",(token,))
    backend_receipts={r['receipt'] for r in backend_success}
    proxy_receipts={r['receipt'] for r in proxy_success if r['receipt']}
    if proxy_receipts-backend_receipts:
        return _store(db,token,RECEIPT_MISMATCH,None,0,transmissions,len(backend_success),
                      {'proxy_only':sorted(proxy_receipts-backend_receipts)})
    if len(backend_success)==0:
        return _store(db,token,NOT_EXECUTED,None,0,transmissions,0,{})
    if len(backend_success)>1:
        return _store(db,token,MULTIPLE_EXECUTIONS,None,0,transmissions,len(backend_success),
                      {'receipts':sorted(backend_receipts)})
    units=req['units']
    binding=one(db,'SELECT tenant FROM cert_bindings WHERE token=?',(token,))
    if binding:
        return _store(db,token,ATTRIBUTED,binding['tenant'],units,transmissions,1,
                      {'physical_units':physical_units})
    candidates=set()
    page_tenant=one(db,'SELECT tenant FROM request_facts WHERE token=?',(token,))
    if page_tenant and page_tenant['tenant']:
        candidates.add(page_tenant['tenant'])
    return _store(db,token,AMBIGUOUS,None,units,transmissions,1,
                  {'candidates':sorted(candidates),'physical_units':physical_units,
                   'cert_generations':[r['cert_generation'] for r in many(db,'SELECT DISTINCT cert_generation FROM proxy_facts WHERE token=?',(token,))]})

def _store(db,token,state,tenant,units,transmissions,executions,detail):
    import json
    _tables(db)
    with db:
        db.execute('INSERT OR REPLACE INTO request_resolutions VALUES(?,?,?,?,?,?,?)',
                   (token,state,tenant,units,transmissions,executions,json.dumps(detail,sort_keys=True)))
    return {'token':token,'state':state,'tenant':tenant,'units':units,
            'transmissions':transmissions,'executions':executions,'detail':detail}

def resolve_all(db):
    _tables(db)
    tokens={r['token'] for r in many(db,'SELECT token FROM request_facts')}
    tokens|={r['token'] for r in many(db,'SELECT DISTINCT token FROM proxy_facts')}
    tokens|={r['token'] for r in many(db,'SELECT DISTINCT token FROM backend_facts')}
    return [resolve(db,t) for t in sorted(tokens)]

def status_of(db,token):
    _tables(db)
    row=one(db,'SELECT * FROM request_resolutions WHERE token=?',(token,))
    return dict(row) if row else None
