"""Customer billing: per-tenant bills issued independently from cloud payouts.

A bill batch is an independently signed, immutable money record.  Re-issuing
the same batch is an idempotent replay; a physical request already billed is
never billed a second time.  Late backend receipts or late binding evidence
can only add a supplementary bill or a reversal entry - historical money
records are never overwritten.
"""
from . import request_attribution as ra
from . import billing_facts

def _tables(db):
    billing_facts.ensure(db)
    ra._tables(db)
    db.execute('CREATE TABLE IF NOT EXISTS bill_batches(id TEXT PRIMARY KEY,tenant TEXT,period TEXT,metric INTEGER,issued_at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS bill_items(batch TEXT,token TEXT,units INTEGER,state TEXT,PRIMARY KEY(batch,token))')
    db.execute('CREATE TABLE IF NOT EXISTS bill_adjustments(id TEXT PRIMARY KEY,batch TEXT,token TEXT,kind TEXT,units INTEGER,at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS billed_tokens(token TEXT PRIMARY KEY,batch TEXT,units INTEGER)')

def issue_batch(db,batch,tenant,period='',at=0):
    """Bill one tenant for every attributed, once-executed request not yet billed."""
    _tables(db)
    if not isinstance(batch,str) or not batch or not isinstance(tenant,str) or not tenant:
        raise ValueError('invalid_batch')
    old=_batch(db,batch)
    if old:
        if old['tenant']!=tenant or old['period']!=period:
            raise ValueError('batch_conflict')
        return {'batch':batch,'tenant':tenant,'period':period,'metric':old['metric'],'status':'replayed'}
    ra.resolve_all(db)
    rows=db.execute("SELECT token,units FROM request_resolutions WHERE state=? AND tenant=? AND units>0 ORDER BY token",
                    (ra.ATTRIBUTED,tenant)).fetchall()
    chosen=[]
    for token,units in rows:
        if _already_billed(db,token):
            continue
        chosen.append((token,units))
    metric=sum(u for _,u in chosen)
    with db:
        db.execute('INSERT INTO bill_batches VALUES(?,?,?,?,?)',(batch,tenant,period,metric,at))
        for token,units in chosen:
            db.execute('INSERT INTO bill_items VALUES(?,?,?,?)',(batch,token,units,ra.ATTRIBUTED))
            db.execute('INSERT INTO billed_tokens VALUES(?,?,?)',(token,batch,units))
    return {'batch':batch,'tenant':tenant,'period':period,'metric':metric,
            'tokens':[t for t,_ in chosen],'status':'issued'}

def supplement(db,adjust,batch,token,at=0):
    """Late binding evidence: charge the tenant for one previously held request."""
    _tables(db)
    resolution=ra.resolve(db,token)
    if resolution['state']!=ra.ATTRIBUTED or resolution['tenant']!=_batch(db,batch)['tenant']:
        raise ValueError('not_attributable')
    if _adjustment(db,adjust):
        return {'id':adjust,'status':'replayed'}
    if _already_billed(db,token):
        raise ValueError('already_billed')
    units=resolution['units']
    with db:
        db.execute('INSERT INTO bill_adjustments VALUES(?,?,?,?,?,?)',(adjust,batch,token,'supplement',units,at))
        db.execute('INSERT INTO billed_tokens VALUES(?,?,?)',(token,batch,units))
        db.execute('UPDATE bill_batches SET metric=metric+? WHERE id=?',(units,batch))
    return {'id':adjust,'batch':batch,'token':token,'kind':'supplement','units':units,'status':'issued'}

def reverse(db,adjust,batch,token,units,at=0):
    """Late receipt proves an earlier charge was wrong: reversal entry only."""
    _tables(db)
    billed=_billed(db,token)
    if not billed or billed['batch']!=batch:
        raise ValueError('not_billed_in_batch')
    if _adjustment(db,adjust):
        return {'id':adjust,'status':'replayed'}
    if units<=0 or units>billed['units']:
        raise ValueError('invalid_amount')
    with db:
        db.execute('INSERT INTO bill_adjustments VALUES(?,?,?,?,?,?)',(adjust,batch,token,'reversal',units,at))
        db.execute('UPDATE bill_batches SET metric=metric-? WHERE id=?',(units,batch))
        db.execute('UPDATE billed_tokens SET units=units-? WHERE token=?',(units,token))
    return {'id':adjust,'batch':batch,'token':token,'kind':'reversal','units':units,'status':'issued'}

def account(db,tenant):
    _tables(db)
    total=db.execute('SELECT COALESCE(SUM(metric),0) FROM bill_batches WHERE tenant=?',(tenant,)).fetchone()[0]
    return {'tenant':tenant,'balance':total,
            'batches':[dict(r) for r in db.execute('SELECT id,period,metric FROM bill_batches WHERE tenant=? ORDER BY id',(tenant,))]}

def _batch(db,batch):
    row=db.execute('SELECT * FROM bill_batches WHERE id=?',(batch,)).fetchone()
    return dict(row) if row else None
def _billed(db,token):
    row=db.execute('SELECT * FROM billed_tokens WHERE token=?',(token,)).fetchone()
    return dict(row) if row else None
def _already_billed(db,token):
    row=_billed(db,token)
    return row is not None and row['units']>0
def _adjustment(db,adjust):
    row=db.execute('SELECT 1 FROM bill_adjustments WHERE id=?',(adjust,)).fetchone()
    return row is not None
