"""Upstream cloud vendor settlement on physical transmission volume.

The vendor is paid for every physical hop a proxy page proves, including the
real traffic produced by a primary/backup retry.  Payment never waits for
tenant identity to be known; a request whose customer cannot yet be named
leaves its customer-sized liability on the platform account instead of
short-changing the bandwidth bill.
"""
from . import request_attribution as ra
from . import billing_facts

def _tables(db):
    billing_facts.ensure(db)
    ra._tables(db)
    db.execute('CREATE TABLE IF NOT EXISTS vendor_batches(id TEXT PRIMARY KEY,period TEXT,metric INTEGER,paid_at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS vendor_items(batch TEXT,proxy TEXT,token TEXT,units INTEGER,PRIMARY KEY(batch,proxy,token))')
    db.execute('CREATE TABLE IF NOT EXISTS platform_liabilities(token TEXT PRIMARY KEY,units INTEGER,batch TEXT,state TEXT)')

def pay_bandwidth(db,batch,period='',at=0):
    """Settle every physical proxy transmission; each hop is paid at most once."""
    _tables(db)
    old=db.execute('SELECT * FROM vendor_batches WHERE id=?',(batch,)).fetchone()
    if old:
        return {'batch':batch,'period':old['period'],'metric':old['metric'],'status':'replayed'}
    rows=db.execute('SELECT proxy,token,units FROM proxy_facts ORDER BY token,proxy').fetchall()
    chosen=[]
    for proxy,token,units in rows:
        if db.execute('SELECT 1 FROM vendor_items WHERE proxy=? AND token=?',(proxy,token)).fetchone():
            continue
        chosen.append((proxy,token,units))
    metric=sum(u for _,_,u in chosen)
    with db:
        db.execute('INSERT INTO vendor_batches VALUES(?,?,?,?)',(batch,period,metric,at))
        db.executemany('INSERT INTO vendor_items VALUES(?,?,?,?)',[(batch,p,t,u) for p,t,u in chosen])
    _refresh_liabilities(db,batch)
    return {'batch':batch,'period':period,'metric':metric,
            'hops':[{'proxy':p,'token':t,'units':u} for p,t,u in chosen],'status':'paid'}

def _refresh_liabilities(db,batch):
    """Customer-sized units of executed but unattributable requests stay on the platform."""
    ra.resolve_all(db)
    held=db.execute("SELECT token,units FROM request_resolutions WHERE state=?",(ra.AMBIGUOUS,)).fetchall()
    for token,units in held:
        old=db.execute('SELECT * FROM platform_liabilities WHERE token=?',(token,)).fetchone()
        if old:
            continue
        db.execute('INSERT INTO platform_liabilities VALUES(?,?,?,?)',(token,units,batch,'unallocated'))

def allocate_liability(db,token):
    """Binding evidence arrived: move the held customer liability off the platform."""
    _tables(db)
    old=db.execute('SELECT * FROM platform_liabilities WHERE token=?',(token,)).fetchone()
    if not old:
        return {'token':token,'status':'nothing_held'}
    resolution=ra.resolve(db,token)
    if resolution['state']!=ra.ATTRIBUTED:
        return {'token':token,'status':'still_unallocated','state':resolution['state']}
    with db:
        db.execute("UPDATE platform_liabilities SET state=? WHERE token=?",('allocated',token))
    return {'token':token,'status':'allocated','tenant':resolution['tenant'],'units':old['units']}

def platform_account(db):
    _tables(db)
    total=db.execute("SELECT COALESCE(SUM(units),0) FROM platform_liabilities WHERE state='unallocated'",()).fetchone()[0]
    return {'unallocated':total,
            'liabilities':[dict(r) for r in db.execute('SELECT token,units,batch,state FROM platform_liabilities ORDER BY token')]}
