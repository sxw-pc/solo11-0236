import argparse,json,sys
from . import identity,trust,admission,store,audit,hardware_custody,vendor_rma
OPS={'identity.bind':identity.bind,'identity.issue':identity.issue,'identity.revoke':identity.revoke,'identity.replica':identity.replica,'identity.retire':identity.retire,'trust.publish':trust.publish,'trust.ack':trust.acknowledge,'trust.coverage':trust.coverage,'trust.retry':trust.retry,'trust.withdraw':trust.withdraw,'handshake.authorize':admission.authorize,'handshake.decide':admission.handshake,'handshake.close':admission.close,'handshake.expiry':admission.expiry,'identity.audit':audit.inspect}
OPS.update(hardware_custody.OPS)
OPS.update(vendor_rma.OPS)
def execute(path,r):
    with store.tx(path) as db:
        action=r['action']
        fn=OPS.get(action)
        if fn is not None:
            return fn(db,r)
        vendor_prefixes=('rma.','vendor','warranty.','claim.','finance.','purchase.','warehouse.','vendor_rma.')
        hardware_prefixes=('hardware.','hardware_custody.','custody.','hw.','recall.','physical.','asset.')
        order=[vendor_rma,hardware_custody] if str(action).startswith(vendor_prefixes) else [hardware_custody,vendor_rma]
        if not str(action).startswith(vendor_prefixes+hardware_prefixes+('service.',)):
            order=[hardware_custody,vendor_rma]
        last_error=None
        for module in order:
            try:
                return module.dispatch(db,r)
            except KeyError as e:
                last_error=e
        raise ValueError('unknown action') from last_error
def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['init','demo','identity','trust','handshake','hardware','custody','recall','rma','vendor','warranty','finance','purchase','service']);p.add_argument('operation',nargs='?');p.add_argument('--db',default='state.sqlite');p.add_argument('--fixture');a=p.parse_args();store.init(a.db)
    if a.command=='init':print(json.dumps({'status':'initialized'}));return
    if not a.fixture and a.command!='demo':p.error('--fixture required')
    requests=json.load(open(a.fixture or 'fixtures/demo.json',encoding='utf-8'))
    allowed_prefixes={
      'hardware':('hardware.','custody.','hw.','recall.','physical.','asset.','service.'),
      'custody':('hardware.','custody.'),'recall':('hardware.','recall.'),
      'rma':('rma.','vendor.','warranty.','claim.'),'vendor':('rma.','vendor.','warranty.','claim.'),
      'warranty':('rma.','vendor.','warranty.','claim.'),'finance':('finance.',),
      'purchase':('purchase.','warehouse.'),'service':('service.',),
    }.get(a.command,(a.command+'.',))
    for r in requests if isinstance(requests,list) else [requests]:
        if a.command!='demo' and not r['action'].startswith(allowed_prefixes):raise ValueError('wrong subsystem command')
        for prerequisite in r.get('setup',[]):execute(a.db,prerequisite)
        print(json.dumps(execute(a.db,r),ensure_ascii=False,default=str))
if __name__=='__main__':
    try:main()
    except (ValueError,KeyError) as e:print(json.dumps({'error':str(e)}),file=sys.stderr);sys.exit(2)
