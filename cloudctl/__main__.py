import argparse,json,sys
from . import identity,trust,admission,store,audit,retention_custody,physical_erasure
OPS={'identity.bind':identity.bind,'identity.issue':identity.issue,'identity.revoke':identity.revoke,'identity.replica':identity.replica,'identity.retire':identity.retire,'trust.publish':trust.publish,'trust.ack':trust.acknowledge,'trust.coverage':trust.coverage,'trust.retry':trust.retry,'trust.withdraw':trust.withdraw,'handshake.authorize':admission.authorize,'handshake.decide':admission.handshake,'handshake.close':admission.close,'handshake.expiry':admission.expiry,'identity.audit':audit.inspect,
'custody.file_order':retention_custody.file_order,'custody.register_key':retention_custody.register_key,'custody.register_volume':retention_custody.register_volume,'custody.register_objects':retention_custody.register_objects,'custody.register_manifest':retention_custody.register_manifest,'custody.open':retention_custody.open_case,'custody.migrate':retention_custody.migrate,'custody.rearrange':retention_custody.rearrange,'custody.deliver_court':retention_custody.deliver_court,'custody.complete':retention_custody.complete,'custody.amend':retention_custody.amend,'custody.resume':retention_custody.resume,'custody.status':retention_custody.status,
'erasure.erase_object':physical_erasure.erase_object,'erasure.erase_copy':physical_erasure.erase_copy,'erasure.verify_copy':physical_erasure.verify_copy,'erasure.shred_key':physical_erasure.shred_key,'erasure.reachability':physical_erasure.reachability}
def execute(path,r):
    with store.tx(path) as tx_:
        if r['action'] not in OPS:raise ValueError('unknown action')
        return OPS[r['action']](tx_,r)
def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['init','demo','identity','trust','handshake','custody','erasure']);p.add_argument('operation',nargs='?');p.add_argument('--db',default='state.sqlite');p.add_argument('--fixture');a=p.parse_args();store.init(a.db)
    if a.command=='init':print(json.dumps({'status':'initialized'}));return
    if not a.fixture and a.command!='demo':p.error('--fixture required')
    requests=json.load(open(a.fixture or 'fixtures/demo.json',encoding='utf-8'))
    for r in requests if isinstance(requests,list) else [requests]:
        if a.command!='demo' and r['action'].split('.')[0]!=a.command:raise ValueError('wrong subsystem command')
        for prerequisite in r.get('setup',[]):execute(a.db,prerequisite)
        print(json.dumps(execute(a.db,r),ensure_ascii=False))
if __name__=='__main__':
    try:main()
    except (ValueError,KeyError) as e:print(json.dumps({'error':str(e)}),file=sys.stderr);sys.exit(2)
