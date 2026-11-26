import argparse,json,sys
from . import identity,trust,admission,store,audit,wal_capture,leader_lease,gateway_fence,consistent_read
OPS={'identity.bind':identity.bind,'identity.issue':identity.issue,'identity.revoke':identity.revoke,'identity.replica':identity.replica,'identity.retire':identity.retire,'trust.publish':trust.publish,'trust.ack':trust.acknowledge,'trust.coverage':trust.coverage,'trust.retry':trust.retry,'trust.withdraw':trust.withdraw,'handshake.authorize':admission.authorize,'handshake.decide':admission.handshake,'handshake.close':admission.close,'handshake.expiry':admission.expiry,'identity.audit':audit.inspect,
     'wal.capture':wal_capture.capture,'wal.prefix':wal_capture.proven_prefix,'wal.replay':wal_capture.replay,
     'gateway.open':gateway_fence.open,'gateway.route':gateway_fence.route,'gateway.fence':gateway_fence.fence,
     'gateway.fence_node':gateway_fence.fence_node,
     'leader.issue':leader_lease.issue,'leader.fence':leader_lease.fence_lease,'leader.status':leader_lease.status,
     'leader.recover':leader_lease.recover,'leader.verify':leader_lease.verify,
     'read.consistent':consistent_read.consistent_read,'write.endpoint':consistent_read.write_endpoint}
def execute(path,r):
    with store.tx(path) as db:
        if r['action'] not in OPS:raise ValueError('unknown action')
        return OPS[r['action']](db,r)
def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['init','demo','identity','trust','handshake','wal','gateway','leader','read','write']);p.add_argument('operation',nargs='?');p.add_argument('--db',default='state.sqlite');p.add_argument('--fixture');a=p.parse_args();store.init(a.db)
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
