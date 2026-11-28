import argparse,json,sys
from . import identity,trust,admission,store,audit,image_attest,image_promote,release
OPS={'identity.bind':identity.bind,'identity.issue':identity.issue,'identity.revoke':identity.revoke,'identity.replica':identity.replica,'identity.retire':identity.retire,'trust.publish':trust.publish,'trust.ack':trust.acknowledge,'trust.coverage':trust.coverage,'trust.retry':trust.retry,'trust.withdraw':trust.withdraw,'handshake.authorize':admission.authorize,'handshake.decide':admission.handshake,'handshake.close':admission.close,'handshake.expiry':admission.expiry,'identity.audit':audit.inspect,
'image.capture':lambda db,r:{'decision':image_attest.capture(db,r['packet'],r['rows'])},
'image.manifest':image_attest.register_manifest,'image.layers':image_attest.record_layers,'image.scan':image_attest.record_scan,'image.builder':image_attest.authorize_builder,'image.builder.revoke':image_attest.revoke_builder,'image.revoke':image_attest.revoke_provenance,'image.promote':image_promote.promote_manifest,
'release.plan':release.plan,'release.checkout':release.checkout,'release.receipt':release.receipt,'release.probe':release.probe,'release.switch':release.switch,'release.halt':release.halt,'release.gate':release.gate}
def execute(path,r):
    with store.tx(path) as db:
        if r['action'] not in OPS:raise ValueError('unknown action')
        return OPS[r['action']](db,r)
def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['init','demo','identity','trust','handshake','image','release']);p.add_argument('operation',nargs='?');p.add_argument('--db',default='state.sqlite');p.add_argument('--fixture');a=p.parse_args();store.init(a.db)
    if a.command=='init':print(json.dumps({'status':'initialized'}));return
    if not a.fixture and a.command!='demo':p.error('--fixture required')
    requests=json.load(open(a.fixture or 'fixtures/demo.json',encoding='utf-8'))
    for r in requests if isinstance(requests,list) else [requests]:
        prefix=r['action'].split('.')[0]
        if a.command not in ('demo',) and not (a.command in ('image','release') and prefix in ('image','release')) and prefix!=a.command:raise ValueError('wrong subsystem command')
        for prerequisite in r.get('setup',[]):execute(a.db,prerequisite)
        print(json.dumps(execute(a.db,r),ensure_ascii=False))
if __name__=='__main__':
    try:main()
    except (ValueError,KeyError) as e:print(json.dumps({'error':str(e)}),file=sys.stderr);sys.exit(2)
