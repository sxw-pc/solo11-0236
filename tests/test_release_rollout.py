import sqlite3,tempfile,unittest
from pathlib import Path
from cloudctl import store
from cloudctl.__main__ import execute
from cloudctl.image_attest import capture,register_manifest,record_layers,record_scan,authorize_builder,revoke_builder,revoke_provenance
from cloudctl.image_promote import promote,promote_manifest,verify_digest

# Fixture scenario from the source documents: stable -> index M, with
# amd64 sub-digest A2 (fully evidenced) and arm64 sub-digest R2 whose only
# signed page is the top-level index and whose base layer came from an
# unauthorized build machine.  Old A1/R1 carry complete evidence.
def seed_artifacts(db):
    capture(db,'p-a1',[{'image':'proxy','build':'b1','builder':'ci','digest':'A1'}])
    capture(db,'p-a2',[{'image':'proxy','build':'b2','builder':'ci','digest':'A2'}])
    capture(db,'p-r1',[{'image':'proxy','build':'b1','builder':'ci','digest':'R1'}])
    # R2's own packet names the unauthorized rogue build machine.
    capture(db,'p-r2',[{'image':'proxy','build':'r2b','builder':'rogue-box','digest':'R2'}])
    capture(db,'p-r3',[{'image':'proxy','build':'b3','builder':'ci','digest':'R3'}])
    from cloudctl.image_attest import authorize_builder as ab
    ab(db,{'builder':'ci','at':1})
    # rogue-box is deliberately never authorized: R2's base layer came from it.
    for d in ('A1','A2','R1','R3'):
        record_layers(db,{'digest':d,'layers':[d+':l1',d+':l2'],'at':2})
        record_scan(db,{'digest':d,'verdict':'pass','at':3})
    record_layers(db,{'digest':'R2','layers':['R2:base-rogue','R2:l2'],'at':2})
    # R2 has no scan page: its evidence stops at the top-level signature.
    register_manifest(db,{'tag':'stable','manifest_digest':'M','arch':'amd64','sub_digest':'A2','signed_by':'top-key','at':4})
    register_manifest(db,{'tag':'stable','manifest_digest':'M','arch':'arm64','sub_digest':'R2','signed_by':'top-key','at':4})
    register_manifest(db,{'tag':'stable','manifest_digest':'M2','arch':'amd64','sub_digest':'A2','signed_by':'top-key','at':4})
    register_manifest(db,{'tag':'stable','manifest_digest':'M2','arch':'arm64','sub_digest':'R3','signed_by':'top-key','at':4})

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.dbp=str(Path(self.tmp.name)/'state.sqlite');store.init(self.dbp)
        with store.tx(self.dbp) as db:seed_artifacts(db)
    def tearDown(self):self.tmp.cleanup()
    def act(self,action,**kw):return execute(self.dbp,{'action':action,**kw})
    def dec(self,action,**kw):return self.act(action,**kw)['decision']
    def with_db(self,fn):
        with store.tx(self.dbp) as db:return fn(db)
    # --- identity/cert/bundle plumbing for the running proxy -------------
    def start_proxy(self):
        self.assertEqual(self.dec('identity.bind',id='ns/proxy',namespace='ns',service='proxy'),'bound')
        self.assertEqual(self.dec('identity.issue',id='cert-g1',identity='ns/proxy',generation=1,root='r1',not_before=0,expires=100),'issued')
        for rep in ('rep-amd1-old','rep-amd2-old','rep-arm1-old'):
            self.assertEqual(self.dec('identity.replica',id=rep,identity='ns/proxy',cert='cert-g1',active=True),'active')
        # replacement generation, new replicas per node
        self.assertEqual(self.dec('identity.issue',id='cert-g2',identity='ns/proxy',generation=2,root='r1',not_before=0,expires=100),'issued')
        for rep in ('rep-amd1-new','rep-amd2-new','rep-arm1-new'):
            self.assertEqual(self.dec('identity.replica',id=rep,identity='ns/proxy',cert='cert-g2',active=True),'active')
        self.assertEqual(self.dec('trust.publish',id='bundle',roots=['r1'],start=0,expires=100),'published')
        for rep in ('rep-amd1-old','rep-amd2-old','rep-arm1-old','rep-amd1-new','rep-amd2-new','rep-arm1-new'):
            gen=1 if rep.endswith('old') else 2
            self.assertEqual(self.dec('trust.ack',bundle='bundle',replica=rep,generation=gen,at=5),'confirmed')
        self.assertEqual(self.dec('handshake.authorize',caller='ns/caller',callee='ns/proxy',purpose='rollout-probe',expires=90,at=1),'authorized')
        self.assertEqual(self.dec('handshake.authorize',caller='ns/caller',callee='ns/proxy',purpose='new-feature',expires=90,at=1),'authorized')
        self.assertEqual(self.dec('identity.bind',id='ns/caller',namespace='ns',service='caller'),'bound')
        self.assertEqual(self.dec('identity.issue',id='cert-caller',identity='ns/caller',generation=1,root='r1',not_before=0,expires=100),'issued')
        self.assertEqual(self.dec('identity.replica',id='rep-caller',identity='ns/caller',cert='cert-caller',active=True),'active')
        self.assertEqual(self.dec('trust.ack',bundle='bundle',replica='rep-caller',generation=1,at=5),'confirmed')
    def nodes_full(self,**over):
        base=[{'node':'amd1','arch':'amd64','identity':'ns/proxy','old_replica':'rep-amd1-old','new_replica':'rep-amd1-new'},
              {'node':'amd2','arch':'amd64','identity':'ns/proxy','old_replica':'rep-amd2-old','new_replica':'rep-amd2-new'},
              {'node':'arm1','arch':'arm64','identity':'ns/proxy','old_replica':'rep-arm1-old','new_replica':'rep-arm1-new'}]
        for n in base:n.update(over.get(n['node'],{}))
        return base
    def plan(self,batch='rel-1',mode='partial',manifest='M'):
        nodes=self.nodes_full(arm1={'old_digest':'R1'}) if mode=='partial' else self.nodes_full()
        return self.act('release.plan',batch=batch,tag='stable',manifest_digest=manifest,mode=mode,at=6,nodes=nodes)
    def probe(self,node,new_rep,hid):
        return self.dec('handshake.decide',id=hid,caller_cert='cert-caller',callee_cert='cert-g2',caller_replica='rep-caller',callee_replica=new_rep,bundle='bundle',purpose='rollout-probe',at=10)
    def roll_node(self,node,arch,digest,new_rep,gen=2,batch='rel-1'):
        self.assertEqual(self.dec('release.checkout',batch=batch,node=node,arch=arch,digest=digest,startup_id=batch+':'+node+':start-1',at=11),'checked_out')
        self.assertEqual(self.dec('release.receipt',batch=batch,node=node,arch=arch,digest=digest,startup_id=batch+':'+node+':start-1',identity='ns/proxy',replica=new_rep,generation=gen,at=12),'confirmed')
        self.assertEqual(self.probe(node,new_rep,'probe-'+node+'-'+batch),'allowed')
        self.assertEqual(self.dec('release.probe',batch=batch,node=node,handshake='probe-'+node+'-'+batch,at=13),'probed')
    def test_top_level_signature_does_not_vouch_for_subimage(self):
        with store.tx(self.dbp) as db:
            ok,reasons=verify_digest(db,'A2');self.assertTrue(ok);self.assertEqual(reasons,[])
            ok,reasons=verify_digest(db,'R2');self.assertFalse(ok)
            self.assertIn('scan_missing',reasons);self.assertTrue(any(x.startswith('builder_unauthorized') and 'rogue-box' in x for x in reasons))
            ok,reasons=verify_digest(db,'ghost');self.assertFalse(ok);self.assertEqual(reasons,['provenance_missing'])
            res=promote_manifest(db,{'tag':'stable','manifest_digest':'M','at':5})
            self.assertEqual(res['decision'],'partial')
            self.assertTrue(res['evidence']['arches']['amd64']['verified'])
            self.assertFalse(res['evidence']['arches']['arm64']['verified'])
            # legacy provisional promote still takes the last matching packet row
            self.assertEqual(promote(db,'proxy')['build'],'b3')
        self.assertEqual(self.dec('image.promote',tag='stable',manifest_digest='M',at=5),'partial')
        self.assertEqual(self.dec('image.promote',tag='stable',manifest_digest='M',at=5),'partial')
    def test_full_rollout_blocks_on_r2_partial_rollout_keeps_r1(self):
        self.start_proxy()
        full=self.act('release.plan',batch='rel-1',tag='stable',manifest_digest='M',mode='full',at=6,nodes=self.nodes_full())
        self.assertEqual(full['decision'],'blocked')
        self.assertEqual(full['evidence']['blocked'][0]['node'],'arm1')
        self.assertIn('arch_unverified:arm64',full['evidence']['blocked'][0]['reasons'])
        nodes=self.nodes_full(arm1={'old_digest':'R1'})
        plan=self.act('release.plan',batch='rel-1',tag='stable',manifest_digest='M',mode='partial',at=6,nodes=nodes)
        self.assertEqual(plan['decision'],'planned')
        rows={n['node']:n for n in plan['evidence']['nodes']}
        self.assertEqual(rows['amd1']['target_digest'],'A2');self.assertFalse(rows['amd1']['retained'])
        self.assertEqual(rows['arm1']['target_digest'],'R1');self.assertTrue(rows['arm1']['retained'])
        self.assertEqual(rows['arm1']['status'],'retained')
        # idempotent replanning under the same batch
        self.assertEqual(self.dec('release.plan',batch='rel-1',tag='stable',manifest_digest='M',mode='partial',at=6,nodes=nodes),'idempotent')
        # retained arm node cannot check out / receive receipts / switch
        self.assertEqual(self.dec('release.checkout',batch='rel-1',node='arm1',arch='arm64',digest='R1',startup_id='rel-1:arm1:start-1',at=7),'retained_node')
        self.assertEqual(self.dec('release.switch',batch='rel-1',node='arm1',at=9),'retained_node')
        # wrong arch pull on an amd node is rejected before anything runs
        bad=self.act('release.checkout',batch='rel-1',node='amd1',arch='arm64',digest='R2',startup_id='rel-1:amd1:start-1',at=8)
        self.assertEqual(bad['decision'],'pull_mismatch')
        self.roll_node('amd1','amd64','A2','rep-amd1-new')
        # switch only after receipt + independent probe
        self.assertEqual(self.dec('release.switch',batch='rel-1',node='amd1',at=14),'switched')
        self.assertFalse(self.with_db(lambda db:store.one(db,'SELECT active FROM replicas WHERE id=?',('rep-amd1-old',)))['active'])
        self.assertTrue(self.with_db(lambda db:store.one(db,'SELECT active FROM replicas WHERE id=?',('rep-amd1-new',)))['active'])
        self.assertTrue(self.with_db(lambda db:store.one(db,'SELECT active FROM replicas WHERE id=?',('rep-arm1-old',)))['active'])
    def test_arm_node_cannot_switch_without_receipt_then_completes(self):
        self.start_proxy()
        self.dec('release.plan',batch='rel-1',tag='stable',manifest_digest='M',mode='partial',at=6,nodes=self.nodes_full(arm1={'old_digest':'R1'}))
        self.assertEqual(self.dec('release.switch',batch='rel-1',node='amd2',at=9),'receipt_missing')
        self.dec('release.checkout',batch='rel-1',node='amd2',arch='amd64',digest='A2',startup_id='rel-1:amd2:start-1',at=11)
        self.assertEqual(self.dec('release.switch',batch='rel-1',node='amd2',at=11),'receipt_missing')
        self.dec('release.receipt',batch='rel-1',node='amd2',arch='amd64',digest='A2',startup_id='rel-1:amd2:start-1',identity='ns/proxy',replica='rep-amd2-new',generation=2,at=12)
        self.assertEqual(self.dec('release.switch',batch='rel-1',node='amd2',at=12),'probe_missing')
        self.assertEqual(self.probe('amd2','rep-amd2-new','probe-amd2'),'allowed')
        self.assertEqual(self.dec('release.probe',batch='rel-1',node='amd2',handshake='probe-amd2',at=13),'probed')
        self.assertEqual(self.dec('release.switch',batch='rel-1',node='amd2',at=14),'switched')
    def test_failed_or_denied_probe_blocks_old_replica_exit(self):
        self.start_proxy()
        self.dec('release.plan',batch='rel-1',tag='stable',manifest_digest='M',mode='partial',at=6,nodes=self.nodes_full(arm1={'old_digest':'R1'}))
        self.dec('release.checkout',batch='rel-1',node='amd1',arch='amd64',digest='A2',startup_id='rel-1:amd1:start-1',at=11)
        self.dec('release.receipt',batch='rel-1',node='amd1',arch='amd64',digest='A2',startup_id='rel-1:amd1:start-1',identity='ns/proxy',replica='rep-amd1-new',generation=2,at=12)
        # probe landing on the still-running old replica does not count
        self.assertEqual(self.dec('handshake.decide',id='probe-wrong',caller_cert='cert-caller',callee_cert='cert-g1',caller_replica='rep-caller',callee_replica='rep-amd1-old',bundle='bundle',purpose='rollout-probe',at=10),'allowed')
        self.assertEqual(self.dec('release.probe',batch='rel-1',node='amd1',handshake='probe-wrong',at=13),'probe_failed')
        self.assertEqual(self.dec('release.switch',batch='rel-1',node='amd1',at=14),'probe_missing')
        self.assertTrue(self.with_db(lambda db:store.one(db,'SELECT active FROM replicas WHERE id=?',('rep-amd1-old',)))['active'])
        self.assertEqual(self.probe('amd1','rep-amd1-new','probe-good'),'allowed')
        self.assertEqual(self.dec('release.probe',batch='rel-1',node='amd1',handshake='probe-good',at=13),'probed')
        self.assertEqual(self.dec('release.switch',batch='rel-1',node='amd1',at=14),'switched')
    def test_power_loss_keeps_batch_and_single_startup_identity(self):
        self.start_proxy()
        self.dec('release.plan',batch='rel-1',tag='stable',manifest_digest='M',mode='partial',at=6,nodes=self.nodes_full(arm1={'old_digest':'R1'}))
        sid='rel-1:amd1:start-1'
        self.assertEqual(self.dec('release.checkout',batch='rel-1',node='amd1',arch='amd64',digest='A2',startup_id=sid,at=11),'checked_out')
        # power-loss retry: same batch, same startup id, same bytes -> idempotent
        self.assertEqual(self.dec('release.checkout',batch='rel-1',node='amd1',arch='amd64',digest='A2',startup_id=sid,at=11),'idempotent')
        # a fresh startup identity on the same node is refused
        self.assertEqual(self.dec('release.checkout',batch='rel-1',node='amd1',arch='amd64',digest='A2',startup_id='rel-1:amd1:start-2',at=11),'startup_identity_mismatch')
        self.assertEqual(self.dec('release.receipt',batch='rel-1',node='amd1',arch='amd64',digest='A2',startup_id=sid,identity='ns/proxy',replica='rep-amd1-new',generation=2,at=12),'confirmed')
        self.assertEqual(self.dec('release.receipt',batch='rel-1',node='amd1',arch='amd64',digest='A2',startup_id=sid,identity='ns/proxy',replica='rep-amd1-new',generation=2,at=12),'idempotent')
        self.assertEqual(self.dec('release.receipt',batch='rel-1',node='amd1',arch='amd64',digest='A2',startup_id=sid,identity='ns/proxy',replica='rep-amd1-new',generation=1,at=12),'receipt_conflict')
    def test_halt_pauses_unfinished_nodes_and_recalls_checked_out(self):
        self.start_proxy()
        nodes=self.nodes_full(arm1={'old_digest':'R1'})
        nodes.append({'node':'amd3','arch':'amd64','identity':'ns/proxy','old_replica':'rep-amd1-old','new_replica':'rep-amd1-new'})
        self.dec('release.plan',batch='rel-1',tag='stable',manifest_digest='M',mode='partial',at=6,nodes=nodes)
        # an old open call is live on amd1 before cutover
        self.dec('handshake.authorize',caller='ns/caller',callee='ns/proxy',purpose='read',expires=90,at=1)
        self.assertEqual(self.dec('handshake.decide',id='live-call',caller_cert='cert-caller',callee_cert='cert-g2',caller_replica='rep-caller',callee_replica='rep-amd1-new',bundle='bundle',purpose='read',at=9),'allowed')
        self.roll_node('amd1','amd64','A2','rep-amd1-new')
        self.assertEqual(self.dec('release.switch',batch='rel-1',node='amd1',at=14),'switched')
        # amd2 has checked out but not yet switched; arm1 retained; no node touched beyond
        self.dec('release.checkout',batch='rel-1',node='amd2',arch='amd64',digest='A2',startup_id='rel-1:amd2:start-1',at=11)
        halt=self.act('release.halt',batch='rel-1',reason='R2_signature_invalid',at=15)
        self.assertEqual(halt['decision'],'halted')
        self.assertEqual(halt['evidence']['paused'],['amd3'])
        self.assertEqual(halt['evidence']['recalls'],['amd2'])
        self.assertEqual(self.with_db(lambda db:store.one(db,'SELECT status FROM release_orders WHERE batch=? AND node=?',('rel-1','amd3')))['status'],'paused')
        self.assertIsNone(self.with_db(lambda db:store.one(db,'SELECT * FROM release_checkouts WHERE batch=? AND node=?',('rel-1','amd3'))))
        self.assertIsNone(self.with_db(lambda db:store.one(db,'SELECT * FROM release_recalls WHERE batch=? AND node=?',('rel-1','amd1'))))
        self.assertEqual(self.with_db(lambda db:store.one(db,'SELECT status FROM release_orders WHERE batch=? AND node=?',('rel-1','amd2')))['status'],'checked_out')
        self.assertEqual(self.with_db(lambda db:store.one(db,'SELECT status FROM release_recalls WHERE batch=? AND node=?',('rel-1','amd2')))['status'],'due')
        # halted batch refuses new checkout/switch; a checked-out node may still
        # file its runtime receipt, but cannot probe or cut over
        self.assertEqual(self.dec('release.checkout',batch='rel-1',node='amd2',arch='amd64',digest='A2',startup_id='rel-1:amd2:start-1',at=16),'idempotent')
        self.assertEqual(self.dec('release.receipt',batch='rel-1',node='amd2',arch='amd64',digest='A2',startup_id='rel-1:amd2:start-1',identity='ns/proxy',replica='rep-amd2-new',generation=2,at=16),'confirmed')
        self.assertEqual(self.probe('amd2','rep-amd2-new','probe-amd2'),'allowed')
        self.assertEqual(self.dec('release.probe',batch='rel-1',node='amd2',handshake='probe-amd2',at=16),'batch_halted')
        self.assertEqual(self.dec('release.switch',batch='rel-1',node='amd2',at=16),'batch_halted')
        # old call survives; checked-out manifest is untouched
        self.assertEqual(self.with_db(lambda db:store.one(db,'SELECT status FROM handshakes WHERE id=?',('live-call',)))['status'],'open')
        self.assertEqual(self.with_db(lambda db:store.one(db,'SELECT digest FROM release_checkouts WHERE batch=? AND node=?',('rel-1','amd2')))['digest'],'A2')
        self.assertEqual(self.dec('release.halt',batch='rel-1',reason='x',at=17),'idempotent')
    def test_rebuild_r3_full_rollout_reaches_a2_r3_and_discharges_recall(self):
        self.start_proxy()
        self.plan()
        self.dec('release.checkout',batch='rel-1',node='amd2',arch='amd64',digest='A2',startup_id='rel-1:amd2:start-1',at=11)
        self.dec('release.halt',batch='rel-1',reason='R2_signature_invalid',at=15)
        # authorized rebuild of arm64 as R3, fully re-evidenced and re-scanned
        self.assertEqual(self.dec('image.promote',tag='stable',manifest_digest='M2',at=16),'verified')
        plan=self.plan(batch='rel-2',mode='full',manifest='M2')
        self.assertEqual(plan['decision'],'planned')
        self.assertEqual({n['node']:n['target_digest'] for n in plan['evidence']['nodes']},{'amd1':'A2','amd2':'A2','arm1':'R3'})
        for node,arch,digest,rep in (('amd1','amd64','A2','rep-amd1-new'),('amd2','amd64','A2','rep-amd2-new'),('arm1','arm64','R3','rep-arm1-new')):
            self.roll_node(node,arch,digest,rep,batch='rel-2')
            self.assertEqual(self.dec('release.switch',batch='rel-2',node=node,at=14),'switched')
        # recall obligation from the halted batch is closed without erasing it
        self.assertEqual(self.with_db(lambda db:store.one(db,'SELECT status FROM release_recalls WHERE batch=? AND node=?',('rel-1','amd2')))['status'],'discharged')
        running=self.with_db(lambda db:store.many(db,"SELECT node,digest FROM release_receipts WHERE batch='rel-2' AND status='confirmed' ORDER BY node"))
        self.assertEqual([(x['node'],x['digest']) for x in running],[('amd1','A2'),('amd2','A2'),('arm1','R3')])
    def test_midrollout_provenance_revocation_blocks_replanning_and_halts(self):
        self.start_proxy()
        self.dec('release.plan',batch='rel-1',tag='stable',manifest_digest='M',mode='partial',at=6,nodes=self.nodes_full(arm1={'old_digest':'R1'}))
        self.roll_node('amd1','amd64','A2','rep-amd1-new')
        # attestation for A2 is withdrawn while the rollout is in flight
        self.assertEqual(self.dec('image.revoke',subject='A2',kind='digest',at=20,reason='attestation_withdrawn'),'revoked')
        with store.tx(self.dbp) as db:
            ok,reasons=verify_digest(db,'A2');self.assertFalse(ok);self.assertIn('provenance_revoked',reasons)
        # a new batch can no longer pin A2 even though its packets are still on disk
        blocked=self.act('release.plan',batch='rel-x',tag='stable',manifest_digest='M',mode='partial',at=21,nodes=self.nodes_full(arm1={'old_digest':'R1'}))
        self.assertEqual(blocked['decision'],'blocked')
        # existing batch evidence is immutable; halt records the obligation
        self.assertEqual(self.dec('release.halt',batch='rel-1',reason='A2_revoked',at=22),'halted')
        self.assertEqual(self.with_db(lambda db:store.one(db,'SELECT digest FROM release_checkouts WHERE batch=? AND node=?',('rel-1','amd1')))['digest'],'A2')
        self.assertEqual(self.dec('image.revoke',subject='A2',kind='digest',at=20,reason='x'),'idempotent')
    def test_feature_gate_limits_new_feature_to_verified_a2_replicas(self):
        self.start_proxy()
        self.assertEqual(self.dec('release.gate',purpose='new-feature',digests=['A2'],at=6),'gated')
        self.dec('release.plan',batch='rel-1',tag='stable',manifest_digest='M',mode='partial',at=6,nodes=self.nodes_full(arm1={'old_digest':'R1'}))
        # no receipt yet -> gated purpose is blocked even for a healthy replica
        self.assertEqual(self.dec('handshake.decide',id='nf-amd-before',caller_cert='cert-caller',callee_cert='cert-g2',caller_replica='rep-caller',callee_replica='rep-amd1-new',bundle='bundle',purpose='new-feature',at=9),'feature_gate_blocked')
        self.roll_node('amd1','amd64','A2','rep-amd1-new')
        # amd1 now runs the verified A2 bytes: gated calls admitted
        self.assertEqual(self.dec('handshake.decide',id='nf-amd-after',caller_cert='cert-caller',callee_cert='cert-g2',caller_replica='rep-caller',callee_replica='rep-amd1-new',bundle='bundle',purpose='new-feature',at=12),'allowed')
        # arm1 is retained on R1 and never gets an A2 receipt: still blocked
        self.assertEqual(self.dec('handshake.decide',id='nf-arm',caller_cert='cert-caller',callee_cert='cert-g1',caller_replica='rep-caller',callee_replica='rep-arm1-old',bundle='bundle',purpose='new-feature',at=12),'feature_gate_blocked')
        # ungated ordinary traffic to the retained R1 replica is unaffected
        self.dec('handshake.authorize',caller='ns/caller',callee='ns/proxy',purpose='read',expires=90,at=1)
        self.assertEqual(self.dec('handshake.decide',id='read-arm',caller_cert='cert-caller',callee_cert='cert-g1',caller_replica='rep-caller',callee_replica='rep-arm1-old',bundle='bundle',purpose='read',at=12),'allowed')
    def test_scan_failure_and_builder_revocation_reject_subimage(self):
        with store.tx(self.dbp) as db:
            capture(db,'p-s1',[{'image':'proxy','build':'b9','builder':'ci','digest':'S1'}])
            record_layers(db,{'digest':'S1','layers':['S1:l1'],'at':8})
            record_scan(db,{'digest':'S1','verdict':'fail','at':9})
            ok,reasons=verify_digest(db,'S1');self.assertFalse(ok);self.assertIn('scan_failed',reasons)
            revoke_builder(db,{'builder':'ci','at':10,'reason':'machine_moved'})
            ok,reasons=verify_digest(db,'A2');self.assertFalse(ok)
            self.assertTrue(any(x.startswith('builder_unauthorized') for x in reasons))
    def test_manifest_conflicts_and_unknown_manifest_are_refused(self):
        with store.tx(self.dbp) as db:
            res=register_manifest(db,{'tag':'stable','manifest_digest':'M','arch':'arm64','sub_digest':'R9','signed_by':'top-key','at':4})
            self.assertEqual(res['decision'],'manifest_conflict')
            res=register_manifest(db,{'tag':'stable','manifest_digest':'M','arch':'arm64','sub_digest':'R2','signed_by':'top-key','at':4})
            self.assertEqual(res['decision'],'idempotent')
        self.assertEqual(self.dec('release.plan',batch='rel-z',tag='stable',manifest_digest='nope',mode='full',at=6,nodes=self.nodes_full()),'manifest_unknown')

if __name__=='__main__':unittest.main()
