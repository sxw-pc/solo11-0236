import tempfile, unittest
from pathlib import Path
from cloudctl import store
from cloudctl.__main__ import execute


class HardwareRMABase(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.db=str(Path(self.tmp.name)/'hardware.sqlite')
        store.init(self.db)
    def tearDown(self):
        self.tmp.cleanup()
    def call(self,action,**kw):
        return execute(self.db,{'action':action,**kw})
    def act(self,action,**kw):
        return self.call(action,**kw)['decision']
    def rows(self,q,a=()):
        with store.tx(self.db) as db:
            return store.many(db,q,a)
    def row(self,q,a=()):
        with store.tx(self.db) as db:
            return store.one(db,q,a)

    def setup_trust_and_calls(self):
        # Two distinct service identities/replicas.  r1 is laundered by an
        # identity.replica rewrite; r2 still serves the M7 second generation.
        for ident in ('ns/r1','ns/r2','ns/bak'):
            service='gateway'
            self.assertEqual(self.act('identity.bind',id=ident,namespace='ns',service=service),'bound')
        certs=[
            ('c-r1-g1','ns/r1',1,'rk7',0),('c-r1-g2','ns/r1',2,'rk8',8),
            ('c-r2-g1','ns/r2',1,'rk7',0),('c-r2-g2','ns/r2',2,'rk7',7),
            ('c-bak-g1','ns/bak',1,'rkb',12),
        ]
        for cid,ident,gen,root,nb in certs:
            serial='M7' if root=='rk7' else ('M8' if root=='rk8' else 'MB')
            fp='fp-'+serial
            self.assertEqual(self.act('identity.issue',id=cid,identity=ident,generation=gen,
                                      root=root,not_before=nb,expires=200,at=nb,
                                      module=serial,key_fingerprint=fp),'issued')
        self.assertEqual(self.act('identity.replica',id='r1',identity='ns/r1',cert='c-r1-g1',
                                  active=True,at=0,module='M7',chassis='机箱一'),'active')
        self.assertEqual(self.act('trust.publish',id='bundle',roots=['rk7','rk8','rkb'],start=0,expires=200),'published')
        self.assertEqual(self.act('trust.ack',bundle='bundle',replica='r1',generation=1,at=1),'confirmed')
        # Minute 8: M7 moves to chassis two/r2; M8 is installed in chassis one/r1.
        self.assertEqual(self.act('hardware.move',id='move-m7',serial='M7',at=8,
                                  from_chassis='机箱一',to_chassis='机箱二',to_replica='r2'),'moved')
        self.assertEqual(self.act('hardware.install',id='install-m8',serial='M8',at=8,
                                  chassis='机箱一',replica='r1',clean_source=True),'installed')
        self.assertEqual(self.act('identity.replica',id='r2',identity='ns/r2',cert='c-r2-g2',
                                  active=True,at=8,module='M7',chassis='机箱二'),'active')
        self.assertEqual(self.act('identity.replica',id='r1',identity='ns/r1',cert='c-r1-g2',
                                  active=True,at=8,module='M8',chassis='机箱一'),'active')
        self.assertEqual(self.act('identity.replica',id='bak',identity='ns/bak',cert='c-bak-g1',
                                  active=True,at=12,module='MB',chassis='机箱三'),'active')
        for rep,gen,at in [('r2',2,8),('r1',2,8),('bak',1,13)]:
            self.assertEqual(self.act('trust.ack',bundle='bundle',replica=rep,generation=gen,at=at),'confirmed')
        self.assertEqual(self.act('handshake.authorize',caller='ns/r1',callee='ns/r2',
                                  purpose='read',expires=80,at=1),'authorized')
        self.assertEqual(self.act('handshake.decide',id='open-call',caller_cert='c-r1-g2',
                                  callee_cert='c-r2-g2',caller_replica='r1',callee_replica='r2',
                                  bundle='bundle',purpose='read',at=9),'allowed')

    def setup_recall_and_evidence(self):
        self.assertEqual(self.act('hardware.announce',id='B7',vendor='Acme HSM',model='HSM-X',
                                  batch_code='LOT7',signed_by='vendor-key',signature_valid=True,
                                  announced_at=10,warranty_until=365),'recall_announced')
        # Registration is naturally idempotent under repeated scans.
        self.assertIn(self.act('hardware.register',id='m7-reg',serial='M7',model='HSM-X',
                               batch='B7',warranty_until=365,key_fingerprint='fp-M7'),
                      ('module_registered','idempotent'))
        self.assertEqual(self.act('hardware.nameplate',id='np7',serial='M7',model='HSM-X',
                                  batch_code='LOT7',chassis='机箱二',at=2,witness='inspector'),'nameplate_recorded')
        self.assertEqual(self.act('hardware.open',id='open1',chassis='机箱一',at=0,
                                  witness='ops',seal_before='S1',authorized=True),'opening_recorded')
        self.assertEqual(self.act('hardware.open',id='open2',chassis='机箱二',at=8,
                                  witness='ops',seal_before='S2',authorized=True),'opening_recorded')
        # The stale asset page still locates M7 in chassis one; a second asset
        # system has its own copy.  Neither creates a second physical module.
        self.assertEqual(self.act('hardware.asset',id='asset-stale',source_system='legacy-export',
                                  asset_key='page-1',chassis='机箱一',serial='M7',observed_at=10),'asset_recorded')
        self.assertEqual(self.act('hardware.asset',id='asset-cmdb',source_system='cmdb',
                                  asset_key='hw-7',chassis='机箱二',serial='M7',observed_at=9),'asset_recorded')
        self.assertEqual(self.act('hardware.confirm_recall',batch='B7',serial='M7'),'recall_confirmed')


class HardwareRMAScenarioTests(HardwareRMABase):
    def test_cross_chassis_truth_quarantines_every_possible_machine(self):
        self.setup_trust_and_calls()
        self.setup_recall_and_evidence()
        q=self.call('hardware.quarantine',serial='M7',at=11)
        self.assertEqual(q['decision'],'quarantined')
        loc=self.call('hardware.locate',serial='M7')
        self.assertEqual(loc['decision'],'location_reconciled')
        self.assertEqual(loc['evidence']['actual_chassis'],'机箱二')
        self.assertIn('asset-stale',loc['evidence']['stale_asset_records'])
        self.assertEqual(q['evidence']['chassis'],['机箱一','机箱二'])
        self.assertIn('r2',q['evidence']['replicas'])
        # The stale chassis-one row is held even though M8/r1 now lives there.
        denied=self.call('handshake.decide',id='late-call',caller_cert='c-r1-g2',callee_cert='c-r2-g2',
                         caller_replica='r1',callee_replica='r2',bundle='bundle',purpose='read',at=11)
        self.assertNotEqual(denied['decision'],'allowed')
        cov=self.call('trust.coverage',bundle='bundle',service='gateway',at=11)
        self.assertEqual(cov['decision'],'partial')
        self.assertIn('r1',cov['evidence']['missing'])
        self.assertIn('r2',cov['evidence']['missing'])
        # The original allowed call is still explicitly open and must be closed.
        self.assertEqual(self.row("SELECT status FROM handshakes WHERE id='open-call'")['status'],'open')

    def test_onsite_destroy_revokes_all_module_certs_settles_credit_and_restore(self):
        self.setup_trust_and_calls()
        self.setup_recall_and_evidence()
        self.act('hardware.quarantine',serial='M7',at=11)
        self.assertEqual(self.act('hardware.challenge',id='ch7',serial='M7',nonce='n7',
                                  response='hw-response:n7:M7',at=11),'challenge_verified')
        self.assertEqual(self.act('purchase.receive',id='po-m8',po='PO8',part_serial='M8',
                                  amount=1000,received_at=11,accepted=True),'part_received')
        self.assertEqual(self.act('hardware.challenge',id='ch8',serial='M8',valid=True,
                                  key_fingerprint='fp-M8',at=11),'challenge_verified')
        self.assertEqual(self.act('hardware.release',chassis='机箱一',at=11,clean_verified=True),'released')
        self.assertEqual(self.act('handshake.close',id='open-call'),'closed')
        self.assertEqual(self.act('identity.replica',id='r2',identity='ns/r2',cert='c-r2-g2',
                                  active=False,at=12,module='M7',chassis='机箱二'),'stopped')
        rev=self.call('hardware.revoke_keys',serial='M7')
        self.assertEqual(rev['decision'],'certificates_revoked')
        self.assertEqual(set(rev['evidence']['revoked']),{'c-r1-g1','c-r2-g1','c-r2-g2'})
        self.assertEqual(self.row("SELECT status FROM certificates WHERE id='c-r1-g2'")['status'],'active')
        # Bag and weight before transport; duplicate scans are idempotent.
        self.assertEqual(self.act('hardware.bag',id='bag7',seal='SEAL7',serial='M7',
                                  weight=1.2,expected_weight=1.2,at=11),'sealed')
        self.assertEqual(self.act('hardware.weigh',bag='bag7',weight=1.205,at=12),'weight_verified')
        self.assertEqual(self.act('hardware.destroy',id='destroy7',serial='M7',at=13,
                                  witness='vendor-engineer+operator',method='witnessed-crushing'),'destroyed')
        # One unique claim only, even if another asset copy requests a replacement.
        self.assertEqual(self.act('rma.submit',id='RMA7',serial='M7',batch='B7',path='onsite_destroy',
                                  amount=1000,at=12,replacement_part='M8'),'claim_submitted')
        dup=self.call('rma.submit',id='RMA7-second-system',serial='M7',path='onsite_destroy',at=12)
        self.assertEqual(dup['decision'],'claim_duplicate')
        self.assertEqual(len(self.rows('SELECT * FROM rma_claims WHERE module_serial=?',('M7',))),1)
        self.assertEqual(self.act('vendor.receive',id='vr7',claim='RMA7',package_type='module_bag',
                                  seal='SEAL7',received_serial='M7',weight=1.2,at=14),'vendor_received')
        # Credit is late: physical replacement exists, but settlement cannot invent it.
        self.assertEqual(self.act('rma.settle',claim='RMA7',at=15),'credit_pending')
        self.assertEqual(self.act('finance.confirm_credit',id='cn7',claim='RMA7',credit_note='CN7',
                                  amount=1000,at=16),'credit_confirmed')
        self.assertEqual(self.act('rma.settle',claim='RMA7',at=16),'settled')
        # Customer service returns only inside an approved window with separate
        # call closure, target cert and backup bundle receipt evidence.
        self.assertEqual(self.act('hardware.window',id='MW1',service='gateway',start=15,end=30,
                                  approved=True,approver='change-board'),'maintenance_window_recorded')
        self.assertEqual(self.act('trust.ack',bundle='bundle',replica='r1',generation=2,at=16),'confirmed')
        rec=self.call('service.restore',id='recovery1',service='gateway',replica='r1',backup_replica='bak',
                      bundle='bundle',backup_bundle='bundle',window='MW1',at=20,
                      closed_calls=['open-call'],backup_cert='c-bak-g1',backup_receipt='bundle/bak/1')
        self.assertEqual(rec['decision'],'service_restored')
        completion=self.call('rma.complete',claim='RMA7',recovery='recovery1',at=21,require_backup=True)
        self.assertEqual(completion['decision'],'completed')
        self.assertEqual(rec['evidence']['closed_calls'],['open-call'])
        self.assertEqual(rec['evidence']['backup_cert'],'c-bak-g1')
        self.assertEqual(rec['evidence']['backup_receipt'],'bundle/bak/1')
        audit=self.call('identity.audit',service='gateway',at=21)
        self.assertEqual(audit['decision'],'healthy')

    def test_bag_swap_and_vendor_rejection_block_completion(self):
        self.setup_trust_and_calls()
        self.setup_recall_and_evidence()
        self.act('hardware.quarantine',serial='M7',at=11)
        self.act('hardware.challenge',id='ch7',serial='M7',valid=True,at=11)
        self.act('hardware.bag',id='bag7',seal='SEAL7',serial='M7',weight=1.2,expected_weight=1.2,at=11)
        self.act('rma.submit',id='RMA7',serial='M7',path='onsite_destroy',at=12)
        rejected=self.call('vendor.receive',id='vr-bad',claim='RMA7',package_type='module_bag',
                           seal='SEAL7',received_serial='FAKE-9',weight=3.4,at=14)
        self.assertEqual(rejected['decision'],'vendor_rejected')
        self.assertEqual(rejected['evidence']['reason'],'serial_mismatch_bag_swap')
        self.assertNotEqual(self.act('rma.settle',claim='RMA7',at=15),'settled')
        # A sent claim cannot be rewritten into a second claim; correction is appended.
        self.assertEqual(self.act('rma.correct',claim='RMA7',correction_id='corr1',
                                  note='vendor holds swapped bag; courier investigation',at=15),'correction_appended')
        self.assertEqual(len(self.rows('SELECT * FROM rma_claims')),1)
        self.assertGreaterEqual(len(self.rows('SELECT * FROM rma_revisions WHERE claim_id=?',('RMA7',))),2)

    def test_whole_unit_path_requires_whole_receipt_and_disassembly(self):
        self.setup_trust_and_calls()
        self.setup_recall_and_evidence()
        self.act('hardware.quarantine',serial='M7',at=11)
        self.act('hardware.challenge',id='ch7',serial='M7',valid=True,at=11)
        self.assertEqual(self.act('rma.submit',id='RMA-W',serial='M7',whole_serial='CH2',
                                  chassis='机箱二',path='whole_return',amount=2000,at=12,
                                  replacement_part='CH-NEW'),'claim_submitted')
        # Whole machine is sealed and shipped; late courier signature is a replay.
        self.assertEqual(self.act('hardware.bag',id='case-seal',seal='CASE-SEAL',serial='M7',
                                  chassis='机箱二',weight=18.0,expected_weight=18.0,at=12),'sealed')
        self.assertEqual(self.act('hardware.ship',id='ship1',tracking='TRACK1',serial='M7',at=12),'custody_recorded')
        self.assertEqual(self.act('hardware.sign',tracking='TRACK1',at=14),'custody_recorded')
        self.assertEqual(self.act('hardware.sign',tracking='TRACK1',at=14),'idempotent')
        # Local destruction is the wrong path and cannot stand in for vendor receipt.
        blocked=self.call('hardware.destroy',id='destroy-wrong',serial='M7',path='whole_return',at=15)
        self.assertEqual(blocked['decision'],'wrong_disposition')
        recv=self.call('vendor.receive',id='vrew',claim='RMA-W',package_type='whole_unit',
                       whole_serial='CH2',chassis='机箱二',seal='CASE-SEAL',received_serial='CH2',
                       weight=18.0,at=16)
        self.assertEqual(recv['decision'],'vendor_received')
        dis=self.call('vendor.disassemble',id='dis1',claim='RMA-W',receipt='vrew',
                      chassis='机箱二',module_serial='M7',found_serial='M7',at=17)
        self.assertEqual(dis['decision'],'disassembled')
        self.assertEqual(self.act('purchase.receive',id='po-new',claim='RMA-W',part_serial='CH-NEW',
                                   kind='backup_appliance',amount=2000,received_at=17),'part_received')
        self.assertEqual(self.act('finance.confirm_credit',id='cnw',claim='RMA-W',amount=2000,at=18),'credit_confirmed')
        self.assertEqual(self.act('rma.settle',claim='RMA-W',at=18),'settled')
        state=self.call('rma.status',claim='RMA-W')
        self.assertTrue(state['evidence']['checks']['vendor_disassembly'])
        self.assertTrue(state['evidence']['checks']['no_fake_local_destruction'])
        self.assertFalse(state['evidence']['checks'].get('no_fake_whole_unit_receipt', True) is False)

    def test_expired_warranty_and_lost_custody_do_not_become_claims_or_destruction(self):
        self.setup_trust_and_calls()
        self.setup_recall_and_evidence()
        expired=self.call('rma.submit',id='RMA-EXPIRED',serial='M7',path='onsite_destroy',
                          warranty_until=5,at=10)
        self.assertEqual(expired['decision'],'warranty_expired')
        self.assertEqual(len(self.rows('SELECT * FROM rma_claims')),0)
        self.act('hardware.challenge',id='ch7',serial='M7',valid=True,at=11)
        self.act('hardware.custody',id='lost7',serial='M7',kind='lost',at=12,location='courier-hub')
        blocked=self.call('hardware.destroy',id='destroy-lost',serial='M7',witness='w',method='crush',at=13)
        self.assertEqual(blocked['decision'],'destruction_blocked')
        self.assertIn('custody_continuous',blocked['evidence']['missing'])

    def test_logical_rewrite_with_reused_recalled_key_still_blocked(self):
        self.setup_trust_and_calls()
        self.setup_recall_and_evidence()
        self.act('hardware.quarantine',serial='M7',at=11)
        self.assertEqual(self.act('identity.issue',id='c-r1-g3',identity='ns/r1',generation=3,
                                  root='rk7',not_before=11,expires=200,module='M8-NEW-BOX',
                                  key_fingerprint='fp-M7'),'issued')
        self.assertEqual(self.act('identity.replica',id='r1',identity='ns/r1',cert='c-r1-g3',
                                  active=True,at=11,module='M8-NEW-BOX',chassis='机箱一'),'active')
        ack=self.call('trust.ack',bundle='bundle',replica='r1',generation=3,at=12)
        self.assertEqual(ack['decision'],'recalled_key_reuse')
        denied=self.call('handshake.decide',id='key-reuse-call',caller_cert='c-r1-g3',
                         callee_cert='c-r2-g2',caller_replica='r1',callee_replica='r2',
                         bundle='bundle',purpose='read',at=12)
        self.assertNotEqual(denied['decision'],'allowed')

    def test_broken_seal_is_explicit_state_and_locks_destruction(self):
        self.setup_trust_and_calls()
        self.setup_recall_and_evidence()
        self.act('hardware.challenge',id='ch7',serial='M7',valid=True,at=11)
        self.act('hardware.bag',id='bag7',seal='SEAL7',serial='M7',weight=1.2,at=11)
        broken=self.call('hardware.break_seal',bag='bag7',at=12,reason='seal cut at hub')
        self.assertEqual(broken['decision'],'seal_broken')
        again=self.call('hardware.break_seal',bag='bag7',at=12)
        self.assertEqual(again['decision'],'seal_broken')
        self.assertEqual(self.row("SELECT status,swapped FROM hw_bags WHERE id='bag7'")['status'],'broken')
        blocked=self.call('hardware.destroy',id='destroy-broken',serial='M7',witness='w',method='crush',at=13)
        self.assertEqual(blocked['decision'],'destruction_blocked')

    def test_sent_claim_facts_are_locked_and_changes_require_correction(self):
        self.setup_trust_and_calls()
        self.setup_recall_and_evidence()
        self.assertEqual(self.act('rma.submit',id='RMA-LOCK',serial='M7',path='onsite_destroy',amount=1000,at=11),'claim_submitted')
        locked=self.call('rma.submit',id='RMA-LOCK',serial='M7',path='whole_return',amount=2000,at=11)
        self.assertEqual(locked['decision'],'claim_locked')
        self.assertEqual(self.row('SELECT path,amount_claimed FROM rma_claims WHERE id=?',('RMA-LOCK',))['path'],'onsite_destroy')
        self.assertEqual(self.act('rma.correct',claim='RMA-LOCK',correction_id='corr-lock',note='amount amendment',amount=1200,at=12),'correction_appended')

    def test_restart_and_duplicate_scans_do_not_duplicate_claims_or_credits(self):
        self.setup_trust_and_calls()
        self.setup_recall_and_evidence()
        before_mods=len(self.rows('SELECT serial FROM hw_modules'))
        for i in range(3):
            d=self.act('hardware.scan',serial='M7',at=10+i)
            self.assertIn(d,('idempotent','module_registered'))
        self.assertEqual(len(self.rows('SELECT serial FROM hw_modules WHERE serial=?',('M7',))),1)
        self.act('rma.submit',id='RMA-IDEM',serial='M7',at=12)
        # Simulate process restart by using a fresh execute/connection each time;
        # the file database itself is the persisted boundary.
        self.assertEqual(execute(self.db,{'action':'rma.submit','id':'RMA-IDEM','serial':'M7','at':12})['decision'],'idempotent')
        self.act('finance.confirm_credit',id='CN-IDEM',claim='RMA-IDEM',amount=1,at=13)
        self.assertEqual(execute(self.db,{'action':'finance.confirm_credit','id':'CN-IDEM','claim':'RMA-IDEM','amount':1,'at':13})['decision'],'idempotent')
        self.assertEqual(len(self.rows("SELECT * FROM rma_claims")),1)
        self.assertEqual(len(self.rows("SELECT * FROM vendor_credits")),1)
        self.assertEqual(len(self.rows("SELECT * FROM events WHERE kind='rma.submit' AND decision='claim_submitted'")),1)


if __name__=='__main__':
    unittest.main()
