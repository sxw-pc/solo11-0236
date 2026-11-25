import tempfile,unittest
from pathlib import Path
from cloudctl import store
from cloudctl.__main__ import execute
print('MODULE_PATH',Path(store.__file__).resolve())
class TrustTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.db=str(Path(self.tmp.name)/'state.sqlite');store.init(self.db)
    def tearDown(self):self.tmp.cleanup()
    def act(self,action,**kw):return execute(self.db,{'action':action,**kw})['decision']
    def setup_pair(self):
        for name in ('alpha','beta'):
            ident='ns/'+name
            self.assertEqual(self.act('identity.bind',id=ident,namespace='ns',service=name),'bound')
            self.assertEqual(self.act('identity.issue',id='cert-'+name,identity=ident,generation=1,root='r1',not_before=0,expires=100),'issued')
            self.assertEqual(self.act('identity.replica',id='rep-'+name,identity=ident,cert='cert-'+name,active=True),'active')
        self.assertEqual(self.act('trust.publish',id='bundle',roots=['r1','r2'],start=0,expires=100),'published')
    def handshake(self):
        return self.act('handshake.decide',id='call',caller_cert='cert-alpha',callee_cert='cert-beta',caller_replica='rep-alpha',callee_replica='rep-beta',bundle='bundle',purpose='read',at=10)
    def test_identity_and_retirement(self):
        self.assertEqual(self.act('identity.bind',id='other/a',namespace='ns',service='alpha'),'wrong_namespace')
        self.setup_pair()
        self.assertEqual(self.act('identity.retire',identity='ns/alpha',at=5,reason='gone'),'blocked')
        self.act('identity.replica',id='rep-alpha',identity='ns/alpha',cert='cert-alpha',active=False)
        self.assertEqual(self.act('identity.retire',identity='ns/alpha',at=6,reason='gone'),'retired')
        self.assertEqual(self.act('identity.issue',id='new',identity='ns/alpha',generation=2,root='r2',not_before=6,expires=100),'identity_unavailable')
    def test_bundle_coverage_and_authorization(self):
        self.setup_pair()
        self.assertEqual(self.act('trust.coverage',bundle='bundle',service='alpha'),'partial')
        self.assertEqual(self.act('trust.retry',bundle='bundle'),'pending')
        for name in ('alpha','beta'):self.assertEqual(self.act('trust.ack',bundle='bundle',replica='rep-'+name,generation=1),'confirmed')
        self.assertEqual(self.act('trust.coverage',bundle='bundle',service='alpha'),'complete')
        self.assertEqual(self.act('trust.retry',bundle='bundle'),'complete')
        self.assertEqual(self.handshake(),'no_call_policy')
    def test_cross_system_handshake_revocation(self):
        self.setup_pair()
        for name in ('alpha','beta'):self.act('trust.ack',bundle='bundle',replica='rep-'+name,generation=1)
        self.assertEqual(self.act('handshake.authorize',caller='ns/alpha',callee='ns/beta',purpose='read',expires=50,at=1),'authorized')
        self.assertEqual(self.handshake(),'allowed')
        self.assertEqual(self.act('identity.revoke',id='cert-alpha'),'revoked')
        self.assertEqual(self.act('handshake.decide',id='call2',caller_cert='cert-alpha',callee_cert='cert-beta',caller_replica='rep-alpha',callee_replica='rep-beta',bundle='bundle',purpose='read',at=11),'revoked')
        self.assertEqual(self.act('trust.withdraw',id='bundle',at=20),'active_replicas_block')
    def test_expiry(self):
        self.setup_pair();self.assertEqual(self.act('handshake.expiry',service='alpha',at=90,horizon=20),'at_risk')
    def test_generation_receipts_and_bundle_window(self):
        self.setup_pair()
        self.assertEqual(self.act('identity.issue',id='wrong',identity='ns/alpha',generation=4,root='r2',not_before=5,expires=50),'wrong_generation')
        for name in ('alpha','beta'):self.act('trust.ack',bundle='bundle',replica='rep-'+name,generation=2)
        self.assertEqual(self.act('trust.ack',bundle='bundle',replica='rep-alpha',generation=1),'stale_receipt')
        self.act('handshake.authorize',caller='ns/alpha',callee='ns/beta',purpose='read',expires=200,at=1)
        self.assertEqual(self.act('handshake.decide',id='late',caller_cert='cert-alpha',callee_cert='cert-beta',caller_replica='rep-alpha',callee_replica='rep-beta',bundle='bundle',purpose='read',at=101),'bundle_outside_window')
    def test_receipt_recovery_changes_admission_and_retirement(self):
        self.setup_pair()
        self.act('handshake.authorize',caller='ns/alpha',callee='ns/beta',purpose='read',expires=50,at=1)
        self.assertEqual(self.handshake(),'unconfirmed_bundle')
        for name in ('alpha','beta'):self.act('trust.ack',bundle='bundle',replica='rep-'+name,generation=1)
        self.assertEqual(self.act('handshake.decide',id='call2',caller_cert='cert-alpha',callee_cert='cert-beta',caller_replica='rep-alpha',callee_replica='rep-beta',bundle='bundle',purpose='read',at=10),'allowed')
        self.act('identity.replica',id='rep-alpha',identity='ns/alpha',cert='cert-alpha',active=False)
        self.assertEqual(self.act('identity.retire',identity='ns/alpha',at=11,reason='shutdown'),'blocked')
        self.assertEqual(self.act('handshake.close',id='call2'),'closed')
        self.assertEqual(self.act('identity.retire',identity='ns/alpha',at=12,reason='shutdown'),'retired')
if __name__=='__main__':unittest.main()
