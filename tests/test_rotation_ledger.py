import shutil,tempfile,unittest
from pathlib import Path
from cloudctl import store
from cloudctl.__main__ import execute


class RotationLedgerScenario(unittest.TestCase):
    """Minute-by-minute replay of the stated rotation:
    m5 gen1 issued, m8 gen2 pre-issued, m9 new root bundle published,
    m10 gen1 revoked, m11 current-generation confirmation, m12 old bundle withdrawal."""
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.db=str(Path(self.tmp.name)/'state.sqlite');store.init(self.db)
    def tearDown(self):self.tmp.cleanup()
    def act(self,action,**kw):return execute(self.db,{'action':action,**kw})
    def decision(self,action,**kw):return self.act(action,**kw)['decision']
    def build(self,overlap_roots):
        self.assertEqual(self.decision('identity.bind',id='ns/alpha',namespace='ns',service='alpha'),'bound')
        self.assertEqual(self.decision('identity.issue',id='cert-g1',identity='ns/alpha',generation=1,root='r-old',not_before=0,expires=100),'issued')            # m5
        self.assertEqual(self.decision('identity.replica',id='rep-alpha',identity='ns/alpha',cert='cert-g1',active=True),'active')
        self.assertEqual(self.decision('trust.publish',id='old-bundle',roots=['r-old'],start=0,expires=100),'published')
        self.assertEqual(self.decision('trust.ack',bundle='old-bundle',replica='rep-alpha',generation=1,at=5),'confirmed')
        self.assertEqual(self.decision('identity.issue',id='cert-g2',identity='ns/alpha',generation=2,root='r-new',not_before=8,expires=200),'issued')            # m8 pre-sign
        self.assertEqual(self.decision('trust.publish',id='new-bundle',roots=overlap_roots,start=9,expires=200),'published')                                    # m9
    def history(self):
        with store.tx(self.db) as db:return store.many(db,'SELECT num,kind,ref FROM checkpoints WHERE subject=? ORDER BY num',('ns/alpha',))
    def test_ordering_distinguishes_two_security_histories(self):
        self.build(['r-new'])
        # m10: revoke gen1 while gen2 issuance is unsealed must be blocked, state preserved
        blocked=self.act('identity.revoke',id='cert-g1')
        self.assertEqual(blocked['decision'],'unsealed_issuance_block')
        self.assertEqual(blocked['evidence']['blocking_checkpoint']['ref'],'cert-g2')
        with store.tx(self.db) as db:self.assertEqual(store.one(db,"SELECT status FROM certificates WHERE id='cert-g1'")['status'],'active')
        # seal-then-revoke versus revoke-then-seal produce different per-subject head numbers
        self.assertEqual(self.decision('trust.seal',at=10),'sealed')
        self.assertEqual(self.decision('identity.revoke',id='cert-g1'),'revoked')
        order_a=[(c['num'],c['kind']) for c in self.history()]
        self.assertEqual(order_a,[(1,'issue'),(2,'replica'),(3,'issue'),(4,'revoke')])
        other=str(Path(self.tmp.name)/'other.sqlite');store.init(other);old=self.db;self.db=other
        self.build(['r-new'])
        self.assertEqual(self.decision('trust.seal',at=9),'sealed')
        self.assertEqual(self.decision('identity.revoke',id='cert-g1'),'revoked')
        self.assertEqual(self.decision('identity.issue',id='cert-g3',identity='ns/alpha',generation=3,root='r-new',not_before=11,expires=200),'issued')
        order_b=[(c['num'],c['kind']) for c in self.history()]
        self.assertEqual(order_b,[(1,'issue'),(2,'replica'),(3,'issue'),(4,'revoke'),(5,'issue')])
        self.db=old
    def test_method_a_sealed_chain_withdraws_at_minute_12(self):
        self.build(['r-new'])
        # a subject-set-only seal could not record this; the real seal pins head numbers + bundle snapshot
        self.assertEqual(self.decision('trust.seal',at=11),'sealed')
        self.assertEqual(self.decision('identity.revoke',id='cert-g1'),'revoked')
        # m11 current-generation acknowledgement (on the new bundle, replica now on gen2)
        self.assertEqual(self.decision('identity.replica',id='rep-alpha',identity='ns/alpha',cert='cert-g2',active=True),'active')
        self.assertEqual(self.decision('trust.ack',bundle='new-bundle',replica='rep-alpha',generation=2,at=11),'confirmed')
        wd=self.act('trust.withdraw',id='old-bundle',at=12)
        self.assertEqual(wd['decision'],'withdrawn')
        self.assertEqual(wd['evidence']['basis'],'sealed_chain')
        self.assertIn('snapshot',wd['evidence'])
        # restart: same conclusions
        self._restart()
        self.assertEqual(self.act('trust.verify')['decision'],'verified')
        again=self.act('trust.withdraw',id='old-bundle',at=12)
        self.assertEqual(again['decision'],'idempotent')
        self.assertEqual(again['evidence']['migrations'][0]['basis'],'sealed_chain')
    def test_method_b_live_receipt_withdraws_and_keeps_history(self):
        # overlapping root so the same generation can be confirmed on the other active bundle
        self.build(['r-old','r-new'])
        self.assertEqual(self.decision('identity.revoke',id='cert-g1'),'unsealed_issuance_block')
        # publication alone cannot stand in for a received receipt
        self.assertEqual(self.decision('trust.withdraw',id='old-bundle',at=12),'dependent_replicas_block')
        self.assertEqual(self.decision('trust.ack',bundle='new-bundle',replica='rep-alpha',generation=1,at=11),'confirmed')
        wd=self.act('trust.withdraw',id='old-bundle',at=12)
        self.assertEqual(wd['decision'],'withdrawn')
        self.assertEqual(wd['evidence']['basis'],'live_receipt')
        self.assertEqual(wd['evidence']['ref'],'new-bundle')
        # old-generation receipt remains; later retries identify it as a historical generation
        with store.tx(self.db) as db:
            rows=store.many(db,"SELECT bundle,generation FROM receipts WHERE replica='rep-alpha' ORDER BY bundle")
        self.assertEqual(rows,[{'bundle':'new-bundle','generation':1},{'bundle':'old-bundle','generation':1}])
        retry=self.act('trust.retry',bundle='old-bundle',at=13)
        self.assertEqual(retry['decision'],'historical_receipt')
        self.assertEqual(retry['evidence']['historical_receipts'][0]['generation'],1)
        self._restart()
        self.assertEqual(self.act('trust.verify')['decision'],'verified')
        self.assertEqual(self.act('trust.retry',bundle='old-bundle',at=13)['decision'],'historical_receipt')
    def test_methods_rely_on_different_evidence_against_same_originals(self):
        results={}
        for method,roots in (('sealed_chain',['r-new']),('live_receipt',['r-old','r-new'])):
            db=str(Path(self.tmp.name)/(method+'.sqlite'));store.init(db);old=self.db;self.db=db
            self.build(roots)
            if method=='sealed_chain':
                self.assertEqual(self.decision('trust.seal',at=11),'sealed')
                self.assertEqual(self.decision('identity.revoke',id='cert-g1'),'revoked')
                self.assertEqual(self.decision('identity.replica',id='rep-alpha',identity='ns/alpha',cert='cert-g2',active=True),'active')
                self.assertEqual(self.decision('trust.ack',bundle='new-bundle',replica='rep-alpha',generation=2,at=11),'confirmed')
            else:
                self.assertEqual(self.decision('trust.ack',bundle='new-bundle',replica='rep-alpha',generation=1,at=11),'confirmed')
            wd=self.act('trust.withdraw',id='old-bundle',at=12)
            self.assertEqual(wd['decision'],'withdrawn')
            results[method]=(wd['evidence']['basis'],wd['evidence'].get('ref'),wd['evidence'].get('snapshot') is not None)
            self.db=old
        self.assertEqual(results['sealed_chain'][0],'sealed_chain');self.assertTrue(results['sealed_chain'][2])
        self.assertEqual(results['live_receipt'][0],'live_receipt');self.assertEqual(results['live_receipt'][1],'new-bundle')
        self.assertFalse(results['live_receipt'][2])
    def _restart(self):
        with store.sqlite3.connect(self.db) as db:db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        copy=str(Path(self.tmp.name)/'restart.sqlite');shutil.copy(self.db,copy);self.db=copy


if __name__=='__main__':unittest.main()
