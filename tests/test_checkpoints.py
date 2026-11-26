import json,shutil,tempfile,unittest
from pathlib import Path
from cloudctl import store
from cloudctl.__main__ import execute
from cloudctl.store import GENESIS,append_checkpoint,verify,CheckpointConflict


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.db=str(Path(self.tmp.name)/'state.sqlite');store.init(self.db)
    def tearDown(self):self.tmp.cleanup()
    def call(self,action,**kw):
        return execute(self.db,{'action':action,**kw})
    def act(self,action,**kw):return self.call(action,**kw)['decision']
    def sql(self,q,a=()):
        with store.tx(self.db) as db:return store.many(db,q,a)
    def setup_alpha(self,new_roots=('r1','r2')):
        self.assertEqual(self.act('identity.bind',id='ns/alpha',namespace='ns',service='alpha'),'bound')
        self.assertEqual(self.act('identity.issue',id='cert-a1',identity='ns/alpha',generation=1,root='r1',not_before=0,expires=100),'issued')
        self.assertEqual(self.act('identity.issue',id='cert-a2',identity='ns/alpha',generation=2,root='r2',not_before=8,expires=100),'issued')
        self.assertEqual(self.act('identity.replica',id='rep-alpha',identity='ns/alpha',cert='cert-a1',active=True),'active')
        self.assertEqual(self.act('trust.publish',id='bundle-old',roots=['r1'],start=0,expires=100),'published')
        self.assertEqual(self.act('trust.publish',id='bundle-new',roots=list(new_roots),start=9,expires=200),'published')
        self.assertEqual(self.act('trust.ack',bundle='bundle-old',replica='rep-alpha',generation=1,at=5),'confirmed')
    # ---------- chain mechanics ----------
    def test_every_success_appends_linked_checkpoint_in_same_commit(self):
        self.setup_alpha()
        cps=self.sql('SELECT * FROM checkpoints WHERE subject=? ORDER BY num',('ns/alpha',))
        self.assertEqual([(c['num'],c['kind'],c['ref']) for c in cps],
                         [(1,'issue','cert-a1'),(2,'issue','cert-a2'),(3,'replica','rep-alpha')])
        self.assertEqual(cps[0]['prev_digest'],GENESIS)
        prev=GENESIS
        for c in cps:
            self.assertEqual(c['prev_digest'],prev)
            self.assertEqual(c['digest'],store.cp_digest(c['subject'],c['num'],c['kind'],c['ref'],json.loads(c['evidence']),c['prev_digest']))
            prev=c['digest']
        bcps=self.sql("SELECT num,kind FROM checkpoints WHERE subject='bundle-old' ORDER BY num")
        self.assertEqual([(c['num'],c['kind']) for c in bcps],[(1,'publish')])
        # per-subject numbering is independent and always continues the committed head
        self.assertEqual(self._verify()['ok'],True)
    def _open(self):
        db=store.sqlite3.connect(self.db);db.row_factory=store.sqlite3.Row;return db
    def _verify(self):
        db=self._open()
        try:return verify(db)
        finally:db.close()
    def test_same_number_retry_reads_back_conflict_never_overwrites(self):
        self.setup_alpha()
        # business-level retry of the same request is idempotent and grows no chain
        heads_before={r['subject']:r['n'] for r in self.sql('SELECT subject,MAX(num) n FROM checkpoints GROUP BY subject')}
        self.assertEqual(self.act('identity.issue',id='cert-a1',identity='ns/alpha',generation=1,root='r1',not_before=0,expires=100),'idempotent')
        self.assertEqual(self.act('identity.replica',id='rep-alpha',identity='ns/alpha',cert='cert-a1',active=True),'active')
        self.assertEqual(heads_before,{r['subject']:r['n'] for r in self.sql('SELECT subject,MAX(num) n FROM checkpoints GROUP BY subject')})
        with store.tx(self.db) as db:
            first=append_checkpoint(db,'ns/x','issue','c1',{'generation':1},999)
            again=append_checkpoint(db,'ns/x','issue','c1',{'generation':1},999)  # identical retry
            self.assertEqual(again['id'],first['id'])
            with self.assertRaises(CheckpointConflict):
                append_checkpoint(db,'ns/x','issue','c1',{'generation':2},999)  # conflicting same number
        row=self.sql('SELECT * FROM checkpoints WHERE subject=? AND num=?',('ns/x',1))
        self.assertEqual(len(row),1)
    def test_receipt_history_is_retained_not_overwritten(self):
        self.setup_alpha()
        # current generation moves; both generations stay on record
        self.assertEqual(self.act('identity.replica',id='rep-alpha',identity='ns/alpha',cert='cert-a2',active=True),'active')
        self.assertEqual(self.act('trust.ack',bundle='bundle-old',replica='rep-alpha',generation=2,at=9),'untrusted_replica')
        self.assertEqual(self.act('trust.ack',bundle='bundle-new',replica='rep-alpha',generation=2,at=11),'confirmed')
        rows=self.sql('SELECT generation,at FROM receipts WHERE bundle=? AND replica=? ORDER BY generation',('bundle-old','rep-alpha'))
        self.assertEqual([(r['generation'],r['at']) for r in rows],[(1,5)])  # historical receipt still present
        # same-number retry reads back; conflicting content cannot overwrite
        self.assertEqual(self.act('trust.ack',bundle='bundle-new',replica='rep-alpha',generation=2,at=11),'idempotent')
        self.assertEqual(self.act('trust.ack',bundle='bundle-new',replica='rep-alpha',generation=2,at=12),'receipt_conflict')
        kept=self.sql('SELECT at FROM receipts WHERE bundle=? AND replica=? AND generation=?',('bundle-new','rep-alpha',2))
        self.assertEqual(kept[0]['at'],11)
        # an older-generation acknowledgement is rejected before touching any row,
        # and the historical gen-1 receipt on the old bundle is left intact
        self.assertEqual(self.act('trust.ack',bundle='bundle-new',replica='rep-alpha',generation=1,at=11),'wrong_replica_generation')
        self.assertEqual([(r['bundle'],r['generation']) for r in self.sql('SELECT bundle,generation FROM receipts WHERE replica=? ORDER BY bundle,generation',('rep-alpha',))],[('bundle-new',2),('bundle-old',1)])
    # ---------- revocation barrier ----------
    def test_revoke_cannot_leap_unsealed_issuance_and_names_predecessor(self):
        self.setup_alpha()
        blocked=self.call('identity.revoke',id='cert-a1')
        self.assertEqual(blocked['decision'],'unsealed_issuance_block')
        self.assertEqual(blocked['evidence']['blocking_checkpoint']['num'],2)
        self.assertEqual(blocked['evidence']['cert_status'],'active')  # original state preserved
        self.assertEqual(self.sql("SELECT status FROM certificates WHERE id='cert-a1'")[0]['status'],'active')
        self.assertEqual(self.sql("SELECT COUNT(*) c FROM checkpoints WHERE subject='ns/alpha'")[0]['c'],3)
    # ---------- sealing ----------
    def test_seal_records_actual_heads_and_snapshot_not_just_subject_set(self):
        # history A: issue, issue then seal
        self.setup_alpha()
        seal_a=self.call('trust.seal',at=11)
        self.assertEqual(seal_a['decision'],'sealed')
        self.assertEqual(seal_a['evidence']['heads']['ns/alpha'],3)
        self.assertEqual(seal_a['evidence']['snapshot']['bundle-old']['head'],1)
        # history B: seal earlier, then revoke (ordering differs => different recorded history)
        other=str(Path(self.tmp.name)/'other.sqlite');store.init(other)
        old=self.db;self.db=other
        self.assertEqual(self.act('identity.bind',id='ns/alpha',namespace='ns',service='alpha'),'bound')
        self.assertEqual(self.act('identity.issue',id='cert-a1',identity='ns/alpha',generation=1,root='r1',not_before=0,expires=100),'issued')
        seal_b=self.call('trust.seal',at=6)
        self.assertEqual(seal_b['evidence']['heads'],{'ns/alpha':1})
        self.assertNotEqual(seal_a['evidence']['digest'],seal_b['evidence']['digest'])
        self.db=old
    def test_seal_refuses_while_chain_unverified(self):
        self.setup_alpha()
        self.sql("DELETE FROM checkpoints WHERE subject='ns/alpha' AND num=2")
        self.assertEqual(self.act('trust.seal',at=11),'chain_unverified')
        self.assertEqual(self.sql('SELECT COUNT(*) c FROM seals')[0]['c'],0)
    # ---------- rotation ledger, method A: sealed chain ----------
    def test_rotation_method_a_sealed_chain_evidence(self):
        self.setup_alpha()
        self.assertEqual(self.act('identity.revoke',id='cert-a1'),'unsealed_issuance_block')
        self.assertEqual(self.act('trust.seal',at=11),'sealed')
        # after the issuance scene is sealed, revocation may proceed
        self.assertEqual(self.act('identity.revoke',id='cert-a1'),'revoked')
        wd=self.call('trust.withdraw',id='bundle-old',at=12)
        self.assertEqual(wd['decision'],'withdrawn')
        self.assertEqual(wd['evidence']['basis'],'sealed_chain')
        self.assertTrue(wd['evidence']['ref'].startswith('seal-'))
        self.assertEqual(wd['evidence']['migrations']['ns/alpha']['basis'],'sealed_chain')
        self.assertEqual(wd['evidence']['snapshot']['roots'],['r1'])
        # withdraw itself extends the bundle chain and the event is cross-linked
        cp=self.sql("SELECT * FROM checkpoints WHERE subject='bundle-old' ORDER BY num DESC LIMIT 1")[0]
        self.assertEqual(cp['kind'],'withdraw')
        retry=self.call('trust.retry',bundle='bundle-old',at=12)
        self.assertEqual(retry['decision'],'sealed_migration')
        self.assertEqual(retry['evidence']['sealed_subjects'],['ns/alpha'])
        # old event/receipt evidence remains traceable
        self.assertEqual(self.sql('SELECT COUNT(*) c FROM receipts WHERE bundle=?',('bundle-old',))[0]['c'],1)
        self.assertEqual(self._verify()['ok'],True)
    def test_method_a_cannot_fake_seal_when_predecessor_uncovered(self):
        self.setup_alpha()
        self.assertEqual(self.act('trust.seal',at=9),'sealed')  # seals before replica switch only covers heads so far
        self.act('identity.replica',id='rep-alpha',identity='ns/alpha',cert='cert-a2',active=True)
        self.act('identity.issue',id='cert-a3',identity='ns/alpha',generation=3,root='r1',not_before=11,expires=100)
        # sealed head now behind the committed issuance chain: sealed basis must not qualify
        self.assertEqual(self.act('trust.withdraw',id='bundle-old',at=12),'migration_evidence_missing')
        self.assertEqual(self.sql("SELECT status FROM bundles WHERE id='bundle-old'")[0]['status'],'active')
    # ---------- rotation ledger, method B: live receipt ----------
    def test_rotation_method_b_live_receipt_evidence(self):
        self.setup_alpha(new_roots=('r1','r2'))  # overlapping roots let the replica confirm same gen on the new bundle
        # revoke stays blocked (no seal happens in this path); cert stays active
        self.assertEqual(self.act('identity.revoke',id='cert-a1'),'unsealed_issuance_block')
        # merely publishing the new bundle is not enough: no migration rows may be invented
        self.assertEqual(self.act('trust.withdraw',id='bundle-old',at=12),'dependent_replicas_block')
        self.assertEqual(self.sql('SELECT COUNT(*) c FROM migrations')[0]['c'],0)
        # actual same-generation receipt on another active bundle completes migration
        self.assertEqual(self.act('trust.ack',bundle='bundle-new',replica='rep-alpha',generation=1,at=11),'confirmed')
        wd=self.call('trust.withdraw',id='bundle-old',at=12)
        self.assertEqual(wd['decision'],'withdrawn')
        self.assertEqual(wd['evidence']['basis'],'live_receipt')
        self.assertEqual(wd['evidence']['ref'],'bundle-new')
        mig=self.sql('SELECT * FROM migrations WHERE bundle=?',('bundle-old',))[0]
        self.assertEqual(mig['basis'],'live_receipt');self.assertEqual(mig['ref'],'bundle-new');self.assertIsNone(mig['seal_seq'])
        # old-generation receipt history retained and later retries classify it as historical
        old_receipts=self.sql('SELECT * FROM receipts WHERE bundle=?',('bundle-old',))
        self.assertEqual([(r['replica'],r['generation']) for r in old_receipts],[('rep-alpha',1)])
        retry=self.call('trust.retry',bundle='bundle-old',at=13)
        self.assertEqual(retry['decision'],'historical_receipt')
        self.assertEqual(retry['evidence']['receipt_subjects'],['ns/alpha'])
        self.assertEqual(retry['evidence']['historical_receipts'][0]['generation'],1)
        self.assertEqual(self._verify()['ok'],True)
    # ---------- fork / missing / broken isolation ----------
    def _pair_for_handshake(self):
        for name in ('alpha','beta'):
            ident='ns/'+name
            self.act('identity.bind',id=ident,namespace='ns',service=name)
            self.act('identity.issue',id='cert-'+name,identity=ident,generation=1,root='r1',not_before=0,expires=100)
            self.act('identity.replica',id='rep-'+name,identity=ident,cert='cert-'+name,active=True)
        self.act('trust.publish',id='bundle',roots=['r1','r2'],start=0,expires=100)
        for name in ('alpha','beta'):self.act('trust.ack',bundle='bundle',replica='rep-'+name,generation=1)
        self.act('handshake.authorize',caller='ns/alpha',callee='ns/beta',purpose='read',expires=50,at=1)
        self.assertEqual(self.act('handshake.decide',id='h0',caller_cert='cert-alpha',callee_cert='cert-beta',caller_replica='rep-alpha',callee_replica='rep-beta',bundle='bundle',purpose='read',at=10),'allowed')
    def _hs(self,hid):return self.act('handshake.decide',id=hid,caller_cert='cert-alpha',callee_cert='cert-beta',caller_replica='rep-alpha',callee_replica='rep-beta',bundle='bundle',purpose='read',at=10)
    def test_missing_checkpoint_isolates_coverage_and_handshake(self):
        self._pair_for_handshake()
        self.sql("DELETE FROM checkpoints WHERE subject='ns/alpha' AND num=1")
        self._head_count=self.sql('SELECT COUNT(*) c FROM checkpoints')[0]['c']
        self.assertFalse(self._verify()['ok'])
        self.assertEqual(self._hs('h1'),'quarantined')
        self.assertEqual(self.act('identity.issue',id='x',identity='ns/alpha',generation=2,root='r1',not_before=0,expires=100),'quarantined')
        self.assertEqual(self.act('identity.revoke',id='cert-alpha'),'quarantined')
        self.assertEqual(self.act('trust.ack',bundle='bundle',replica='rep-alpha',generation=1),'quarantined')
        self.assertEqual(self.act('trust.coverage',bundle='bundle',service='alpha'),'quarantined')
        self.assertEqual(self.act('trust.retry',bundle='bundle',at=20),'quarantined')
        self.assertEqual(self.act('trust.publish',id='bundle-2',roots=['r1'],start=0,expires=50),'quarantined')
        self.assertEqual(self.act('identity.replica',id='rep-alpha',identity='ns/alpha',cert='cert-alpha',active=False),'quarantined')
        self.assertEqual(self.act('trust.seal',at=20),'chain_unverified')
        self.assertEqual(self.act('trust.withdraw',id='bundle',at=20),'quarantined')
        # no new checkpoint may be appended while the chain is isolated
        self.assertEqual(self.sql('SELECT COUNT(*) c FROM checkpoints')[0]['c'],self._head_count)
    def test_broken_predecessor_and_fork_are_detected(self):
        self._pair_for_handshake()
        self.sql("UPDATE checkpoints SET prev_digest=? WHERE subject='ns/alpha' AND num=2",('0'*64,))
        kinds={f['type'] for f in self._verify()['faults']}
        self.assertTrue({'broken_predecessor','digest_mismatch'} & kinds)
        self.assertEqual(self._hs('h2'),'quarantined')
        # rebuild, then create a forked predecessor (two rows claiming the same subject number)
        self.setup_rebuild()
        with store.tx(self.db) as db:
            ev_seq=store.one(db,"SELECT event_seq FROM checkpoints WHERE subject='ns/alpha' AND num=1")['event_seq']
            db.execute("INSERT INTO checkpoints(subject,num,kind,ref,evidence,prev_digest,digest,event_seq) VALUES(?,?,?,?,?,?,?,?)",('ns/alpha',1,'issue','cert-FORGED','{}',GENESIS,'f'*64,ev_seq))
        self.assertIn('forked_predecessor',[f['type'] for f in self._verify()['faults']])
        self.assertEqual(self._hs('h3'),'quarantined')
    def setup_rebuild(self):
        self.tmp.cleanup();self.setUp()
        self._pair_for_handshake()
    def test_bundle_chain_fault_also_quarantines_handshake(self):
        self._pair_for_handshake()
        self.sql("UPDATE checkpoints SET digest=? WHERE subject='bundle'",('bad',))
        self.assertEqual(self._hs('h4'),'quarantined')
    def test_tampered_seal_is_a_global_quarantine_fault(self):
        self._pair_for_handshake()
        self.assertEqual(self.act('trust.seal',at=10),'sealed')
        self.assertEqual(self._hs('h5'),'allowed')
        self.sql("UPDATE seals SET digest=? WHERE seq=1",('deadbeef',))
        self.assertIn('seal_tampered',[f['type'] for f in self._verify()['faults']])
        # every subject chain is intact, yet the tampered global seal isolates admission and sealing
        self.assertEqual(self._hs('h6'),'quarantined')
        self.assertEqual(self.act('trust.coverage',bundle='bundle',service='alpha'),'quarantined')
        self.assertEqual(self.act('trust.seal',at=11),'chain_unverified')
    # ---------- power loss / reopen ----------
    def test_persisted_state_yields_same_conclusions_after_reopen(self):
        # method A state
        self.setup_alpha()
        self.act('trust.seal',at=11)
        self.act('identity.revoke',id='cert-a1')
        wd=self.call('trust.withdraw',id='bundle-old',at=12)
        self.assertEqual(wd['decision'],'withdrawn');seal_digest=wd['evidence']['migrations']['ns/alpha']['ref']
        with store.sqlite3.connect(self.db) as db:db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        copy=str(Path(self.tmp.name)/'restart.sqlite');shutil.copy(self.db,copy)
        old=self.db;self.db=copy
        self.assertTrue(self._verify()['ok'])
        again=self.call('trust.withdraw',id='bundle-old',at=12)
        self.assertEqual(again['decision'],'idempotent')
        self.assertEqual(again['evidence']['migrations'][0]['basis'],'sealed_chain')
        self.assertEqual(again['evidence']['migrations'][0]['ref'],seal_digest)
        self.assertEqual(self.call('trust.retry',bundle='bundle-old',at=12)['decision'],'sealed_migration')
        self.db=old
        # method B state survives restart with its distinct basis
        bdir=tempfile.TemporaryDirectory();bdb=str(Path(bdir.name)/'b.sqlite');store.init(bdb);old=self.db;self.db=bdb
        self.setup_alpha(new_roots=('r1','r2'))
        self.act('trust.ack',bundle='bundle-new',replica='rep-alpha',generation=1,at=11)
        self.assertEqual(self.act('trust.withdraw',id='bundle-old',at=12),'withdrawn')
        with store.sqlite3.connect(self.db) as db:db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        bcopy=str(Path(bdir.name)/'b-restart.sqlite');shutil.copy(self.db,bcopy);self.db=bcopy
        self.assertTrue(self._verify()['ok'])
        self.assertEqual(self.call('trust.retry',bundle='bundle-old',at=13)['decision'],'historical_receipt')
        self.assertEqual(self.call('trust.withdraw',id='bundle-old',at=12)['evidence']['migrations'][0]['basis'],'live_receipt')
        bdir.cleanup();self.db=old


if __name__=='__main__':unittest.main()
