import tempfile,unittest
from pathlib import Path
from cloudctl import store
from cloudctl.__main__ import execute
from cloudctl.store import digest

IDENT='ns/archive'

class RetentionCustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.db=str(Path(self.tmp.name)/'state.sqlite');store.init(self.db)
    def tearDown(self):self.tmp.cleanup()
    def act(self,action,**kw):
        return execute(self.db,{'action':action,**kw})
    def decision(self,action,**kw):
        return self.act(action,**kw)['decision']

    # ---------- fixtures ----------
    def order_hash(self,ref,body):
        return digest({'ref':ref,'body':body})
    def file_orders(self,at=20,require_original=False,deletion_scope=('A-log-1',),hold_scope=('B-hold-1',),delete_expires=1000,hold_expires=1000):
        dh=self.order_hash('warrant-del-1','court deletion warrant for tenant A logs')
        self.assertEqual(self.decision('custody.file_order',id='ord-del',identity=IDENT,kind='deletion',
            subject='tenant-A',scope=list(deletion_scope),issued_at=at,expires=delete_expires,executor='exec-1',
            original_ref='warrant-del-1',original_body='court deletion warrant for tenant A logs',original_hash=dh),'filed')
        hh=self.order_hash('warrant-hold-1','court litigation hold for tenant B records')
        self.assertEqual(self.decision('custody.file_order',id='ord-hold',identity=IDENT,kind='preservation',
            subject='tenant-B',scope=list(hold_scope),issued_at=at,expires=hold_expires,executor='exec-2',custodian='escrow-co',
            original_ref='warrant-hold-1',original_body='court litigation hold for tenant B records',original_hash=hh,
            require_original_ciphertext=require_original),'filed')
    def world(self,shared=True,extra_share_missing=False,second_volume=False):
        # key K with shares
        shares=[{'id':'K-share-1','holder':'store-a'},{'id':'K-share-2','holder':'store-b'}]
        if extra_share_missing:shares[1]['present']=False
        self.assertEqual(self.decision('custody.register_key',id='K',identity=IDENT,generation=1,shares=shares),'key_registered')
        if shared:
            blocks=[{'id':'B','cipher_digest':'cipher-B','plain_digest':'plain-shared'}]
        else:
            blocks=[{'id':'A1','cipher_digest':'cipher-A1','plain_digest':'plain-A'},
                    {'id':'B1','cipher_digest':'cipher-B1','plain_digest':'plain-B'}]
        if second_volume:
            blocks.append({'id':'D','cipher_digest':'cipher-D','plain_digest':'plain-A'})
        self.assertEqual(self.decision('custody.register_volume',id='V',identity=IDENT,key_id='K',
            copies=[{'id':'V-copy-1','controller':'store-a'},{'id':'V-copy-2','controller':'store-b'}],
            blocks=blocks),'volume_registered')
        if shared:
            objects=[{'id':'A-log-1','tenant':'A','plain_digest':'plain-shared',
                      'locations':[{'block_id':'B','volume':'V','key_id':'K'}]},
                     {'id':'B-hold-1','tenant':'B','plain_digest':'plain-shared',
                      'locations':[{'block_id':'B','volume':'V','key_id':'K'}]}]
        else:
            objects=[{'id':'A-log-1','tenant':'A','plain_digest':'plain-A',
                      'locations':[{'block_id':'A1','volume':'V','key_id':'K'}]},
                     {'id':'B-hold-1','tenant':'B','plain_digest':'plain-B',
                      'locations':[{'block_id':'B1','volume':'V','key_id':'K'}]}]
        if second_volume:
            objects[0]['locations'].append({'block_id':'D','volume':'V2','key_id':'K'})
            self.assertEqual(self.decision('custody.register_volume',id='V2',identity=IDENT,key_id='K',
                copies=[{'id':'V2-copy-1','controller':'store-c'}],
                blocks=[{'id':'D','cipher_digest':'cipher-D','plain_digest':'plain-A'}]),'volume_registered')
        self.assertEqual(self.decision('custody.register_objects',identity=IDENT,objects=objects),'objects_registered')
        # all replicas stop at minute 30, the last call is closed, then identity.retire writes retired
        self.assertEqual(self.retire_identity(),'retired')
        return objects
    def retire_identity(self,at=30):
        self.assertEqual(self.decision('identity.bind',id=IDENT,namespace='ns',service='archive'),'bound')
        self.assertEqual(self.decision('identity.issue',id='cert-arch',identity=IDENT,generation=1,root='r1',not_before=0,expires=100),'issued')
        self.assertEqual(self.decision('identity.replica',id='rep-arch',identity=IDENT,cert='cert-arch',active=True),'active')
        self.assertEqual(self.decision('identity.replica',id='rep-arch',identity=IDENT,cert='cert-arch',active=False),'stopped')
        return self.decision('identity.retire',identity=IDENT,at=at,reason='shutdown')

    # ---------- fixed scenario: conventional object-level flow yields a false certificate, which we refuse ----------
    def test_naive_object_erasure_cannot_certify_shared_block(self):
        self.world(shared=True);self.file_orders()
        self.assertEqual(self.decision('custody.register_manifest',id='manifest-1',identity=IDENT,at=31),'manifest_recorded')
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=31),'opened')
        # directory entry / object number erase receipts come back clean from the storage vendor
        self.assertEqual(self.decision('erasure.erase_object',receipt='rcpt-obj-A',identity=IDENT,copy='V-copy-1',object='A-log-1',at=32),'object_erased')
        self.assertEqual(self.decision('erasure.erase_object',receipt='rcpt-obj-A2',identity=IDENT,copy='V-copy-2',object='A-log-1',at=32),'object_erased')
        # block B bytes remain recoverable under K, so A's plaintext is still readable
        reach=self.act('erasure.reachability',identity=IDENT,at=33)['evidence']
        self.assertIn('A-log-1',reach['tenants']['A']['recoverable_objects'])
        self.assertEqual(self.decision('custody.complete',identity=IDENT,at=34),'deletion_incomplete')
        # destroying K or the whole block would break B's hold as well
        self.assertEqual(self.decision('erasure.shred_key',receipt='shred-bad',key='K',at=35),'hold_decryption_at_risk')
        self.assertEqual(self.decision('erasure.erase_copy',receipt='rcpt-wipe-bad',identity=IDENT,copy='V-copy-1',at=35),'hold_conflict_quarantined')
        # no certificate is ever issued
        with store.tx(self.db) as db:
            self.assertEqual(store.many(db,'SELECT id FROM destruction_certificates WHERE identity=?',(IDENT,)),[])
        self.assertEqual(self.decision('custody.status',identity=IDENT,at=35),'status')

    # ---------- block-level erasure of a held block is refused and isolated ----------
    def test_block_erasure_against_preservation_hold_is_quarantined(self):
        self.world(shared=False);self.file_orders()
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=31),'opened')
        # attempting to physically wipe the held B1 block conflicts with the preservation order
        res=self.act('erasure.erase_copy',receipt='rcpt-hold-block',identity=IDENT,copy='V-copy-1',blocks=['B1'],at=32)
        self.assertEqual(res['decision'],'hold_conflict_quarantined')
        with store.tx(self.db) as db:
            self.assertEqual(store.one(db,"SELECT status FROM volume_copies WHERE id=?",('V-copy-1',))['status'],'quarantined')
        self.assertEqual(self.decision('custody.complete',identity=IDENT,at=33),'quarantined_copies_present')
        # after the court receives the records, the held block still cannot be wiped while readable elsewhere requirement stands;
        # deleting the deletion-target block A1 is allowed and leaves B1 intact
        self.assertEqual(self.decision('erasure.erase_copy',receipt='rcpt-a1',identity=IDENT,copy='V-copy-2',blocks=['A1'],at=34),'copy_erased')
        with store.tx(self.db) as db:
            self.assertIsNotNone(store.one(db,'SELECT receipt_id FROM copy_block_erasure WHERE copy_id=? AND block_id=?',('V-copy-2','A1')))
            self.assertIsNone(store.one(db,'SELECT receipt_id FROM copy_block_erasure WHERE copy_id=? AND block_id=?',('V-copy-2','B1')))

    # ---------- path one: migration to independent key volume, then destroy old volume + key ----------
    def test_migration_path_completes_with_real_certificate(self):
        self.world(shared=True);self.file_orders()
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=31),'opened')
        # independent key volume for the court escrow
        self.assertEqual(self.decision('custody.register_key',id='K2',identity=IDENT,generation=2,
            shares=[{'id':'K2-share-1','holder':'escrow-co'}]),'key_registered')
        self.assertEqual(self.decision('custody.register_volume',id='V-escrow',identity=IDENT,key_id='K2',
            copies=[{'id':'V-escrow-1','controller':'escrow-co'}],
            blocks=[{'id':'B-escrow','cipher_digest':'cipher-B-escrow','plain_digest':'plain-shared'}]),'volume_registered')
        self.assertEqual(self.decision('custody.migrate',identity=IDENT,at=40,order_id='ord-hold',order_version=1,
            to_volume='V-escrow',new_blocks={('V','B'):'B-escrow'},new_cipher={'B-escrow':'cipher-B-escrow'},proof='proof-mig-1'),'migrated')
        # order content and order preserved, deletion subject excluded from the new volume
        with store.tx(self.db) as db:
            proof=store.one(db,'SELECT * FROM migration_proofs WHERE id=?',('proof-mig-1',))
            self.assertEqual(proof['status'],'verified')
            self.assertEqual(store.one(db,'SELECT reachable FROM object_blocks WHERE object_id=? AND block_id=? AND volume=?',('A-log-1','B-escrow','V-escrow')),None)
            self.assertEqual(store.one(db,'SELECT reachable FROM object_blocks WHERE object_id=? AND block_id=? AND volume=?',('B-hold-1','B-escrow','V-escrow'))['reachable'],1)
        # court receives only B's records, never the whole shared volume; byte form checked against proof
        proof=execute(self.db,{'action':'custody.status','identity':IDENT,'at':41})
        preserved=digest([['B-hold-1','plain-shared']])
        self.assertEqual(self.decision('custody.deliver_court',id='del-1',identity=IDENT,at=41,order_id='ord-hold',order_version=1,
            custodian='escrow-co',volume='V-escrow',key_id='K2',form='reencrypted',scope=['B-hold-1'],
            byte_digest=preserved,proof='proof-mig-1'),'delivered')
        # scope cannot exceed the order
        self.assertEqual(self.decision('custody.deliver_court',id='del-bad',identity=IDENT,at=41,order_id='ord-hold',order_version=1,
            custodian='escrow-co',volume='V-escrow',form='reencrypted',scope=['B-hold-1','A-log-1'],
            byte_digest=preserved,proof='proof-mig-1'),'scope_exceeds_order')
        # now destroy every physical copy of the old volume and shred the old key
        self.assertEqual(self.decision('erasure.erase_copy',receipt='rcpt-v1',identity=IDENT,copy='V-copy-1',at=42),'copy_erased')
        self.assertEqual(self.decision('erasure.erase_copy',receipt='rcpt-v2',identity=IDENT,copy='V-copy-2',at=42),'copy_erased')
        self.assertEqual(self.decision('erasure.shred_key',receipt='shred-K',key='K',at=43),'key_shredded')
        reach=self.act('erasure.reachability',identity=IDENT,at=44)['evidence']
        self.assertEqual(reach['tenants']['A']['irrecoverable_objects'],['A-log-1'])
        self.assertEqual(reach['tenants']['A']['recoverable_objects'],[])
        self.assertEqual(reach['tenants']['B']['controllers_of_recoverable_copies'],['escrow-co'])
        res=self.act('custody.complete',identity=IDENT,at=45)
        self.assertEqual(res['decision'],'completed')
        cert=res['evidence']['certificate']
        # completion is idempotent: no duplicate destruction certificate
        again=self.act('custody.complete',identity=IDENT,at=46)
        self.assertEqual(again['decision'],'idempotent')
        self.assertEqual(again['evidence']['certificate'],cert)

    # ---------- path two: original ciphertext must be kept, separate blocks allow proven rearrangement ----------
    def test_rearrangement_path_keeps_original_bytes_and_excludes_deletion(self):
        self.world(shared=False)
        self.file_orders(require_original=True)
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=31),'opened')
        res=self.act('custody.rearrange',identity=IDENT,at=40,order_id='ord-hold',order_version=1,volume='V',
            kept_blocks=['B1'],rewritten_blocks={'A1':'A1-rw'},
            new_cipher={'A1-rw':'cipher-A1-rw'},new_plain_digest={'A1-rw':'plain-empty'},
            rewrite_receipt='rcpt-rw-1')
        self.assertEqual(res['decision'],'rearranged')
        # B's original ciphertext bytes are untouched under the original key
        with store.tx(self.db) as db:
            self.assertEqual(store.one(db,'SELECT cipher_digest FROM physical_blocks WHERE id=? AND volume=?',('B1','V'))['cipher_digest'],'cipher-B1')
            self.assertTrue(store.one(db,'SELECT receipt_id FROM copy_block_erasure WHERE copy_id=? AND block_id=?',('V-copy-1','A1')))
        original_digest=digest(['cipher-B1'])
        self.assertEqual(self.decision('custody.deliver_court',id='del-hold',identity=IDENT,at=41,order_id='ord-hold',order_version=1,
            custodian='escrow-co',volume='V',key_id='K',form='original_ciphertext',scope=['B-hold-1'],
            byte_digest=original_digest),'delivered')
        # wrong custodian is refused
        self.assertEqual(self.decision('custody.deliver_court',id='del-hold-x',identity=IDENT,at=41,order_id='ord-hold',order_version=1,
            custodian='intruder',volume='V',form='original_ciphertext',scope=['B-hold-1'],byte_digest=original_digest),'custodian_unauthorized')
        self.assertEqual(self.decision('custody.complete',identity=IDENT,at=42),'completed')
        reach=self.act('erasure.reachability',identity=IDENT,at=43)['evidence']
        self.assertEqual(reach['tenants']['A']['irrecoverable_objects'],['A-log-1'])
        self.assertEqual(reach['tenants']['B']['recoverable_objects'],['B-hold-1'])

    # ---------- original ciphertext required + shared block: must stop unfinished and escalate, no false proof ----------
    def test_shared_block_with_original_ciphertext_hold_escalates(self):
        self.world(shared=True)
        self.file_orders(require_original=True)
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=31),'rearrangement_blocked_escalated')
        # an attempted rearrangement is likewise blocked rather than corrupting the hold
        self.assertEqual(self.decision('custody.rearrange',identity=IDENT,at=40,order_id='ord-hold',order_version=1,volume='V',
            kept_blocks=['B'],rewritten_blocks={},new_cipher={},new_plain_digest={},rewrite_receipt='rcpt-x'),'rearrangement_blocked_escalated')
        self.assertEqual(self.decision('custody.complete',identity=IDENT,at=41),'escalated_no_false_certificate')
        with store.tx(self.db) as db:
            self.assertEqual(store.many(db,'SELECT id FROM destruction_certificates WHERE identity=?',(IDENT,)),[])
            self.assertEqual(store.one(db,'SELECT state FROM custody_cases WHERE identity=?',(IDENT,))['state'],'escalated_court')

    # ---------- duplicated blocks across volumes: every independent copy must be erased ----------
    def test_duplicate_blocks_across_volumes_require_all_copies_destroyed(self):
        self.world(shared=False,second_volume=True)
        self.file_orders()
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=31),'opened')
        # erase only the V copies: the late/offline V2 copy still holds A's plaintext under K
        self.assertEqual(self.decision('erasure.erase_copy',receipt='rcpt-a1-c1',identity=IDENT,copy='V-copy-1',blocks=['A1'],at=32),'copy_erased')
        self.assertEqual(self.decision('erasure.erase_copy',receipt='rcpt-a1-c2',identity=IDENT,copy='V-copy-2',blocks=['A1'],at=32),'copy_erased')
        self.assertEqual(self.decision('custody.complete',identity=IDENT,at=33),'deletion_incomplete')
        # B must stay readable on V
        self.assertEqual(self.decision('erasure.shred_key',receipt='shred-early',key='K',at=34),'hold_decryption_at_risk')
        # destroy the remaining duplicate copy too
        self.assertEqual(self.decision('erasure.erase_copy',receipt='rcpt-d-c1',identity=IDENT,copy='V2-copy-1',blocks=['D'],at=35),'copy_erased')
        self.assertEqual(self.decision('custody.deliver_court',id='del-b',identity=IDENT,at=36,order_id='ord-hold',order_version=1,
            custodian='escrow-co',volume='V',key_id='K',form='original_ciphertext',scope=['B-hold-1'],
            byte_digest=digest(['cipher-B1'])),'delivered')
        self.assertEqual(self.decision('custody.complete',identity=IDENT,at=37),'completed')

    # ---------- late-arriving backup after closure: supplement and correct, never erase old proof ----------
    def test_late_backup_volume_requires_amendment_not_replacement(self):
        self.world(shared=False)
        self.file_orders()
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=31),'opened')
        for copy,block in (('V-copy-1','A1'),('V-copy-2','A1')):
            self.assertEqual(self.decision('erasure.erase_copy',receipt='rcpt-'+copy,identity=IDENT,copy=copy,blocks=[block],at=32),'copy_erased')
        self.assertEqual(self.decision('custody.deliver_court',id='del-b',identity=IDENT,at=33,order_id='ord-hold',order_version=1,
            custodian='escrow-co',volume='V',key_id='K',form='original_ciphertext',scope=['B-hold-1'],
            byte_digest=digest(['cipher-B1'])),'delivered')
        first=self.act('custody.complete',identity=IDENT,at=34)
        self.assertEqual(first['decision'],'completed');first_cert=first['evidence']['certificate']
        # a third offline backup surfaces later with A's plaintext still recoverable
        self.assertEqual(self.decision('custody.register_volume',id='V-late',identity=IDENT,key_id='K',
            copies=[{'id':'V-late-1','controller':'store-d'}],
            blocks=[{'id':'L','cipher_digest':'cipher-L','plain_digest':'plain-A'}]),'volume_registered')
        self.assertEqual(self.decision('custody.register_objects',identity=IDENT,objects=[
            {'id':'A-log-1','tenant':'A','plain_digest':'plain-A','locations':[{'block_id':'L','volume':'V-late','key_id':'K'}]}]),'objects_registered')
        self.assertEqual(self.decision('custody.complete',identity=IDENT,at=40),'deletion_incomplete')
        self.assertEqual(self.decision('erasure.erase_copy',receipt='rcpt-late',identity=IDENT,copy='V-late-1',blocks=['L'],at=41),'copy_erased')
        amended=self.act('custody.amend',identity=IDENT,at=42,note='late offline volume V-late')
        self.assertEqual(amended['decision'],'amended')
        with store.tx(self.db) as db:
            old=store.one(db,'SELECT * FROM destruction_certificates WHERE id=?',(first_cert,))
            self.assertTrue(old['superseded_by'])
            self.assertNotEqual(old['superseded_by'],first_cert)
            # both certificates remain on record; history is never erased
            self.assertEqual(len(store.many(db,'SELECT id FROM destruction_certificates WHERE identity=?',(IDENT,))),2)
            self.assertEqual(store.one(db,'SELECT state FROM custody_cases WHERE identity=?',(IDENT,))['state'],'amended')

    # ---------- missing key shares: shredding is refused; physical erasure still achieves deletion ----------
    def test_missing_key_share_blocks_shred_but_physical_erasure_completes(self):
        self.world(shared=False,extra_share_missing=True)
        self.file_orders()
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=31),'opened')
        self.assertEqual(self.decision('erasure.shred_key',receipt='shred-K',key='K',at=32),'key_shares_missing')
        for copy in ('V-copy-1','V-copy-2'):
            self.assertEqual(self.decision('erasure.erase_copy',receipt='rcpt-'+copy,identity=IDENT,copy=copy,blocks=['A1'],at=33),'copy_erased')
        self.assertEqual(self.decision('custody.deliver_court',id='del-b',identity=IDENT,at=34,order_id='ord-hold',order_version=1,
            custodian='escrow-co',volume='V',key_id='K',form='original_ciphertext',scope=['B-hold-1'],
            byte_digest=digest(['cipher-B1'])),'delivered')
        # B still needs K, which is fine because the share gap does not delete the key, only blocks shredding
        res=self.act('custody.complete',identity=IDENT,at=35)
        self.assertEqual(res['decision'],'completed')
        # completion here rests on physical erasure receipts, not on a key shred
        self.assertEqual(res['evidence']['basis']['key_shreds'],[])
        with store.tx(self.db) as db:
            self.assertEqual(store.many(db,"SELECT s.id FROM key_shreds s JOIN data_keys k ON k.id=s.key_id WHERE k.identity=?",(IDENT,)),[])

    # ---------- interrupted execution resumes by volume / key generation / order version, no duplicate proof ----------
    def test_interrupted_execution_resumes_without_duplicate_certificate(self):
        self.world(shared=False,extra_share_missing=True)
        self.file_orders()
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=31),'opened')
        # partial work: one copy erased, then the executor stops
        self.assertEqual(self.decision('erasure.erase_copy',receipt='rcpt-partial',identity=IDENT,copy='V-copy-1',blocks=['A1'],at=32),'copy_erased')
        plan=self.act('custody.resume',identity=IDENT,at=33)['evidence']
        actions=[p['action'] for p in plan['plan']]
        self.assertIn('erase_copy',actions)
        self.assertIn('deliver_court',actions)
        self.assertEqual(plan['order_versions'],[['ord-del',1],['ord-hold',1]])
        # resume per plan: receipts already issued are idempotent, no duplicate
        self.assertEqual(self.decision('erasure.erase_copy',receipt='rcpt-partial',identity=IDENT,copy='V-copy-1',blocks=['A1'],at=34),'idempotent')
        self.assertEqual(self.decision('erasure.erase_copy',receipt='rcpt-rest',identity=IDENT,copy='V-copy-2',blocks=['A1'],at=34),'copy_erased')
        self.assertEqual(self.decision('custody.deliver_court',id='del-b',identity=IDENT,at=35,order_id='ord-hold',order_version=1,
            custodian='escrow-co',volume='V',key_id='K',form='original_ciphertext',scope=['B-hold-1'],
            byte_digest=digest(['cipher-B1'])),'delivered')
        self.assertEqual(self.decision('custody.complete',identity=IDENT,at=36),'completed')

    # ---------- court order change mid-flight invalidates the bound order fingerprint ----------
    def test_order_change_requires_rebind_before_completion(self):
        self.world(shared=False)
        self.file_orders()
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=31),'opened')
        # the court amends the hold: original ciphertext now required
        hh=self.order_hash('warrant-hold-2','amended hold requiring original ciphertext')
        self.assertEqual(self.decision('custody.file_order',id='ord-hold',identity=IDENT,kind='preservation',
            subject='tenant-B',scope=['B-hold-1'],issued_at=32,expires=1000,executor='exec-2',custodian='escrow-co',
            original_ref='warrant-hold-2',original_body='amended hold requiring original ciphertext',original_hash=hh,
            require_original_ciphertext=True),'filed')
        self.assertEqual(self.decision('custody.complete',identity=IDENT,at=33),'order_changed')
        # reopen rebinds the new order version; old versions remain historically on record
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=34),'opened')
        with store.tx(self.db) as db:
            self.assertEqual(store.one(db,'SELECT version,superseded FROM legal_orders WHERE id=? AND version=1',('ord-hold',))['superseded'],1)
            self.assertEqual(store.one(db,'SELECT version FROM legal_orders WHERE id=? AND superseded=0',('ord-hold',))['version'],2)

    # ---------- verifiable originals: a warrant whose hash cannot be checked is rejected ----------
    def test_order_original_must_be_verifiable(self):
        self.assertEqual(self.decision('custody.file_order',id='ord-bad',identity=IDENT,kind='deletion',
            subject='tenant-A',scope=['A-log-1'],issued_at=20,expires=100,executor='exec-1',
            original_ref='warrant-x',original_body='body',original_hash='deadbeef'),'original_unverifiable')

    # ---------- failed verification isolates the copy instead of counting it complete ----------
    def test_failed_migration_verification_quarantines_copy(self):
        self.world(shared=True);self.file_orders()
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=31),'opened')
        self.assertEqual(self.decision('custody.register_key',id='K2',identity=IDENT,generation=2,
            shares=[{'id':'K2-share-1','holder':'escrow-co'}]),'key_registered')
        self.assertEqual(self.decision('custody.register_volume',id='V-escrow',identity=IDENT,key_id='K2',
            copies=[{'id':'V-escrow-1','controller':'escrow-co'}],
            blocks=[{'id':'B-escrow','cipher_digest':'cipher-B-escrow','plain_digest':'plain-shared'}]),'volume_registered')
        # one physical copy returns bytes that do not match the recorded block digest
        res=self.act('custody.migrate',identity=IDENT,at=40,order_id='ord-hold',order_version=1,to_volume='V-escrow',
            new_blocks={('V','B'):'B-escrow'},new_cipher={'B-escrow':'cipher-B-escrow'},proof='proof-bad',
            observed={'V-copy-2':{'B':'tampered-cipher'}})
        self.assertEqual(res['decision'],'verification_failed_quarantined')
        self.assertIn('V-copy-2',res['evidence']['copies'])
        self.assertEqual(self.decision('custody.complete',identity=IDENT,at=41),'quarantined_copies_present')
        with store.tx(self.db) as db:
            self.assertEqual(store.one(db,"SELECT status FROM volume_copies WHERE id=?",('V-copy-2',))['status'],'quarantined')
            self.assertEqual(store.one(db,"SELECT status FROM migration_proofs WHERE id=?",('proof-bad',)),None)

    # ---------- retirement records the pending custody obligation and audit exposes it ----------
    def test_retirement_creates_custody_obligation_and_audit_reports_it(self):
        self.world(shared=True);self.file_orders()
        with store.tx(self.db) as db:
            self.assertEqual(store.one(db,'SELECT state FROM custody_cases WHERE identity=?',(IDENT,))['state'],'awaiting_custody')
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=31),'opened')
        audit=self.act('identity.audit',service='archive',at=32)['evidence']
        entry=[c for c in audit['custody'] if c['identity']==IDENT][0]
        self.assertEqual(entry['state'],'open')
        self.assertIn('store-a',entry['recoverable_controllers'])
        self.assertEqual(entry['certificates'],[])

    # ---------- status answers: who controls recoverable copies, what is irrecoverable, what the court holds ----------
    def test_status_reports_controllers_irrecoverability_and_court_materials(self):
        self.world(shared=True);self.file_orders()
        self.assertEqual(self.decision('custody.open',identity=IDENT,at=31),'opened')
        st=self.act('custody.status',identity=IDENT,at=32)['evidence']
        self.assertEqual(sorted(st['controllers_of_recoverable_copies']),['store-a','store-b'])
        self.assertEqual(st['irrecoverable_customer_data'],[])
        self.assertEqual({o['id'] for o in st['active_orders']},{'ord-del','ord-hold'})

if __name__=='__main__':unittest.main()
