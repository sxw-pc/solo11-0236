import json,sqlite3,unittest
from cloudctl import message_intake as intake
from cloudctl import message_result as result
from cloudctl import offset_checkpoint as checkpoint
from cloudctl import message_recovery as recovery

GROUP='g1';STREAM='open';REPAIR='repair'
T_A='tenantA';T_B='tenantB'

class MessageRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:')
        recovery.ensure_schema(self.db)
        self.gateway=recovery.Gateway()

    def tearDown(self):
        self.db.close()

    # ------------------------------------------------------------------ scene

    def seed_intake(self):
        """Tenant A: parent P at open/0/7, child C at open/1/4."""
        # contiguous prefixes so verified-span checkpoints are meaningful
        for off in range(7):
            intake.accept(self.db,STREAM,0,off,'prodA',100+off,'fill',None,
                          {'value':'filler'},tenant=T_A)
        intake.accept(self.db,STREAM,0,7,'prodA',201,'P',None,
                      {'value':{'instance_id':'I'}},tenant=T_A)
        for off in range(4):
            intake.accept(self.db,STREAM,1,off,'prodA',300+off,'fill',None,
                          {'value':'filler'},tenant=T_A)
        parent=self.parent_ref()
        intake.accept(self.db,STREAM,1,4,'prodA',405,'C','P',
                      {'value':{'network':'N'}},tenant=T_A,parent_ref=parent)
        # Tenant B: same display key P on another stream, different content/seq
        for off in range(5):
            intake.accept(self.db,REPAIR,0,off,'prodB',900+off,'fill',None,
                          {'value':'fix'},tenant=T_B)
        intake.accept(self.db,REPAIR,0,5,'prodB',999,'P',None,
                      {'value':{'repaired':True}},tenant=T_B)
        return self.parent_ref(),self.child_ref()

    def parent_ref(self):
        row=intake.locate(self.db,STREAM,0,7,T_A)
        return intake.version_ref(row)

    def child_ref(self):
        row=intake.locate(self.db,STREAM,1,4,T_A)
        return intake.version_ref(row)

    def b_ref(self):
        return intake.version_ref(intake.locate(self.db,REPAIR,0,5,T_B))

    def seed_fault(self):
        """Old epoch-2 agent finished P and acked only up to 6; B also finished."""
        parent,child=self.seed_intake()
        self.assertEqual(result.finish(self.db,STREAM,0,7,'old',2,tenant=T_A),'finished')
        # every filler on both partitions has a result, but child C (1/4) does not
        for off in range(7):
            result.finish(self.db,STREAM,0,off,'old',2,tenant=T_A)
        for off in range(4):
            result.finish(self.db,STREAM,1,off,'old',2,tenant=T_A)
        result.finish(self.db,REPAIR,0,5,'old',2,tenant=T_B)
        for off in range(5):
            result.finish(self.db,REPAIR,0,off,'old',2,tenant=T_B)
        checkpoint.acknowledge(self.db,GROUP,STREAM,0,6,2)
        # epoch-3 standby takes both partitions before the old ack arrives
        recovery.take_group(self.db,GROUP,STREAM,[0,1],'standby',3,60,at=10)
        recovery.grant_resource_lease(self.db,'lease-N','N','mount-agent',0,60)
        return parent,child

    # ------------------------------------------------- 1. same-name key isolation

    def test_same_display_key_never_joins_tenants_or_streams(self):
        parent,child=self.seed_fault()
        # business-key lookup returns both rows, and they are distinguishable
        keys=result.find_by_key(self.db,'P')
        self.assertEqual({r['tenant'] for r in keys},{T_A,T_B})
        self.assertEqual({r['stream'] for r in keys},{STREAM,REPAIR})
        # resolving the child's parent by version points at A's parent, never B
        linked=intake.parse_parent_ref(intake.find_by_ref(self.db,child))
        self.assertEqual(linked,parent)
        self.assertNotEqual(linked,self.b_ref())
        self.assertIsNone(intake.find_by_ref(self.db,
            {**self.b_ref(),'tenant':T_A}))
        # B's P cannot satisfy proof for A's parent
        with self.assertRaises(ValueError):
            recovery.attach_creation_receipt(self.db,self.b_ref(),'I',at=15)
        # digest tampering breaks the version pointer
        bad=dict(parent);bad['digest']='deadbeef'
        self.assertIsNone(intake.find_by_ref(self.db,bad))

    # ---------------------------------------- 2. parent result on disk, ack lost

    def test_persisted_parent_result_is_reused_not_reexecuted(self):
        parent,child=self.seed_fault()
        recovery.attach_creation_receipt(self.db,parent,'I',at=15)
        out=recovery.recover_family(self.db,GROUP,parent,child,'standby',3,
                                    at=20,gateway=self.gateway)
        self.assertEqual(out['decision'],'delivered')
        # no create_instance side effect ran again: only the mount did
        self.assertEqual([c[0] for c in self.gateway.calls],['mount_network'])
        actions={a['kind'] for a in recovery.action_log(self.db)}
        self.assertEqual(actions,{'mount_network'})
        proof=recovery.parent_proof(self.db,parent)
        self.assertEqual(proof['completed_by_epoch'],2)
        self.assertEqual(proof['instance_id'],'I')
        self.assertEqual(checkpoint.checkpoint(self.db,GROUP,STREAM,0)['offset'],7)
        self.assertEqual(checkpoint.checkpoint(self.db,GROUP,STREAM,1)['offset'],4)

    # ------------------------------------------------ 3. old agent resumes writes

    def test_superseded_agent_cannot_write_results_or_advance_offsets(self):
        parent,child=self.seed_fault()
        recovery.attach_creation_receipt(self.db,parent,'I',at=15)
        # old epoch-2 result writes are fenced, even with a valid payload
        with self.assertRaises(checkpoint.FenceViolation):
            result.finish(self.db,STREAM,1,4,'old',2,group=GROUP,tenant=T_A)
        with self.assertRaises(checkpoint.FenceViolation):
            result.store_result(self.db,intake.find_by_ref(self.db,child),
                                'old',2,GROUP)
        # the old agent's undelivered epoch-2 ack for offset 7 is refused
        with self.assertRaises(checkpoint.FenceViolation):
            checkpoint.acknowledge(self.db,GROUP,STREAM,0,7,2,at=18)
        # a regressing ack from the current generation is still refused too
        with self.assertRaises(ValueError):
            checkpoint.acknowledge(self.db,GROUP,STREAM,0,4,3,at=18)
        self.assertEqual(checkpoint.checkpoint(self.db,GROUP,STREAM,0)['offset'],6)
        # recovery still succeeds and records the late original separately
        decision=recovery.register_late_original(self.db,GROUP,'checkpoint',parent,2,at=18)
        self.assertEqual(decision,'rejected_stale_generation')
        out=recovery.recover_family(self.db,GROUP,parent,child,'standby',3,
                                    at=20,gateway=self.gateway)
        self.assertEqual(out['decision'],'delivered')
        # the late ack must not have altered the epoch-3 conclusion
        self.assertEqual(checkpoint.checkpoint(self.db,GROUP,STREAM,0),
                         {'offset':7,'epoch':3})

    # ------------------------------------------- 4. cross-partition child racing

    def test_child_cannot_be_acknowledged_before_parent_is_resolved(self):
        parent,child=self.seed_fault()
        # proof not yet gathered -> checkpoint for the child must not jump to 4
        with self.assertRaises(ValueError):
            recovery.advance(self.db,GROUP,child,3,at=12)
        # per-partition max-offset trick is blocked even though child offset exists
        with self.assertRaises(ValueError):
            checkpoint.acknowledge(self.db,GROUP,STREAM,1,4,3,verify=True,at=12)
        # and a raw mount without parent proof is refused
        with self.assertRaises(ValueError):
            recovery.mount_child(self.db,GROUP,parent,child,'standby',3,12,
                                 self.gateway)
        self.assertIsNone(result.get_result(self.db,child))
        self.assertEqual(checkpoint.checkpoint(self.db,GROUP,STREAM,1)['offset'],-1)

    def test_verified_span_never_crosses_unprocessed_offset(self):
        parent,child=self.seed_fault()
        with self.assertRaises(ValueError):
            checkpoint.acknowledge(self.db,GROUP,STREAM,1,4,3,verify=True,at=11)

    # ------------------------------------------------------ 5. lease invalidated

    def test_expired_resource_lease_quarantines_instead_of_mounting(self):
        parent,child=self.seed_fault()
        recovery.attach_creation_receipt(self.db,parent,'I',at=15)
        # the mount agent's lease runs out before the handoff completes
        recovery.grant_resource_lease(self.db,'lease-N','N','mount-agent',0,25)
        self.assertTrue(recovery.expire_resource_lease(self.db,'lease-N',at=26))
        out=recovery.recover_family(self.db,GROUP,parent,child,'standby',3,
                                    at=29,gateway=self.gateway,deadline=30)
        self.assertEqual(out['decision'],'undelivered')
        self.assertIn('resource_lease_invalid',out['reasons'])
        self.assertNotIn('proof_deadline_exceeded',out['reasons'])
        self.assertFalse(out['network_mounted'])
        self.assertEqual(self.gateway.calls,[])
        # child is sealed and neither partition crosses it
        state=recovery.family_state(self.db,GROUP,parent,child)
        self.assertTrue(state['sealed'])
        self.assertIsNone(state['child_result'])
        self.assertEqual(state['parent_checkpoint']['offset'],6)
        self.assertEqual(state['child_checkpoint']['offset'],-1)

    # ------------------------------------------------ 6. proof past the deadline

    def test_missing_proof_after_deadline_seals_child_and_keeps_instance(self):
        parent,child=self.seed_fault()
        # no attach_creation_receipt: independent proof never arrives
        out=recovery.recover_family(self.db,GROUP,parent,child,'standby',3,
                                    at=31,gateway=self.gateway)
        self.assertEqual(out['decision'],'undelivered')
        self.assertIn('proof_deadline_exceeded',out['reasons'])
        self.assertIn('parent_proof_unavailable',out['reasons'])
        # the real creation record is preserved, network never mounted
        self.assertIsNotNone(result.get_result(self.db,parent))
        self.assertIsNone(result.get_result(self.db,child))
        self.assertEqual(self.gateway.calls,[])
        notes=recovery.notifications(self.db,T_A)
        self.assertEqual([n['kind'] for n in notes],['incomplete'])
        self.assertFalse(notes[0]['content']['network_mounted'])

    # ------------------------------------------------ 7. manual continuation

    def test_manual_ticket_and_incomplete_notification_are_originals(self):
        parent,child=self.seed_fault()
        recovery.attach_creation_receipt(self.db,parent,'I',at=15)
        recovery.grant_resource_lease(self.db,'lease-N','N','mount-agent',0,20)
        recovery.expire_resource_lease(self.db,'lease-N',at=21)
        out=recovery.recover_family(self.db,GROUP,parent,child,'standby',3,
                                    at=25,gateway=self.gateway,deadline=30)
        ticket=out['ticket']
        row=self.db.execute('SELECT status,reason FROM manual_tickets WHERE ticket_id=?',
                            (ticket,)).fetchone()
        self.assertEqual(row[0],'open')
        self.assertIn('resource_lease_invalid',json.loads(row[1]))
        note=recovery.notifications(self.db,T_A)[0]
        self.assertEqual(note['content']['ticket'],ticket)
        self.assertEqual(note['content']['status'],'undelivered')
        # re-running recovery does not duplicate the ticket or notification
        again=recovery.recover_family(self.db,GROUP,parent,child,'standby',3,
                                      at=26,gateway=self.gateway)
        self.assertTrue(again['replayed'])
        self.assertEqual(len(recovery.notifications(self.db,T_A)),1)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM manual_tickets').fetchone()[0],1)

    # ------------------------------------------------------ 8. repeat takeover

    def test_repeated_takeover_is_idempotent_and_older_epoch_is_refused(self):
        parent,child=self.seed_fault()
        again=recovery.take_group(self.db,GROUP,STREAM,[0,1],'standby',3,60,at=11)
        self.assertTrue(all(c['replayed'] for c in again))
        # a stale epoch-2 agent cannot re-take the partitions
        with self.assertRaises(checkpoint.FenceViolation):
            recovery.take_group(self.db,GROUP,STREAM,[0,1],'old',2,99,at=12)
        # a higher generation takes over and then fences epoch 3 as well
        recovery.take_group(self.db,GROUP,STREAM,[0,1],'standby2',4,90,at=13)
        with self.assertRaises(checkpoint.FenceViolation):
            result.finish(self.db,STREAM,1,4,'standby',3,group=GROUP,tenant=T_A)
        kinds=[e['decision'] for e in recovery.events(self.db)]
        self.assertIn('claimed',kinds);self.assertIn('replayed',kinds)

    # ------------------------------- 9. late original after customer notified

    def test_late_original_after_notification_cannot_change_conclusion(self):
        parent,child=self.seed_fault()
        recovery.attach_creation_receipt(self.db,parent,'I',at=15)
        out=recovery.recover_family(self.db,GROUP,parent,child,'standby',3,
                                    at=20,gateway=self.gateway)
        self.assertEqual(out['decision'],'delivered')
        first=recovery.notifications(self.db,T_A)
        self.assertEqual(len(first),1)
        # old epoch-2 result original arrives late: fenced, recorded, no overwrite
        with self.assertRaises(checkpoint.FenceViolation):
            result.finish(self.db,STREAM,1,4,'old',2,group=GROUP,tenant=T_A)
        decision=recovery.register_late_original(self.db,GROUP,'result',child,2,
                                                 at=40,content={'bogus':True})
        self.assertEqual(decision,'rejected_stale_generation')
        # customer-visible conclusion stays exactly as first published
        notes=recovery.notifications(self.db,T_A)
        self.assertEqual(notes,first)
        child_result=result.get_result(self.db,child)
        self.assertEqual(child_result['epoch'],3)
        late=recovery.late_originals(self.db)
        self.assertTrue(all(l['decision']=='rejected_stale_generation' for l in late))

    # ------------------------------------------------ 10. restart durability

    def test_all_originals_survive_reopen_and_family_reconstructs(self):
        parent,child=self.seed_fault()
        recovery.attach_creation_receipt(self.db,parent,'I',at=15)
        recovery.recover_family(self.db,GROUP,parent,child,'standby',3,
                                at=20,gateway=self.gateway)
        before=recovery.family_state(self.db,GROUP,parent,child)
        dump='\n'.join(line for line in self.db.iterdump())
        self.db.close()
        reopened=sqlite3.connect(':memory:')
        reopened.executescript(dump)
        recovery.ensure_schema(reopened)
        after=recovery.family_state(reopened,GROUP,parent,child)
        for key in ('parent_result','child_result','parent_checkpoint',
                    'child_checkpoint','proof','sealed','notifications',
                    'actions','late_originals','events'):
            self.assertEqual(before[key],after[key],key)
        self.assertEqual(after['proof']['instance_id'],'I')
        self.assertEqual(after['notifications'][0]['kind'],'delivered')
        reopened.close()

    # --------------------------------- 11. redelivery never repeats side effects

    def test_redelivery_reuses_actions_and_results(self):
        parent,child=self.seed_fault()
        recovery.attach_creation_receipt(self.db,parent,'I',at=15)
        recovery.recover_family(self.db,GROUP,parent,child,'standby',3,
                                at=20,gateway=self.gateway)
        first_mounts=len(self.gateway.calls)
        self.assertEqual(first_mounts,1)
        # message redelivery: same versions, recovery must be fully idempotent
        again=recovery.recover_family(self.db,GROUP,parent,child,'standby',3,
                                      at=21,gateway=self.gateway)
        self.assertTrue(again['replayed'])
        self.assertEqual(len(self.gateway.calls),first_mounts)
        self.assertEqual(
            self.db.execute('SELECT COUNT(*) FROM external_actions').fetchone()[0],1)
        self.assertEqual(
            self.db.execute('SELECT COUNT(*) FROM message_results').fetchone()[0],
            self.db.execute('SELECT COUNT(*) FROM intake').fetchone()[0])
        # re-finishing the same version returns the stored result, no conflict
        self.assertEqual(result.finish(self.db,STREAM,1,4,'standby',3,
                                       group=GROUP,tenant=T_A),'replayed')

    # ---------------- 12. generation attribution and effective network state

    def test_which_generation_completed_each_task_and_when_customer_is_served(self):
        parent,child=self.seed_fault()
        recovery.attach_creation_receipt(self.db,parent,'I',at=12)
        out=recovery.recover_family(self.db,GROUP,parent,child,'standby',3,
                                    at=22,gateway=self.gateway)
        parent_result=result.get_result(self.db,parent)
        child_result=result.get_result(self.db,child)
        # instance really created by old generation 2; network mounted by gen 3
        self.assertEqual(parent_result['epoch'],2)
        self.assertEqual(parent_result['worker'],'old')
        self.assertEqual(child_result['epoch'],3)
        self.assertEqual(child_result['worker'],'standby')
        self.assertEqual(out['instance_completed_by_epoch'],2)
        self.assertEqual(out['mount_completed_by_epoch'],3)
        # the network mount is an effective side effect tied to the exact instance
        receipt=json.loads(self.db.execute(
            "SELECT receipt FROM external_actions WHERE kind='mount_network'").fetchone()[0])
        self.assertEqual(receipt,{'instance_id':'I','network':'N','at':22})
        # customer only receives the available-instance notice after the mount
        notes=recovery.notifications(self.db,T_A)
        self.assertEqual(len(notes),1)
        self.assertEqual(notes[0]['kind'],'delivered')
        self.assertEqual(notes[0]['issued_at'],22)
        self.assertTrue(notes[0]['content']['network_mounted'])
        self.assertEqual(notes[0]['content']['instance_id'],'I')
        # and the delivered conclusion survives a late old-generation ack
        with self.assertRaises(checkpoint.FenceViolation):
            checkpoint.acknowledge(self.db,GROUP,STREAM,1,4,2,at=50)

    # ---------------- 13. notification order and seal-before-mount protection

    def test_notification_only_after_effective_mount_and_seal_blocks_later_mount(self):
        parent,child=self.seed_fault()
        recovery.attach_creation_receipt(self.db,parent,'I',at=12)
        # no customer original exists while work is still pending
        self.assertEqual(recovery.notifications(self.db,T_A),[])
        out=recovery.recover_family(self.db,GROUP,parent,child,'standby',3,
                                    at=22,gateway=self.gateway)
        self.assertEqual(out['decision'],'delivered')
        note=recovery.notifications(self.db,T_A)[0]
        mount_at=recovery.action_log(self.db)[0]['at']
        self.assertGreaterEqual(note['issued_at'],mount_at)
        # a second, different notification kind cannot replace the original
        again=recovery.notify_customer(self.db,T_A,child,'delivered',
                                       {'status':'tampered'},3,at=40)
        self.assertTrue(again['replayed'])
        self.assertEqual(recovery.notifications(self.db,T_A),[note])
        # a sealed child can never be mounted afterwards even with a fresh lease
        self.db.close()
        self.db=sqlite3.connect(':memory:')
        recovery.ensure_schema(self.db)
        p2,c2=self.seed_fault()
        recovery.attach_creation_receipt(self.db,p2,'I',at=12)
        recovery.grant_resource_lease(self.db,'lease-N','N','mount-agent',0,99)
        recovery.seal_child(self.db,p2,c2,['manual'],3,at=23)
        with self.assertRaises(recovery.SealedError):
            recovery.mount_child(self.db,GROUP,p2,c2,'standby',3,24,self.gateway)
        self.assertIsNone(result.get_result(self.db,c2))

if __name__=='__main__':
    unittest.main()
