import json,sqlite3,unittest
from pathlib import Path
from cloudctl import wal_capture as wal,gateway_fence as gw,leader_lease as lease,store
from cloudctl.__main__ import execute

EAST_A21={'node':'a','term':7,'index':21,'digest':'digest-a21-east','prev_digest':'digest-a20',
          'boot':1,'source':'leader','ack':True,'content':'east','ticket':'ticket-east'}
B20={'node':'b','term':8,'index':20,'digest':'digest-a20','prev_digest':'digest-a19',
     'boot':1,'source':'follower','ack':True}
B21_WEST={'node':'b','term':8,'index':21,'digest':'digest-b21-west','prev_digest':'digest-a20',
          'boot':1,'source':'self','ack':False,'content':'west'}


def drill_db():
    db=sqlite3.connect(':memory:')
    wal.capture(db,'page-a',[EAST_A21])
    wal.capture(db,'page-b',[B20,B21_WEST])
    wal.capture(db,'page-w',[dict(EAST_A21,node='w')])
    return db


class WalCaptureEvidence(unittest.TestCase):
    def test_pages_keep_forks_and_only_replays_identical_content(self):
        db=sqlite3.connect(':memory:')
        self.assertEqual(wal.capture(db,'p1',[EAST_A21]),'captured')
        self.assertEqual(wal.capture(db,'p1',[EAST_A21]),'replayed')
        with self.assertRaises(ValueError):
            wal.capture(db,'p1',[dict(EAST_A21,content='west')])
        # a different page with different content at the same position is kept
        self.assertEqual(wal.capture(db,'p2',[B21_WEST]),'captured')
        positions={(e['node'],e['term'],e['index']) for e in wal.entries(db)}
        self.assertIn(('a',7,21),positions);self.assertIn(('b',8,21),positions)
        fork=wal.forks(db)
        self.assertEqual(len(fork),1)
        self.assertEqual(fork[0]['confirmed'],['digest-a21-east'])

    def test_missing_evidence_fields_are_rejected(self):
        db=sqlite3.connect(':memory:')
        for bad in ({'node':'a','term':7,'index':21},
                    dict(EAST_A21,boot='one'),
                    dict(EAST_A21,ack=1),
                    dict(EAST_A21,term=True)):
            with self.assertRaises(ValueError):wal.capture(db,'p',[bad])

    def test_confirmed_prefix_ignores_higher_unconfirmed_term(self):
        db=drill_db()
        prefix=wal.proven_prefix(db)
        self.assertFalse(prefix['blocked'])
        self.assertEqual(prefix['head_index'],21)
        self.assertEqual(prefix['head_digest'],'digest-a21-east')
        self.assertEqual([e['index'] for e in prefix['entries']],[20,21])
        self.assertEqual(prefix['ignored_forks'][0]['ignored_digest'],'digest-b21-west')
        self.assertEqual(prefix['ignored_forks'][0]['kept_digest'],'digest-a21-east')

    def test_two_confirmed_digests_at_one_position_block_the_prefix(self):
        db=sqlite3.connect(':memory:')
        wal.capture(db,'p1',[EAST_A21])
        wal.capture(db,'p2',[dict(B21_WEST,ack=True,ticket='ticket-west')])
        prefix=wal.proven_prefix(db)
        self.assertTrue(prefix['blocked'])
        self.assertEqual(len(prefix['conflicts']),1)
        # neither term may win: the control plane refuses to issue
        self.assertEqual(lease.issue(db,{'node':'b','at':1,'term':99})['decision'],'rejected')

    def test_replay_copies_the_proven_prefix_and_keeps_divergent_entry(self):
        db=drill_db()
        result=wal.replay(db,'b',source='w',at=33)
        self.assertEqual(result['decision'],'replayed')
        self.assertEqual(result['missing_after'],[])
        # the unconfirmed west entry is still retained as evidence
        own=[e for e in wal.entries(db,'b') if e['index']==21]
        self.assertEqual({e['digest'] for e in own},{'digest-a21-east','digest-b21-west'})
        prefix=wal.proven_prefix(db)
        self.assertEqual(prefix['head_digest'],'digest-a21-east')
        self.assertEqual(wal.replay(db,'b',source='w',at=34)['decision'],'idempotent')


class FencingEvidence(unittest.TestCase):
    def test_lease_row_is_not_a_physical_fence(self):
        db=sqlite3.connect(':memory:')
        gw.open(db,'gw-a','a',writes=True,at=25)
        refused=gw.fence(db,'gw-a','a',at=30,kind='lease',evidence={'physical':False})
        self.assertEqual(refused['decision'],'not_physical')
        self.assertEqual([x['node'] for x in gw.reachable(db,'a')],['a'])
        self.assertEqual(gw.fence(db,'gw-a','a',at=31,kind='lease')['decision'],'not_physical')
        done=gw.fence(db,'gw-a','a',at=34,kind='connection_closed',evidence={'physical':True})
        self.assertEqual(done['decision'],'fenced')
        self.assertEqual(gw.reachable(db,'a'),[])

    def test_rerouting_a_gateway_does_not_close_the_old_link(self):
        db=sqlite3.connect(':memory:')
        gw.open(db,'gw-a','a',writes=True,at=25)
        gw.route(db,'gw-a','b',mode='write',at=29)
        self.assertEqual([x['node'] for x in gw.reachable(db,'a')],['a'])
        self.assertEqual([x['node'] for x in gw.reachable(db,'b')],['b'])
        self.assertEqual(len(gw.unfenced(db,at=30)),2)

    def test_control_plane_evidence_cannot_be_stamped_physical(self):
        db=sqlite3.connect(':memory:')
        gw.open(db,'gw-a','a',writes=True,at=25)
        for kind,evidence in (('lease',{'physical':True}),('control_plane',{'physical':True}),
                              ('lease',None)):
            self.assertEqual(gw.fence(db,'gw-a','a',at=30,kind=kind,evidence=evidence)['decision'],
                             'not_physical')
        self.assertEqual(len(gw.reachable(db,'a')),1)

    def test_fences_are_time_ordered(self):
        db=sqlite3.connect(':memory:')
        gw.open(db,'gw-a','a',writes=True,at=25)
        gw.fence(db,'gw-a','a',at=34,kind='connection_closed')
        self.assertEqual(len(gw.reachable(db,'a',at=33)),1)
        self.assertEqual(gw.reachable(db,'a',at=34),[])


class FailoverRunbooks(unittest.TestCase):
    def setUp(self):self.db=drill_db()
    def tearDown(self):self.db.close()

    def test_replay_runbook_never_promotes_west_and_waits_for_the_fence(self):
        db=self.db
        gw.open(db,'gw-a','a',writes=True,at=25)
        gw.open(db,'gw-b','b',writes=False,at=29)
        # B's ticket arrives at 29, but A's write link is still live
        blocked=lease.recover(db,{'candidate':'b','previous':'a','witness':'w','at':29,'term':29})
        self.assertEqual(blocked['decision'],'fenced_out')
        self.assertEqual(blocked['mode'],'read_only')
        self.assertEqual(blocked['endpoint'],{'api':'east'})
        self.assertEqual(blocked['pending_writers'][0]['node'],'a')
        # read-only clients keep seeing east from the proven prefix
        view=lease.read(db,{'at':30})
        self.assertEqual(view['mode'],'read_only');self.assertEqual(view['endpoint'],{'api':'east'})
        self.assertEqual(view['prefix_head'],21)
        # A's gateway closes at 34; only now can B be promoted
        gw.fence(db,'gw-a','a',at=34,kind='connection_closed')
        promoted=lease.recover(db,{'candidate':'b','previous':'a','witness':'w','at':35,'term':35})
        self.assertEqual(promoted['decision'],'promoted')
        self.assertEqual(promoted['node'],'b');self.assertEqual(promoted['term'],35)
        self.assertEqual(promoted['index'],21);self.assertEqual(promoted['digest'],'digest-a21-east')
        self.assertEqual(promoted['endpoint'],{'api':'east'})
        after=lease.read(db,{'at':36,'term':35})
        self.assertEqual(after['mode'],'write');self.assertEqual(after['endpoint'],{'api':'east'})
        self.assertTrue(lease.verify(db)['ok'])

    def test_keep_previous_runbook_promotes_a_behind_the_same_prefix(self):
        db=self.db
        gw.open(db,'gw-a','a',writes=True,at=25)
        gw.open(db,'gw-b','b',writes=True,at=29)
        # register and then fence B's candidate lease with its 29 ticket
        candidate=lease.issue(db,{'node':'b','at':29,'term':29})
        self.assertEqual(candidate['decision'],'candidate')
        self.assertEqual(lease.fence_lease(db,{'node':'b','term':29})['decision'],'fenced')
        # B's 29 candidate cannot be promoted unchanged
        self.assertEqual(lease.issue(db,{'node':'b','at':29,'term':29})['reason'],'lease_fenced')
        # A is fenced physically, then B's gateway link is closed too
        gw.fence(db,'gw-a','a',at=34,kind='connection_closed')
        gw.fence(db,'gw-b','b',at=34,kind='connection_closed')
        promoted=lease.recover(db,{'candidate':'a','previous':'b','witness':'w','at':35,'term':35})
        self.assertEqual(promoted['decision'],'promoted')
        self.assertEqual(promoted['node'],'a')
        self.assertEqual(promoted['endpoint'],{'api':'east'})
        self.assertEqual(promoted['digest'],'digest-a21-east')
        self.assertTrue(lease.verify(db)['ok'])
        self.assertEqual(lease.verify(db)['primaries'],['a'])

    def test_two_runbooks_agree_on_east_but_differ_on_primary(self):
        results={}
        for name,node,previous in (('replay','b','a'),('keep_previous','a','b')):
            db=drill_db()
            gw.open(db,'gw-a','a',writes=True,at=25)
            gw.open(db,'gw-b','b',writes=True,at=29)
            gw.fence(db,'gw-a','a',at=34,kind='connection_closed')
            gw.fence(db,'gw-b','b',at=34,kind='connection_closed')
            out=lease.recover(db,{'candidate':node,'previous':previous,'witness':'w','at':35,'term':35})
            results[name]=(out['decision'],out['node'],out['endpoint'])
            db.close()
        self.assertEqual(results['replay'][2],{'api':'east'})
        self.assertEqual(results['keep_previous'][2],{'api':'east'})
        self.assertEqual(results['replay'][1],'b');self.assertEqual(results['keep_previous'][1],'a')

    def test_witness_must_attest_the_prefix_head_before_promotion(self):
        db=self.db
        gw.fence_node(db,'a',at=34,kind='connection_closed')
        waiting=lease.recover(db,{'candidate':'b','witness':'ghost','at':35,'term':35})
        self.assertEqual(waiting['decision'],'waiting_witness')
        self.assertEqual(waiting['endpoint'],{'api':'east'})
        ok=lease.recover(db,{'candidate':'b','witness':'w','at':35,'term':35})
        self.assertEqual(ok['decision'],'promoted')

    def test_confirmed_content_cannot_be_overwritten_by_a_higher_term(self):
        db=self.db
        gw.fence_node(db,'a',at=34,kind='connection_closed')
        rejected=lease.issue(db,{'node':'b','at':35,'term':36,
                                 'digest':'digest-b21-west','index':21})
        self.assertEqual(rejected['decision'],'rejected')
        self.assertEqual(rejected['reason'],'confirmed_content_protected')
        self.assertEqual(rejected['proven'],'digest-a21-east')
        # the candidate lease never overwrote the confirmed entry
        self.assertEqual(wal.proven_prefix(db)['head_digest'],'digest-a21-east')


class ConsistentReadAndWrite(unittest.TestCase):
    def setUp(self):self.db=drill_db();self.tmp=None

    def tearDown(self):self.db.close()
    def promote_b(self,at=35):
        gw.fence_node(self.db,'a',at=34,kind='connection_closed')
        return lease.recover(self.db,{'candidate':'b','previous':'a','witness':'w','at':at,'term':at})

    def test_read_only_view_is_one_prefix_and_retries_are_pinned(self):
        db=self.db
        first=lease.read(db,{'at':30})
        self.assertEqual(first['endpoint'],{'api':'east'})
        # retry with the observed view is served from the same prefix
        again=lease.read(db,{'at':31,'expected_view':first['view_digest']})
        self.assertEqual(again['decision'],'read')
        self.assertEqual(again['prefix_digest'],first['prefix_digest'])
        self.assertEqual(self.promote_b()['decision'],'promoted')
        moved=lease.read(db,{'at':36,'expected_view':first['view_digest']})
        self.assertEqual(moved['decision'],'view_moved')
        self.assertEqual(moved['reason'],'retry_must_not_reroute')

    def test_write_reads_bind_to_the_same_term(self):
        db=self.db
        self.promote_b()
        self.assertEqual(lease.read(db,{'at':36,'term':34})['decision'],'term_mismatch')
        self.assertEqual(lease.read(db,{'at':36,'term':35})['decision'],'read')
        self.assertEqual(lease.write(db,{'at':36,'term':34,'request_id':'r','content':'east'})['reason'],
                         'term_mismatch')
        self.assertEqual(lease.write(db,{'at':36,'term':35,'request_id':'r','content':'east'})['decision'],
                         'applied')

    def test_retry_applies_an_endpoint_change_once(self):
        db=self.db
        self.promote_b()
        first=lease.write(db,{'at':36,'request_id':'change-1','term':35,'content':'east'})
        self.assertEqual(first['decision'],'applied')
        second=lease.write(db,{'at':37,'request_id':'change-1','term':35,'content':'east'})
        self.assertEqual(second['decision'],'duplicate')
        self.assertEqual(second['index'],first['index'])
        rows=[e for e in wal.entries(db,'b') if e['index']==first['index']]
        self.assertEqual(len(rows),1)
        conflicting=lease.write(db,{'at':38,'request_id':'change-1','term':35,'content':'west'})
        self.assertEqual(conflicting['decision'],'conflict')

    def test_write_without_a_lease_is_refused(self):
        db=self.db
        self.assertEqual(lease.write(db,{'at':30,'request_id':'x','content':'east'})['reason'],
                         'no_write_lease')

    def test_no_dual_primary_across_power_loss_and_reopen(self):
        db=self.db
        self.promote_b()
        self.assertEqual(lease.verify(db)['primaries'],['b'])
        # A new live link to A would be a split brain until it is fenced
        gw.open(db,'gw-a2','a',writes=True,at=36)
        self.assertEqual(lease.write(db,{'at':37,'term':35,'request_id':'y','content':'east'})['reason'],
                         'split_brain_risk')
        report=lease.verify(db)
        self.assertFalse(report['ok'])
        self.assertIn('dual_primary',[f['type'] for f in report['faults']])
        gw.fence(db,'gw-a2','a',at=38,kind='connection_closed')
        self.assertTrue(lease.verify(db)['ok'])


class CommandSurface(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp=tempfile.TemporaryDirectory();self.path=str(Path(self.tmp.name)/'s.sqlite');store.init(self.path)

    def tearDown(self):self.tmp.cleanup()
    def act(self,action,**kw):return execute(self.path,{'action':action,**kw})

    def test_operations_dispatch_through_the_control_plane(self):
        self.assertEqual(self.act('wal.capture',page='pa',rows=[EAST_A21])['decision'] if False else
                         execute(self.path,{'action':'wal.capture','page':'pa','rows':[EAST_A21]}),'captured')
        prefix=execute(self.path,{'action':'wal.prefix'})
        self.assertEqual(prefix['head_digest'],'digest-a21-east')
        self.assertEqual(execute(self.path,{'action':'gateway.open','gateway':'gw-a','node':'a',
                                            'writes':True,'at':25})['decision'],'linked')
        self.assertEqual(execute(self.path,{'action':'gateway.fence','gateway':'gw-a','node':'a',
                                            'at':34,'kind':'connection_closed'})['decision'],'fenced')
        issued=execute(self.path,{'action':'leader.issue','node':'a','at':35,'term':35})
        self.assertEqual(issued['decision'],'issued')
        self.assertEqual(issued['endpoint'],{'api':'east'})
        self.assertEqual(execute(self.path,{'action':'leader.verify'})['decision'] if False else
                         execute(self.path,{'action':'leader.verify'})['ok'],True)
        read=execute(self.path,{'action':'read.consistent','at':36,'term':35})
        self.assertEqual(read['endpoint'],{'api':'east'})


if __name__=='__main__':unittest.main()
