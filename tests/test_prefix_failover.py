import sqlite3,tempfile,unittest
from pathlib import Path
from cloudctl.route_probe import import_page,evaluate
from cloudctl import traffic_route as tr

PFX='10.0.0.0/24'
A='10.0.0.0/25'
B='10.0.0.128/25'

def probe(source,segment,region,sent_at,rtt,received=1,sent=5,neighbor=None):
    return {'source':source,'segment':segment,'neighbor':neighbor or 'ne-'+region,
            'prefix':PFX,'region':region,'sent_at':sent_at,'rtt_ms':rtt,
            'reachable':1 if received else 0,'sent':sent,'received':received}

def minute10():
    return [probe('obs-a',A,'east',10,20),probe('obs-a',A,'west',10,35),
            probe('obs-b',B,'east',10,0,received=0),probe('obs-b',B,'west',10,35)]

def base_req(plan_id,mode,generation,**kw):
    req={'id':plan_id,'prefix':PFX,'mode':mode,'generation':generation,'at':12,'contract_ms':40,
         'segments':[{'segment':A,'bandwidth':4},{'segment':B,'bandwidth':4}],
         'egress':{'east':{'used':2,'limit':10},'west':{'used':2,'limit':10}},
         'neighbors':[{'id':'ne-east','region':'east','forwarding':1,'via':['core-e']},
                      {'id':'ne-west','region':'west','forwarding':1,'via':['core-w']}],
         'edges':[{'id':'edge-east','region':'east','cert_generation':1},
                  {'id':'edge-west','region':'west','cert_generation':1}]}
    req.update(kw)
    return req

def seed_buggy_state(db):
    """Legacy prefix-level probes announce the whole /24 east; minute-10
    per-segment originals then reveal B's eastern blackhole."""
    legacy=[{'source':'edge-a','prefix':PFX,'region':'east','at':8,'rtt_ms':20,'reachable':1},
            {'source':'edge-b','prefix':PFX,'region':'west','at':8,'rtt_ms':35,'reachable':1}]
    assert import_page(db,'seed',legacy,9)['status']=='captured'
    assert tr.announce(db,PFX)['region']=='east'
    assert import_page(db,'min10',minute10(),11)['status']=='captured'

class PrefixFailoverTests(unittest.TestCase):
    def test_consolidate_switch_serves_all_segments_and_releases_old_path_last(self):
        db=sqlite3.connect(':memory:')
        seed_buggy_state(db)
        self.assertEqual(tr.coverage(db,B)['region'],'east')
        ev=tr.evaluate_segments(db,PFX,40)
        self.assertEqual(ev[A]['choice'],'east')
        self.assertEqual(ev[B]['choice'],'west')
        req=base_req('plan-w','consolidate',2,target='west')
        res=tr.plan_switch(db,req)
        self.assertEqual(res['decision'],'planned')
        self.assertEqual(res['announce'],[{'prefix':PFX,'region':'west'}])
        self.assertEqual(res['withdraw'],[{'prefix':PFX,'region':'east'}])
        self.assertEqual(tr.plan_switch(db,req)['decision'],'replayed')
        self.assertEqual(tr.plan_switch(db,dict(req,at=99))['decision'],'plan_conflict')
        # orders issued, no receipts yet: the old path must stay announced
        self.assertEqual(tr.commit(db,'plan-w',13)['decision'],'awaiting_receipts')
        self.assertEqual(tr.coverage(db,A)['region'],'east')
        self.assertEqual(tr.apply_receipt(db,'plan-w','edge-west',PFX,'announce',2,1,14)['decision'],'recorded')
        self.assertEqual(tr.commit(db,'plan-w',15)['decision'],'awaiting_withdrawal_receipts')
        # replacement is live for both segments; east stays until its edge confirms
        self.assertEqual(tr.coverage(db,A)['region'],'west')
        self.assertEqual(tr.coverage(db,B)['region'],'west')
        east=[a for a in tr.history(db,PFX)['announcements'] if a['region']=='east'][0]
        self.assertEqual(east['status'],'active')
        self.assertEqual(tr.apply_receipt(db,'plan-w','edge-east',PFX,'withdraw',2,1,16)['decision'],'recorded')
        self.assertEqual(tr.commit(db,'plan-w',17)['decision'],'completed')
        active=[(a['prefix'],a['region']) for a in tr.history(db,PFX)['announcements'] if a['status']=='active']
        self.assertEqual(active,[(PFX,'west')])
        st=tr.plan_status(db,'plan-w')
        self.assertTrue(all(s['switched'] for s in st['segments'].values()))
        self.assertEqual(st['pending_receipts'],[])

    def test_surgical_keeps_aggregate_and_adds_specific(self):
        db=sqlite3.connect(':memory:')
        seed_buggy_state(db)
        res=tr.plan_switch(db,base_req('plan-s','surgical',2,overrides=[{'segment':B,'region':'west'}]))
        self.assertEqual(res['decision'],'planned')
        self.assertEqual(res['announce'],[{'prefix':B,'region':'west'}])
        self.assertEqual(res['withdraw'],[])
        self.assertEqual(tr.commit(db,'plan-s',13)['decision'],'awaiting_receipts')
        # control-plane order exists but the west neighbor apply receipt is
        # missing: B must not be declared switched
        st=tr.plan_status(db,'plan-s')
        self.assertEqual(st['decision'],'applying')
        self.assertFalse(st['segments'][B]['switched'])
        self.assertEqual(st['segments'][B]['effective']['region'],'east')
        self.assertTrue(st['segments'][A]['switched'])
        self.assertEqual(tr.apply_receipt(db,'plan-s','edge-west',B,'announce',2,1,14)['decision'],'recorded')
        self.assertEqual(tr.commit(db,'plan-s',15)['decision'],'completed')
        # longest-prefix: A keeps the 20ms eastern aggregate, B rides the /25 west
        self.assertEqual(tr.coverage(db,A)['region'],'east')
        cov=tr.coverage(db,B)
        self.assertEqual((cov['prefix'],cov['region']),(B,'west'))
        self.assertTrue(tr.plan_status(db,'plan-s')['segments'][B]['switched'])
        self.assertEqual(tr.coverage(db,'10.9.9.0/25')['decision'],'blackhole')

    def test_restart_after_partial_apply_resumes_without_reapplying(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=str(Path(tmp)/'state.sqlite')
            db=sqlite3.connect(path)
            seed_buggy_state(db)
            tr.plan_switch(db,base_req('plan-r','consolidate',2,target='west'))
            tr.commit(db,'plan-r',13)
            tr.apply_receipt(db,'plan-r','edge-west',PFX,'announce',2,1,14)
            db.close()
            db2=sqlite3.connect(path)
            st=tr.plan_status(db2,'plan-r')
            self.assertEqual(st['decision'],'applying')
            self.assertEqual(st['pending_receipts'],[{'edge':'edge-east','prefix':PFX,'action':'withdraw'}])
            self.assertEqual(tr.commit(db2,'plan-r',15)['decision'],'awaiting_withdrawal_receipts')
            # an old-generation receipt must not complete the new generation
            self.assertEqual(tr.apply_receipt(db2,'plan-r','edge-east',PFX,'withdraw',1,1,16)['decision'],'stale_receipt')
            self.assertEqual(tr.apply_receipt(db2,'plan-r','edge-east',PFX,'withdraw',2,1,16)['decision'],'recorded')
            self.assertEqual(tr.commit(db2,'plan-r',17)['decision'],'completed')
            db2.close()
            db3=sqlite3.connect(path)
            self.assertEqual(tr.plan_status(db3,'plan-r')['decision'],'completed')
            self.assertEqual(tr.coverage(db3,A)['region'],'west')
            db3.close()

    def test_edge_certificate_rotation_invalidates_prior_receipt(self):
        db=sqlite3.connect(':memory:')
        seed_buggy_state(db)
        tr.plan_switch(db,base_req('plan-c','consolidate',2,target='west'))
        tr.commit(db,'plan-c',13)
        self.assertEqual(tr.apply_receipt(db,'plan-c','edge-west',PFX,'announce',2,1,14)['decision'],'recorded')
        self.assertEqual(tr.rotate_edge(db,'edge-west',2)['decision'],'rotated')
        # receipt recorded under the old edge certificate no longer proves application
        self.assertEqual(tr.commit(db,'plan-c',15)['decision'],'awaiting_receipts')
        self.assertEqual(tr.apply_receipt(db,'plan-c','edge-west',PFX,'announce',2,1,16)['decision'],'stale_edge_certificate')
        self.assertEqual(tr.apply_receipt(db,'plan-c','edge-west',PFX,'announce',2,2,16)['decision'],'recorded')
        self.assertEqual(tr.commit(db,'plan-c',17)['decision'],'awaiting_withdrawal_receipts')
        self.assertEqual(tr.rotate_edge(db,'edge-west',2)['decision'],'stale_edge_generation')
        self.assertEqual(tr.apply_receipt(db,'plan-c','edge-east',PFX,'withdraw',2,1,18)['decision'],'recorded')
        self.assertEqual(tr.commit(db,'plan-c',19)['decision'],'completed')

    def test_stale_specific_cannot_shadow_new_aggregate(self):
        db=sqlite3.connect(':memory:')
        legacy=[{'source':'edge-a','prefix':PFX,'region':'east','at':8,'rtt_ms':20,'reachable':1},
                {'source':'edge-b','prefix':PFX,'region':'west','at':8,'rtt_ms':35,'reachable':1}]
        import_page(db,'seed',legacy,8)
        tr.announce(db,PFX)
        import_page(db,'min9',[probe('obs-a',A,'east',9,20),probe('obs-a',A,'west',9,35),
                               probe('obs-b',B,'east',9,22),probe('obs-b',B,'west',9,35)],10)
        # an earlier fine-grained attempt leaves a more-specific eastern route for B
        self.assertEqual(tr.plan_switch(db,base_req('plan-e','surgical',2,overrides=[{'segment':B,'region':'east'}]))['decision'],'planned')
        tr.commit(db,'plan-e',11)
        tr.apply_receipt(db,'plan-e','edge-east',B,'announce',2,1,11)
        self.assertEqual(tr.commit(db,'plan-e',11)['decision'],'completed')
        self.assertEqual(tr.coverage(db,B)['prefix'],B)
        # B's eastern path collapses; a west consolidation must withdraw both old routes
        import_page(db,'min12',[probe('obs-b',B,'east',12,0,received=0)],13)
        res=tr.plan_switch(db,base_req('plan-w','consolidate',3,target='west',at=14))
        self.assertEqual(res['decision'],'planned')
        self.assertEqual(sorted((w['prefix'],w['region']) for w in res['withdraw']),[(PFX,'east'),(B,'east')])
        tr.commit(db,'plan-w',15)
        tr.apply_receipt(db,'plan-w','edge-west',PFX,'announce',3,1,15)
        self.assertEqual(tr.commit(db,'plan-w',16)['decision'],'awaiting_withdrawal_receipts')
        # until the /25 withdrawal receipt lands, the stale specific still shadows B
        self.assertEqual(tr.coverage(db,B)['prefix'],B)
        tr.apply_receipt(db,'plan-w','edge-east',PFX,'withdraw',3,1,17)
        self.assertEqual(tr.commit(db,'plan-w',18)['decision'],'awaiting_withdrawal_receipts')
        self.assertEqual(tr.coverage(db,B)['region'],'east')
        tr.apply_receipt(db,'plan-w','edge-east',B,'withdraw',3,1,19)
        self.assertEqual(tr.commit(db,'plan-w',20)['decision'],'completed')
        cov=tr.coverage(db,B)
        self.assertEqual((cov['prefix'],cov['region']),(PFX,'west'))

    def test_failure_and_recovery_probes_change_segment_decision(self):
        db=sqlite3.connect(':memory:')
        import_page(db,'m10',[probe('obs-b',B,'east',10,20),probe('obs-b',B,'west',10,35)],11)
        self.assertEqual(tr.evaluate_segments(db,PFX,40)[B]['choice'],'east')
        import_page(db,'m11',[probe('obs-b',B,'east',11,0,received=0)],12)
        self.assertEqual(tr.evaluate_segments(db,PFX,40)[B]['choice'],'west')
        import_page(db,'m12',[probe('obs-b',B,'east',12,18)],13)
        self.assertEqual(tr.evaluate_segments(db,PFX,40)[B]['choice'],'east')
        # consecutive failures are not washed out by one lower-latency success
        import_page(db,'m13',[probe('obs-b',B,'east',13,0,received=0),probe('obs-b',B,'east',14,0,received=0)],15)
        import_page(db,'m15',[probe('obs-b',B,'east',15,5)],16)
        self.assertEqual(tr.evaluate_segments(db,PFX,40)[B]['choice'],'west')
        import_page(db,'m16',[probe('obs-b',B,'east',16,5)],17)
        self.assertEqual(tr.evaluate_segments(db,PFX,40)[B]['choice'],'east')

    def test_retransmissions_are_not_independent_proofs(self):
        db=sqlite3.connect(':memory:')
        import_page(db,'p1',[probe('obs-a',A,'east',10,20) for _ in range(3)],11)
        ev=evaluate(db,PFX)
        view=ev['segments'][A]['regions']['east']
        self.assertEqual(view['proofs'],1)
        self.assertEqual(view['sources']['obs-a']['samples'],3)
        import_page(db,'p2',[probe('obs-a2',A,'east',10,21)],11)
        view=evaluate(db,PFX)['segments'][A]['regions']['east']
        self.assertEqual(view['proofs'],2)
        self.assertEqual(view['rtt_ms'],20)

    def test_page_clock_offset_is_shared_and_late_calibration_only_reevaluates(self):
        db=sqlite3.connect(':memory:')
        rows=[probe('obs-a',A,'east',10,20),probe('obs-a',A,'west',10,35)]
        import_page(db,'cal1',rows,11,clock_offset=3)
        self.assertEqual(db.execute('SELECT DISTINCT at FROM route_probe_rows').fetchall(),[(13,)])
        self.assertEqual(tr.announce(db,PFX)['region'],'east')
        # the calibration arrives late as a corrected page: new evaluation only
        import_page(db,'cal1-fixed',rows,12,clock_offset=1)
        self.assertEqual({r[0] for r in db.execute('SELECT at FROM route_probe_rows WHERE page_id=?',('cal1-fixed',))},{11})
        active=[(a['prefix'],a['region']) for a in tr.history(db,PFX)['announcements'] if a['status']=='active']
        self.assertEqual(active,[(PFX,'east')])
        with self.assertRaises(ValueError):
            import_page(db,'cal1',rows,11,clock_offset=2)

    def test_capacity_neighbor_duplicate_and_generation_blocks(self):
        db=sqlite3.connect(':memory:')
        seed_buggy_state(db)
        self.assertEqual(tr.plan_switch(db,base_req('g1','consolidate',5,target='west'))['decision'],'generation_confusion')
        looped=base_req('g2','consolidate',2,target='west')
        looped['neighbors']=[{'id':'ne-east','region':'east','forwarding':1,'via':['core-e']},
                             {'id':'ne-west','region':'west','forwarding':1,'via':['core-w','edge-west']}]
        self.assertEqual(tr.plan_switch(db,looped)['decision'],'neighbor_loop')
        down=base_req('g3','consolidate',2,target='west')
        down['neighbors'][1]['forwarding']=0
        self.assertEqual(tr.plan_switch(db,down)['decision'],'neighbor_not_forwarding')
        tight=base_req('g4','consolidate',2,target='west')
        tight['egress']['west']={'used':7,'limit':10}
        self.assertEqual(tr.plan_switch(db,tight)['decision'],'insufficient_capacity')
        self.assertEqual(tr.plan_switch(db,base_req('g5','consolidate',2,target='west'))['decision'],'planned')
        self.assertEqual(tr.plan_switch(db,base_req('g6','consolidate',3,target='west'))['decision'],'plan_in_progress')
        tr.commit(db,'g5',13)
        tr.apply_receipt(db,'g5','edge-west',PFX,'announce',2,1,14)
        tr.commit(db,'g5',15)
        tr.apply_receipt(db,'g5','edge-east',PFX,'withdraw',2,1,16)
        self.assertEqual(tr.commit(db,'g5',17)['decision'],'completed')
        self.assertEqual(tr.plan_switch(db,base_req('g7','consolidate',3,target='west'))['decision'],'duplicate_announcement')
        # blocked attempts, executed announcements and originals stay traceable
        hist=tr.history(db,PFX)
        decisions=[e['decision'] for e in hist['events']]
        for d in ('generation_confusion','neighbor_loop','neighbor_not_forwarding','insufficient_capacity','duplicate_announcement'):
            self.assertIn(d,decisions)
        self.assertTrue(any(a['status']=='withdrawn' and a['region']=='east' for a in hist['announcements']))
        self.assertIn(A,evaluate(db,PFX)['segments'])

    def test_replan_when_evidence_changes(self):
        db=sqlite3.connect(':memory:')
        seed_buggy_state(db)
        self.assertEqual(tr.plan_switch(db,base_req('plan-s','surgical',2,overrides=[{'segment':B,'region':'west'}]))['decision'],'planned')
        tr.commit(db,'plan-s',13)
        st=tr.plan_status(db,'plan-s')
        self.assertEqual(st['decision'],'applying')
        self.assertFalse(st['segments'][B]['switched'])
        # east upstream stops forwarding and fresh probes show A lost east too
        import_page(db,'m12',[probe('obs-a',A,'east',12,0,received=0)],13)
        self.assertEqual(tr.evaluate_segments(db,PFX,40)[A]['choice'],'west')
        self.assertEqual(tr.abort(db,'plan-s',14,'east_neighbor_down')['decision'],'aborted')
        # the stale 20ms sample must not stand in for live path evidence
        self.assertEqual(tr.plan_switch(db,base_req('plan-e','consolidate',3,target='east',at=14))['decision'],'no_measured_path')
        res=tr.plan_switch(db,base_req('plan-w2','consolidate',3,target='west',at=14))
        self.assertEqual(res['decision'],'planned')
        self.assertEqual(tr.commit(db,'plan-w2',15)['decision'],'awaiting_receipts')
        tr.apply_receipt(db,'plan-w2','edge-west',PFX,'announce',3,1,15)
        self.assertEqual(tr.commit(db,'plan-w2',16)['decision'],'awaiting_withdrawal_receipts')
        tr.apply_receipt(db,'plan-w2','edge-east',PFX,'withdraw',3,1,16)
        self.assertEqual(tr.commit(db,'plan-w2',17)['decision'],'completed')
        self.assertEqual(tr.coverage(db,A)['region'],'west')
        self.assertEqual(tr.coverage(db,B)['region'],'west')

    def test_withdrawal_waits_when_replacement_path_loses_evidence(self):
        db=sqlite3.connect(':memory:')
        seed_buggy_state(db)
        tr.plan_switch(db,base_req('plan-w','consolidate',2,target='west'))
        tr.commit(db,'plan-w',13)
        tr.apply_receipt(db,'plan-w','edge-west',PFX,'announce',2,1,14)
        self.assertEqual(tr.commit(db,'plan-w',15)['decision'],'awaiting_withdrawal_receipts')
        tr.apply_receipt(db,'plan-w','edge-east',PFX,'withdraw',2,1,16)
        # fresh evidence: B loses west as well; east is still its only announced path
        import_page(db,'m16',[probe('obs-b',B,'west',16,0,received=0)],17)
        self.assertEqual(tr.commit(db,'plan-w',18)['decision'],'withdrawal_blocked')
        east=[a for a in tr.history(db,PFX)['announcements'] if a['region']=='east'][0]
        self.assertEqual(east['status'],'active')
        import_page(db,'m17',[probe('obs-b',B,'west',17,35)],18)
        self.assertEqual(tr.commit(db,'plan-w',19)['decision'],'completed')

if __name__=='__main__':unittest.main()
