import sqlite3,unittest
from cloudctl.route_probe import import_page
from cloudctl.traffic_route import announce
class RouteSeedTests(unittest.TestCase):
    def test_probe_changes_actual_announcement(self):
        db=sqlite3.connect(':memory:')
        self.assertEqual(announce(db,'10.0.0/24')['decision'],'no_route')
        rows=[{'source':'edge-a','prefix':'10.0.0/24','region':'east','at':10,'rtt_ms':20,'reachable':1},{'source':'edge-b','prefix':'10.0.0/24','region':'west','at':10,'rtt_ms':35,'reachable':1}]
        self.assertEqual(import_page(db,'p1',rows,11)['status'],'captured')
        self.assertEqual(announce(db,'10.0.0/24')['region'],'east')
        self.assertEqual(import_page(db,'p1',rows,11)['status'],'replayed')
        with self.assertRaises(ValueError):import_page(db,'p1',[{**rows[0],'rtt_ms':5}],11)
