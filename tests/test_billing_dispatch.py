import tempfile, unittest
from pathlib import Path
from cloudctl import store
from cloudctl.__main__ import execute


class DispatcherTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / 'state.sqlite')
        store.init(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_billing_actions_flow_through_store_transactions(self):
        req = {'action': 'billing.capture_request', 'page': 'rp', 'device': 'gw',
               'rows': [{'token': 'Q', 'tenant': 'A', 'path': '/x', 'units': 700,
                         'admission': 'allowed', 'cert_generation': 1, 'at': 1}]}
        self.assertEqual(execute(self.db, req), 'captured')
        self.assertEqual(execute(self.db, req), 'replayed')
        proxy = {'action': 'billing.capture_proxy', 'page': 'pp', 'device': 'dev',
                 'clock_skew': 0, 'stored_at': 3,
                 'rows': [{'proxy': 'p1', 'token': 'Q', 'status': 'success', 'units': 700,
                           'cert_generation': 2, 'receipt': 'r1', 'link_counter': 5, 'at': 2}]}
        self.assertEqual(execute(self.db, proxy), 'captured')
        backend = {'action': 'billing.capture_backend', 'page': 'bp', 'device': 'dev',
                   'rows': [{'receipt': 'r1', 'token': 'Q', 'status': 'success', 'units': 700, 'at': 3}]}
        self.assertEqual(execute(self.db, backend), 'captured')
        # The admission facts live in the same database as identity/handshake data.
        with store.tx(self.db) as db:
            db.execute('INSERT OR REPLACE INTO admissions VALUES(?,?,?,?)', ('Q', 'Q', 'allowed', 0))
        resolution = execute(self.db, {'action': 'billing.resolve', 'token': 'Q'})
        self.assertEqual(resolution['state'], 'ambiguous')
        self.assertEqual(resolution['transmissions'], 1)
        pay = execute(self.db, {'action': 'billing.pay_bandwidth', 'id': 'v1'})
        self.assertEqual(pay['metric'], 700)
        execute(self.db, {'action': 'billing.bind_evidence', 'token': 'Q',
                          'tenant': 'A', 'evidence': 'ledger', 'at': 9})
        bill = execute(self.db, {'action': 'billing.issue_batch', 'id': 'b1', 'tenant': 'A'})
        self.assertEqual(bill['metric'], 700)
        moved = execute(self.db, {'action': 'billing.allocate_liability', 'token': 'Q'})
        self.assertEqual(moved['status'], 'allocated')


if __name__ == '__main__':
    unittest.main()
