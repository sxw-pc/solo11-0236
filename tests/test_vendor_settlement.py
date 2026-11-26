import sqlite3, unittest
from tests import billing_helpers as bh
from cloudctl import billing_facts as bf
from cloudctl import request_attribution as ra
from cloudctl import vendor_settlement as vs


class VendorSettlementTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row

    def test_physical_retry_traffic_paid_in_full_including_unknown_identity(self):
        bh.build_month_end(self.db)
        pay = vs.pay_bandwidth(self.db, 'vendor-1')
        self.assertEqual(pay['metric'], 1400)
        self.assertEqual({h['proxy'] for h in pay['hops']},
                         {'proxy-primary', 'proxy-backup'})

    def test_payment_batch_is_idempotent_and_hop_paid_once(self):
        bh.build_month_end(self.db)
        vs.pay_bandwidth(self.db, 'vendor-1')
        replay = vs.pay_bandwidth(self.db, 'vendor-1')
        self.assertEqual(replay['status'], 'replayed')
        self.assertEqual(replay['metric'], 1400)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM vendor_items').fetchone()[0], 2)
        # A second batch after no new facts pays nothing extra.
        second = vs.pay_bandwidth(self.db, 'vendor-2')
        self.assertEqual(second['metric'], 0)

    def test_new_hop_after_first_batch_settles_incrementally(self):
        bh.build_month_end(self.db)
        vs.pay_bandwidth(self.db, 'vendor-1')
        bf.capture_proxy(self.db, 'page-extra',
                         [{'proxy': 'proxy-primary', 'token': 'Q2', 'status': 'timeout', 'units': 30,
                           'cert_generation': 1, 'receipt': '', 'link_counter': 3000, 'at': 200}],
                         'proxy-primary-device', stored_at=201)
        second = vs.pay_bandwidth(self.db, 'vendor-2')
        self.assertEqual(second['metric'], 30)
        self.assertEqual(second['hops'][0]['token'], 'Q2')
        self.assertEqual(self.db.execute('SELECT SUM(metric) FROM vendor_batches').fetchone()[0], 1430)

    def test_unallocated_liability_released_by_binding_evidence_only(self):
        bh.build_month_end(self.db)
        vs.pay_bandwidth(self.db, 'vendor-1')
        account = vs.platform_account(self.db)
        self.assertEqual(account['unallocated'], 700)
        self.assertEqual(account['liabilities'][0]['token'], 'Q')
        # Without evidence the liability cannot be moved.
        self.assertEqual(vs.allocate_liability(self.db, 'Q')['status'], 'still_unallocated')
        ra.bind_evidence(self.db, 'Q', 'A', 'binding-ledger', at=200)
        moved = vs.allocate_liability(self.db, 'Q')
        self.assertEqual(moved['status'], 'allocated')
        self.assertEqual(moved['tenant'], 'A')
        self.assertEqual(vs.platform_account(self.db)['unallocated'], 0)
        # Vendor money never moves when identity gets resolved.
        self.assertEqual(self.db.execute('SELECT metric FROM vendor_batches').fetchone()[0], 1400)

    def test_traffic_settles_even_when_request_was_denied(self):
        bh.admit(self.db, 'D')
        bf.capture_request(self.db, 'rp',
                           [{'token': 'D', 'tenant': 'A', 'path': '/x', 'units': 40,
                             'admission': 'denied', 'cert_generation': 1, 'at': 1}], 'gw')
        bf.capture_proxy(self.db, 'pp',
                         [{'proxy': 'p1', 'token': 'D', 'status': 'timeout', 'units': 40,
                           'cert_generation': 1, 'receipt': '', 'link_counter': 9, 'at': 2}], 'dev')
        pay = vs.pay_bandwidth(self.db, 'vendor-1')
        self.assertEqual(pay['metric'], 40)
        # A denied, unexecuted request leaves no customer liability behind.
        self.assertEqual(vs.platform_account(self.db)['unallocated'], 0)

    def test_physical_and_business_books_never_share_a_flag(self):
        bh.build_month_end(self.db)
        vs.pay_bandwidth(self.db, 'vendor-1')
        # Vendor side already settled 1400 while no customer bill exists.
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM vendor_items').fetchone()[0], 2)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM request_resolutions WHERE state='ambiguous'").fetchone()[0], 1)
        # Resolving the identity changes only the customer-facing books.
        ra.bind_evidence(self.db, 'Q', 'A', 'binding', at=9)
        vs.allocate_liability(self.db, 'Q')
        self.assertEqual(self.db.execute('SELECT metric FROM vendor_batches').fetchone()[0], 1400)


if __name__ == '__main__':
    unittest.main()
