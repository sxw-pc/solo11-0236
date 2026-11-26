import sqlite3, tempfile, unittest
from pathlib import Path
from tests import billing_helpers as bh
from cloudctl import request_attribution as ra
from cloudctl import customer_billing as cb
from cloudctl import vendor_settlement as vs


class MonthEndScenarioTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        statuses = bh.build_month_end(self.db)
        self.assertEqual(set(statuses), {'captured'})

    def test_retry_is_one_execution_but_two_physical_transmissions(self):
        r = ra.resolve(self.db, 'Q')
        # Two pages / two certificate generations never double count the business fact.
        self.assertEqual(r['executions'], 1)
        self.assertEqual(r['transmissions'], 2)
        self.assertEqual(r['units'], 700)

    def test_ambiguous_identity_holds_the_customer_charge_back(self):
        r = ra.resolve(self.db, 'Q')
        self.assertEqual(r['state'], ra.AMBIGUOUS)
        self.assertIsNone(r['tenant'])
        # Neither tenant may be billed while both worlds stay compatible.
        self.assertEqual(cb.issue_batch(self.db, 'bill-A', 'A')['metric'], 0)
        self.assertEqual(cb.issue_batch(self.db, 'bill-B', 'B')['metric'], 0)

    def test_vendor_is_paid_both_transmissions_without_waiting_for_identity(self):
        pay = vs.pay_bandwidth(self.db, 'vendor-1')
        self.assertEqual(pay['metric'], 1400)
        self.assertEqual(len(pay['hops']), 2)
        held = vs.platform_account(self.db)
        # Customer-sized liability (one execution) stays on the platform books.
        self.assertEqual(held['unallocated'], 700)
        self.assertEqual(held['liabilities'][0]['state'], 'unallocated')

    def test_late_binding_evidence_bills_A_once_and_moves_liability_only(self):
        vs.pay_bandwidth(self.db, 'vendor-1')
        self.assertEqual(ra.bind_evidence(self.db, 'Q', 'A', 'cert-binding-ledger', at=200), 'bound')
        r = ra.resolve(self.db, 'Q')
        self.assertEqual(r['state'], ra.ATTRIBUTED)
        self.assertEqual(r['tenant'], 'A')
        bill = cb.issue_batch(self.db, 'bill-A', 'A')
        self.assertEqual(bill['metric'], 700)
        self.assertEqual(bill['tokens'], ['Q'])
        # B is never charged.
        self.assertEqual(cb.issue_batch(self.db, 'bill-B', 'B')['metric'], 0)
        moved = vs.allocate_liability(self.db, 'Q')
        self.assertEqual(moved['status'], 'allocated')
        self.assertEqual(moved['tenant'], 'A')
        self.assertEqual(vs.platform_account(self.db)['unallocated'], 0)
        # The 1400 vendor batch is never paid again.
        self.assertEqual(vs.pay_bandwidth(self.db, 'vendor-1')['status'], 'replayed')
        self.assertEqual(self.db.execute('SELECT metric FROM vendor_batches').fetchone()[0], 1400)

    def test_two_worlds_both_compatible_so_page_order_cannot_pick_a_tenant(self):
        # Re-running resolution without independent evidence must keep withholding.
        ra.resolve_all(self.db)
        row = ra.status_of(self.db, 'Q')
        self.assertEqual(row['state'], ra.AMBIGUOUS)
        import json
        detail = json.loads(row['detail'])
        self.assertEqual(detail['cert_generations'], [1, 2])


class PersistenceTest(unittest.TestCase):
    """Power loss and reopen: the same physical request stays counted once."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'state.sqlite')

    def tearDown(self):
        self.tmp.cleanup()

    def _open(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def test_import_billing_and_payment_are_idempotent_across_reopen(self):
        db = self._open()
        self.assertEqual(set(bh.build_month_end(db)), {'captured'})
        db.commit()
        db.close()

        db = self._open()
        # Re-import every original page after restart: replays, no duplicate rows.
        bh.build_month_end(db)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM proxy_facts').fetchone()[0], 2)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM backend_facts').fetchone()[0], 1)

        vs.pay_bandwidth(db, 'vendor-1')
        db.commit()
        db.close()

        db = self._open()
        pay = vs.pay_bandwidth(db, 'vendor-1')
        self.assertEqual(pay['status'], 'replayed')
        self.assertEqual(pay['metric'], 1400)

        ra.bind_evidence(db, 'Q', 'A', 'cert-binding-ledger', at=200)
        cb.issue_batch(db, 'bill-A', 'A')
        db.commit()
        db.close()

        db = self._open()
        again = cb.issue_batch(db, 'bill-A', 'A')
        self.assertEqual(again['status'], 'replayed')
        self.assertEqual(again['metric'], 700)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM billed_tokens').fetchone()[0], 1)
        db.close()


if __name__ == '__main__':
    unittest.main()
