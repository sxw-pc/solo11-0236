import sqlite3, unittest
from tests import billing_helpers as bh
from cloudctl import billing_facts as bf
from cloudctl import request_attribution as ra
from cloudctl import customer_billing as cb


class CustomerBillingTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row

    def _full_request(self, token, tenant='A', units=100):
        bh.admit(self.db, token)
        bf.capture_request(self.db, 'rp-' + token,
                           [{'token': token, 'tenant': tenant, 'path': '/x', 'units': units,
                             'admission': 'allowed', 'cert_generation': 1, 'at': 1}], 'gw')
        bf.capture_proxy(self.db, 'pp-' + token,
                         [{'proxy': 'p-' + token, 'token': token, 'status': 'success', 'units': units,
                           'cert_generation': 1, 'receipt': 'r-' + token, 'link_counter': 1, 'at': 2}], 'dev')
        bf.capture_backend(self.db, 'bp-' + token,
                           [{'receipt': 'r-' + token, 'token': token, 'status': 'success',
                             'units': units, 'at': 3}], 'dev')
        ra.bind_evidence(self.db, token, tenant, 'bind-' + token, at=4)

    def test_batch_bills_each_physical_request_once(self):
        self._full_request('q1', units=100)
        self._full_request('q2', units=250)
        batch = cb.issue_batch(self.db, 'bill-1', 'A')
        self.assertEqual(batch['metric'], 350)
        self.assertEqual(batch['tokens'], ['q1', 'q2'])

    def test_reissuing_batch_is_replay_and_never_double_bills(self):
        self._full_request('q1', units=100)
        first = cb.issue_batch(self.db, 'bill-1', 'A')
        second = cb.issue_batch(self.db, 'bill-1', 'A')
        self.assertEqual(second['status'], 'replayed')
        self.assertEqual(second['metric'], 100)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM billed_tokens').fetchone()[0], 1)
        # A later batch must not pick up an already billed token.
        self._full_request('q2', units=50)
        next_batch = cb.issue_batch(self.db, 'bill-2', 'A')
        self.assertEqual(next_batch['metric'], 50)
        self.assertEqual(next_batch['tokens'], ['q2'])

    def test_batch_conflict_on_identity_change(self):
        self._full_request('q1')
        cb.issue_batch(self.db, 'bill-1', 'A')
        with self.assertRaises(ValueError):
            cb.issue_batch(self.db, 'bill-1', 'B')

    def test_late_evidence_creates_supplement_not_overwrite(self):
        # Ambiguous at month end: nothing billed.
        bh.build_month_end(self.db)
        self.assertEqual(cb.issue_batch(self.db, 'bill-A', 'A')['metric'], 0)
        ra.bind_evidence(self.db, 'Q', 'A', 'late-binding', at=200)
        sup = cb.supplement(self.db, 'sup-1', 'bill-A', 'Q', at=201)
        self.assertEqual(sup['units'], 700)
        self.assertEqual(sup['kind'], 'supplement')
        self.assertEqual(self.db.execute('SELECT metric FROM bill_batches WHERE id=?', ('bill-A',)).fetchone()[0], 700)
        # Supplement replay is idempotent; the token cannot be billed again by a new batch.
        self.assertEqual(cb.supplement(self.db, 'sup-1', 'bill-A', 'Q', at=201)['status'], 'replayed')
        self.assertEqual(cb.issue_batch(self.db, 'bill-A-2', 'A')['metric'], 0)

    def test_supplement_rejected_while_still_ambiguous(self):
        bh.build_month_end(self.db)
        with self.assertRaises(ValueError):
            cb.supplement(self.db, 'sup-1', 'bill-A', 'Q')

    def test_reversal_entry_keeps_history_and_changes_balance_only(self):
        self._full_request('q1', units=100)
        cb.issue_batch(self.db, 'bill-1', 'A')
        out = cb.reverse(self.db, 'rev-1', 'bill-1', 'q1', 100, at=50)
        self.assertEqual(out['kind'], 'reversal')
        self.assertEqual(cb.account(self.db, 'A')['balance'], 0)
        adjustment = self.db.execute('SELECT kind,units FROM bill_adjustments').fetchone()
        self.assertEqual(tuple(adjustment), ('reversal', 100))
        # Original batch row still carries its history through the adjustment trail.
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM bill_items').fetchone()[0], 1)
        with self.assertRaises(ValueError):
            cb.reverse(self.db, 'rev-2', 'bill-1', 'q1', 1)
        # Reversal replay.
        self.assertEqual(cb.reverse(self.db, 'rev-1', 'bill-1', 'q1', 100, at=50)['status'], 'replayed')


if __name__ == '__main__':
    unittest.main()
