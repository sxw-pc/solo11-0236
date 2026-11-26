import sqlite3, unittest
from tests import billing_helpers as bh
from cloudctl import billing_facts as bf
from cloudctl import request_attribution as ra


class AttributionTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row

    def _request(self, token, admission='allowed', tenant='A', units=700, gen=1):
        return [{'token': token, 'tenant': tenant, 'path': '/v1/run', 'units': units,
                 'admission': admission, 'cert_generation': gen, 'at': 100}]

    def _proxy(self, token, proxy, status, units=700, gen=1, receipt=None, counter=1000):
        if receipt is None:
            receipt = 'rcpt-' + token if status == 'success' else ''
        return [{'proxy': proxy, 'token': token, 'status': status, 'units': units,
                 'cert_generation': gen, 'receipt': receipt, 'link_counter': counter, 'at': 101}]

    def _backend(self, token, status='success', units=700, receipt=None):
        return [{'receipt': receipt or 'rcpt-' + token, 'token': token,
                 'status': status, 'units': units, 'at': 106}]

    def test_denied_request_is_never_billable_but_traffic_still_settles(self):
        bh.admit(self.db, 'D')
        bf.capture_request(self.db, 'rp', self._request('D', admission='denied'), 'gw')
        bf.capture_proxy(self.db, 'pp', self._proxy('D', 'p1', 'timeout', counter=1), 'dev')
        r = ra.resolve(self.db, 'D')
        self.assertEqual(r['state'], ra.DENIED)
        self.assertEqual(r['units'], 0)
        self.assertEqual(r['transmissions'], 1)

    def test_control_plane_denial_corroborates_and_overrides_page_claim(self):
        bf.capture_request(self.db, 'rp', self._request('D'), 'gw')
        # No admission record yet: the meter page's own decision stands.
        self.assertNotEqual(ra.resolve(self.db, 'D')['state'], ra.DENIED)
        bh.admit(self.db, 'D')
        self.db.execute("UPDATE admissions SET decision='denied' WHERE handshake='D'")
        r = ra.resolve(self.db, 'D')
        self.assertEqual(r['state'], ra.DENIED)

    def test_timeout_without_backend_success_is_not_executed(self):
        bh.admit(self.db, 'T')
        bf.capture_request(self.db, 'rp', self._request('T'), 'gw')
        bf.capture_proxy(self.db, 'pp', self._proxy('T', 'p1', 'timeout', counter=1), 'dev')
        r = ra.resolve(self.db, 'T')
        self.assertEqual(r['state'], ra.NOT_EXECUTED)
        self.assertEqual(r['transmissions'], 1)
        self.assertEqual(r['executions'], 0)

    def test_proxy_receipt_without_backend_receipt_is_a_mismatch(self):
        bh.admit(self.db, 'M')
        bf.capture_request(self.db, 'rp', self._request('M'), 'gw')
        bf.capture_proxy(self.db, 'pp', self._proxy('M', 'p1', 'success', receipt='ghost', counter=1), 'dev')
        r = ra.resolve(self.db, 'M')
        self.assertEqual(r['state'], ra.RECEIPT_MISMATCH)

    def test_two_backend_receipts_flag_multiple_executions(self):
        bh.admit(self.db, 'X')
        bf.capture_request(self.db, 'rp', self._request('X'), 'gw')
        bf.capture_proxy(self.db, 'pp', self._proxy('X', 'p1', 'success', receipt='r1', counter=1), 'dev')
        bf.capture_backend(self.db, 'bp1', self._backend('X', receipt='r1'), 'dev')
        bf.capture_backend(self.db, 'bp2', self._backend('X', receipt='r2'), 'dev2')
        r = ra.resolve(self.db, 'X')
        self.assertEqual(r['state'], ra.MULTIPLE_EXECUTIONS)
        self.assertEqual(r['executions'], 2)
        self.assertEqual(r['units'], 0)

    def test_distinct_tokens_never_merge_on_equal_path_and_units(self):
        for token in ('q1', 'q2'):
            bh.admit(self.db, token)
            bf.capture_request(self.db, 'rp-' + token, self._request(token), 'gw')
            bf.capture_proxy(self.db, 'pp-' + token,
                             self._proxy(token, 'p-' + token, 'success', counter=1), 'dev')
            bf.capture_backend(self.db, 'bp-' + token, self._backend(token), 'dev')
            ra.bind_evidence(self.db, token, 'A', 'bind-' + token, at=1)
        ra.resolve_all(self.db)
        rows = self.db.execute("SELECT token,units FROM request_resolutions WHERE state='attributed' ORDER BY token").fetchall()
        self.assertEqual([tuple(r) for r in rows], [('q1', 700), ('q2', 700)])

    def test_binding_evidence_is_idempotent_and_cannot_switch_tenant(self):
        bh.admit(self.db, 'Q')
        bf.capture_request(self.db, 'rp', self._request('Q'), 'gw')
        bf.capture_proxy(self.db, 'pp', self._proxy('Q', 'p1', 'success', counter=1), 'dev')
        bf.capture_backend(self.db, 'bp', self._backend('Q'), 'dev')
        self.assertEqual(ra.bind_evidence(self.db, 'Q', 'A', 'ledger', at=1), 'bound')
        self.assertEqual(ra.bind_evidence(self.db, 'Q', 'A', 'ledger', at=1), 'replayed')
        with self.assertRaises(ValueError):
            ra.bind_evidence(self.db, 'Q', 'B', 'ledger', at=2)
        self.assertEqual(ra.resolve(self.db, 'Q')['tenant'], 'A')

    def test_ambiguous_then_resolved_after_late_evidence(self):
        bh.admit(self.db, 'Q')
        bf.capture_request(self.db, 'rp', self._request('Q'), 'gw')
        bf.capture_proxy(self.db, 'pp', self._proxy('Q', 'p1', 'success', counter=1), 'dev')
        bf.capture_backend(self.db, 'bp', self._backend('Q'), 'dev')
        self.assertEqual(ra.resolve(self.db, 'Q')['state'], ra.AMBIGUOUS)
        ra.bind_evidence(self.db, 'Q', 'B', 'independent-binding', at=9)
        r = ra.resolve(self.db, 'Q')
        self.assertEqual(r['state'], ra.ATTRIBUTED)
        self.assertEqual(r['tenant'], 'B')

    def test_missing_request_token(self):
        self.assertEqual(ra.resolve(self.db, 'nope')['state'], ra.MISSING_REQUEST)


if __name__ == '__main__':
    unittest.main()
