import sqlite3, unittest
from cloudctl import billing_facts as bf


class FactCaptureTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')

    def test_three_segments_capture_and_replay(self):
        req = [{'token': 't1', 'tenant': 'A', 'path': '/x', 'units': 10,
                'admission': 'allowed', 'cert_generation': 1, 'at': 1}]
        self.assertEqual(bf.capture_request(self.db, 'rp', req, 'dev', stored_at=2), 'captured')
        self.assertEqual(bf.capture_request(self.db, 'rp', req, 'dev', stored_at=2), 'replayed')
        with self.assertRaises(ValueError):
            bf.capture_request(self.db, 'rp', [dict(req[0], units=11)], 'dev', stored_at=2)

        proxy = [{'proxy': 'p1', 'token': 't1', 'status': 'success', 'units': 10,
                  'cert_generation': 1, 'receipt': 'r1', 'link_counter': 5, 'at': 2}]
        self.assertEqual(bf.capture_proxy(self.db, 'pp', proxy, 'dev', stored_at=3), 'captured')
        self.assertEqual(bf.capture_proxy(self.db, 'pp', proxy, 'dev', stored_at=3), 'replayed')

        backend = [{'receipt': 'r1', 'token': 't1', 'status': 'success', 'units': 10, 'at': 3}]
        self.assertEqual(bf.capture_backend(self.db, 'bp', backend, 'dev', stored_at=4), 'captured')
        self.assertEqual(bf.capture_backend(self.db, 'bp', backend, 'dev', stored_at=4), 'replayed')

    def test_originals_keep_every_required_fact(self):
        req = [{'token': 't1', 'tenant': 'A', 'path': '/x', 'units': 10,
                'admission': 'allowed', 'cert_generation': 3, 'at': 7}]
        bf.capture_request(self.db, 'rp', req, 'dev', clock_skew=4, stored_at=99)
        row = self.db.execute('SELECT tenant,path,units,cert_generation,at,at_norm FROM request_facts WHERE token=?', ('t1',)).fetchone()
        self.assertEqual(tuple(row), ('A', '/x', 10, 3, 7, 11))
        page = self.db.execute('SELECT device,clock_skew,stored_at FROM request_pages').fetchone()
        self.assertEqual(tuple(page), ('dev', 4, 99))

        proxy = [{'proxy': 'p1', 'token': 't1', 'status': 'timeout', 'units': 10,
                  'cert_generation': 3, 'receipt': '', 'link_counter': 8, 'at': 8}]
        bf.capture_proxy(self.db, 'pp', proxy, 'dev', clock_skew=-2, stored_at=100)
        row = self.db.execute('SELECT proxy,token,cert_generation,receipt,link_counter,at_norm FROM proxy_facts').fetchone()
        self.assertEqual(tuple(row), ('p1', 't1', 3, '', 8, 6))
        self.assertEqual(self.db.execute('SELECT stored_at FROM proxy_pages').fetchone()[0], 100)

    def test_clock_skew_acts_on_the_whole_device_page_only(self):
        rows = [
            {'token': 't1', 'tenant': 'A', 'path': '/x', 'units': 1, 'admission': 'allowed', 'cert_generation': 1, 'at': 10},
            {'token': 't2', 'tenant': 'A', 'path': '/x', 'units': 1, 'admission': 'allowed', 'cert_generation': 1, 'at': 20},
        ]
        bf.capture_request(self.db, 'rp', rows, 'dev', clock_skew=5, stored_at=1)
        norms = [r[0] for r in self.db.execute('SELECT at_norm-at FROM request_facts ORDER BY token')]
        self.assertEqual(norms, [5, 5])

    def test_invalid_rows_rejected(self):
        good = [{'token': 't1', 'tenant': 'A', 'path': '/x', 'units': 1,
                 'admission': 'allowed', 'cert_generation': 1, 'at': 1}]
        with self.assertRaises(ValueError):
            bf.capture_request(self.db, 'rp', [dict(good[0], units=-1)], 'dev')
        with self.assertRaises(ValueError):
            bf.capture_request(self.db, 'rp', [{'token': 't1'}], 'dev')
        with self.assertRaises(ValueError):
            bf.capture_request(self.db, 'rp', good, '')
        bad_proxy = [{'proxy': 'p1', 'token': 't1', 'status': 'weird', 'units': 1,
                      'cert_generation': 1, 'receipt': '', 'link_counter': 1, 'at': 1}]
        with self.assertRaises(ValueError):
            bf.capture_proxy(self.db, 'pp', bad_proxy, 'dev')
        no_receipt = [{'proxy': 'p1', 'token': 't1', 'status': 'success', 'units': 1,
                       'cert_generation': 1, 'receipt': '', 'link_counter': 1, 'at': 1}]
        with self.assertRaises(ValueError):
            bf.capture_proxy(self.db, 'pp', no_receipt, 'dev')

    def test_same_token_twice_is_two_requests_not_merged_by_digest(self):
        r1 = [{'token': 'q1', 'tenant': 'A', 'path': '/p', 'units': 5,
               'admission': 'allowed', 'cert_generation': 1, 'at': 1}]
        r2 = [{'token': 'q2', 'tenant': 'A', 'path': '/p', 'units': 5,
               'admission': 'allowed', 'cert_generation': 1, 'at': 2}]
        bf.capture_request(self.db, 'rp1', r1, 'dev')
        bf.capture_request(self.db, 'rp2', r2, 'dev')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM request_facts').fetchone()[0], 2)

    def test_physical_link_counter_cannot_regress_on_a_device(self):
        first = [{'proxy': 'p1', 'token': 't1', 'status': 'timeout', 'units': 1,
                  'cert_generation': 1, 'receipt': '', 'link_counter': 100, 'at': 1}]
        second = [{'proxy': 'p2', 'token': 't2', 'status': 'timeout', 'units': 1,
                   'cert_generation': 1, 'receipt': '', 'link_counter': 99, 'at': 2}]
        bf.capture_proxy(self.db, 'pp1', first, 'same-device')
        with self.assertRaises(ValueError):
            bf.capture_proxy(self.db, 'pp2', second, 'same-device')
        # A different device owns its own counter sequence.
        self.assertEqual(bf.capture_proxy(self.db, 'pp3', second, 'other-device'), 'captured')

    def test_receipt_reused_by_another_token_conflicts(self):
        b1 = [{'receipt': 'r1', 'token': 't1', 'status': 'success', 'units': 1, 'at': 1}]
        b2 = [{'receipt': 'r1', 'token': 't2', 'status': 'success', 'units': 1, 'at': 2}]
        bf.capture_backend(self.db, 'bp1', b1, 'dev')
        with self.assertRaises(ValueError):
            bf.capture_backend(self.db, 'bp2', b2, 'dev')


if __name__ == '__main__':
    unittest.main()
