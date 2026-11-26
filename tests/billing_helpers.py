"""Shared builders for the three-segment billing tests."""
from cloudctl import billing_facts as bf


def admit(db, token):
    """Mark an admitted call directly, mirroring admission.py handshakes/admissions."""
    db.execute('CREATE TABLE IF NOT EXISTS admissions(id TEXT PRIMARY KEY,handshake TEXT,decision TEXT,at INTEGER)')
    db.execute('INSERT OR REPLACE INTO admissions VALUES(?,?,?,?)', (token, token, 'allowed', 0))


def build_month_end(db, skew_primary=0, skew_backup=0):
    """Two proxy pages for one request Q: primary timeout, backup success.

    Both proxies physically transmit 700 units of upstream bandwidth while the
    backend executes Q exactly once.  No independent binding evidence exists,
    so the tenant world (A or B) stays ambiguous.
    """
    admit(db, 'Q')
    request_rows = [{
        'token': 'Q', 'tenant': 'A', 'path': '/v1/run', 'units': 700,
        'admission': 'allowed', 'cert_generation': 1, 'at': 100,
    }]
    primary_rows = [{
        'proxy': 'proxy-primary', 'token': 'Q', 'status': 'timeout', 'units': 700,
        'cert_generation': 1, 'receipt': '', 'link_counter': 1000, 'at': 101,
    }]
    backup_rows = [{
        'proxy': 'proxy-backup', 'token': 'Q', 'status': 'success', 'units': 700,
        'cert_generation': 2, 'receipt': 'rcpt-Q-1', 'link_counter': 2000, 'at': 105,
    }]
    backend_rows = [{
        'receipt': 'rcpt-Q-1', 'token': 'Q', 'status': 'success', 'units': 700, 'at': 106,
    }]
    return (
        bf.capture_request(db, 'page-request', request_rows, 'gw', stored_at=100),
        bf.capture_proxy(db, 'page-primary', primary_rows, 'proxy-primary-device',
                         clock_skew=skew_primary, stored_at=110),
        bf.capture_proxy(db, 'page-backup', backup_rows, 'proxy-backup-device',
                         clock_skew=skew_backup, stored_at=111),
        bf.capture_backend(db, 'page-backend', backend_rows, 'backend-device', stored_at=112),
    )
