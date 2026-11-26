"""Read/write entry points bound to one proven commit prefix and one term.

Reads during the outage are served from the proven commit prefix (never from a
candidate's unconfirmed suffix) and carry a ``view_digest``.  A read-only
client that retries must pass the digest it first saw as ``expected_view``;
if the directory would move underneath it the retry is refused instead of
being silently rerouted to the other endpoint.

Writes are only accepted once a lease has been issued and every other write
entry point is fenced; a repeated ``request_id`` is answered from the applied
log, so an endpoint change is never applied twice.
"""
from . import leader_lease as lease

def consistent_read(db,request=None,**kw):
    """Serve a consistent endpoint directory.

    ``consistent_read(db, at=10)`` and ``consistent_read(db, {'at':10})`` are
    equivalent; the request dict form is used by :func:`cloudctl.__main__.execute`.
    """
    return lease.read(db,request,**kw)

def write_endpoint(db,request=None,**kw):
    """Apply one endpoint change exactly once under the current write term."""
    return lease.write(db,request,**kw)
