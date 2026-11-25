"""Provisional prefix route from captured regional probe rows."""

from .route_probe import ensure_rows

def announce(db,prefix):
    ensure_rows(db)
    db.execute('CREATE TABLE IF NOT EXISTS traffic_announcements (prefix TEXT,region TEXT,observed_ms INTEGER)')
    row=db.execute('SELECT region,rtt_ms FROM route_probe_rows WHERE prefix=? AND reachable=1 ORDER BY rtt_ms,region LIMIT 1',(prefix,)).fetchone()
    if not row:return {'decision':'no_route','prefix':prefix}
    with db:db.execute('INSERT INTO traffic_announcements VALUES (?,?,?)',(prefix,row[0],row[1]))
    return {'decision':'announced','prefix':prefix,'region':row[0]}
