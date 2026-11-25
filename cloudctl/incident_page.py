"""Provisional written result for incident escalation."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS incident_pages (subject TEXT,metric INTEGER)')
    value=sum(r['errors'] for (raw,) in db.execute('SELECT rows_json FROM trace_pages') for r in json.loads(raw) if r['service']==subject)
    with db:db.execute('INSERT INTO incident_pages VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
