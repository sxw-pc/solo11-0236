"""Provisional written result for tenant service usage."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS usage_statements (subject TEXT,metric INTEGER)')
    value=sum(r['units'] for (raw,) in db.execute('SELECT rows_json FROM meter_pages') for r in json.loads(raw) if r['tenant']==subject)
    with db:db.execute('INSERT INTO usage_statements VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
