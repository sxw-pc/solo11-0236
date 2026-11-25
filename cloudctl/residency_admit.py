"""Provisional written result for data residency admission."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS residency_orders (subject TEXT,metric INTEGER)')
    value=sum(r['region'] for (raw,) in db.execute('SELECT rows_json FROM zone_pages') for r in json.loads(raw) if r['tenant']==subject)
    with db:db.execute('INSERT INTO residency_orders VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
