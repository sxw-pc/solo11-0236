"""Provisional written result for request queue backpressure."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS backpressure_orders (subject TEXT,metric INTEGER)')
    value=sum(r['depth'] for (raw,) in db.execute('SELECT rows_json FROM queue_pages') for r in json.loads(raw) if r['service']==subject)
    with db:db.execute('INSERT INTO backpressure_orders VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
