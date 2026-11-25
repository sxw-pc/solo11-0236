"""Provisional written result for application rollout."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS rollout_orders (subject TEXT,metric INTEGER)')
    value=sum(r['revision'] for (raw,) in db.execute('SELECT rows_json FROM release_pages') for r in json.loads(raw) if r['service']==subject)
    with db:db.execute('INSERT INTO rollout_orders VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
