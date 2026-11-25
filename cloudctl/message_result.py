"""Current worker output path; output and broker progress are separate."""
import json

def finish(db,stream,partition,offset,worker,epoch):
    db.execute('CREATE TABLE IF NOT EXISTS message_results (business_key TEXT PRIMARY KEY,stream TEXT,partition_id INTEGER,offset_id INTEGER,worker TEXT,epoch INTEGER,result TEXT)')
    row=db.execute('SELECT business_key,parent_key,payload FROM intake WHERE stream=? AND partition_id=? AND offset_id=?',(stream,partition,offset)).fetchone()
    if not row: raise ValueError('missing_intake')
    key,parent,raw=row
    output={'key':key,'parent':parent,'value':json.loads(raw).get('value')}
    old=db.execute('SELECT result FROM message_results WHERE business_key=?',(key,)).fetchone()
    if old:
        if old[0]!=json.dumps(output,sort_keys=True): raise ValueError('result_conflict')
        return 'replayed'
    with db: db.execute('INSERT INTO message_results VALUES (?,?,?,?,?,?,?)',(key,stream,partition,offset,worker,epoch,json.dumps(output,sort_keys=True)))
    return 'finished'
