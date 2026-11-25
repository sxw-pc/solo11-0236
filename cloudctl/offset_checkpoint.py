"""Broker progress record, independent of the worker output transaction."""
def acknowledge(db,group,stream,partition,offset,epoch):
    db.execute('CREATE TABLE IF NOT EXISTS offset_checkpoints (group_id TEXT,stream TEXT,partition_id INTEGER,offset_id INTEGER,epoch INTEGER,PRIMARY KEY(group_id,stream,partition_id))')
    old=db.execute('SELECT offset_id,epoch FROM offset_checkpoints WHERE group_id=? AND stream=? AND partition_id=?',(group,stream,partition)).fetchone()
    if old and (epoch<old[1] or offset<old[0]): raise ValueError('stale_checkpoint')
    with db: db.execute('INSERT INTO offset_checkpoints VALUES (?,?,?,?,?) ON CONFLICT(group_id,stream,partition_id) DO UPDATE SET offset_id=excluded.offset_id,epoch=excluded.epoch',(group,stream,partition,offset,epoch))
    return {'group':group,'offset':offset,'epoch':epoch}
