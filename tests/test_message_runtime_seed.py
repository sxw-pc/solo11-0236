import sqlite3,unittest
from cloudctl import message_intake,message_result,offset_checkpoint

class MessageRuntimeSeed(unittest.TestCase):
    def test_output_and_progress_are_independent(self):
        db=sqlite3.connect(':memory:')
        self.assertEqual(message_intake.accept(db,'orders',0,7,'prod',1,'P',None,{'value':'parent'}),'accepted')
        self.assertEqual(message_intake.accept(db,'orders',1,4,'prod',2,'C','P',{'value':'child'}),'accepted')
        self.assertEqual(message_result.finish(db,'orders',0,7,'fast',2),'finished')
        offset_checkpoint.acknowledge(db,'fast','orders',0,6,2)
        self.assertEqual(db.execute('SELECT business_key FROM message_results').fetchone()[0],'P')
        self.assertEqual(db.execute('SELECT offset_id FROM offset_checkpoints').fetchone()[0],6)
        db.close()
