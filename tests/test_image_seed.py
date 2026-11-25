import sqlite3,unittest
from cloudctl.image_attest import capture
from cloudctl.image_promote import promote
class ImageSeed(unittest.TestCase):
 def test_capture_changes_written_promotion(self):
  db=sqlite3.connect(":memory:");r=[{"image":"api","build":"b2","builder":"ci","digest":"d2"}]
  self.assertEqual(capture(db,"p1",r),"captured");self.assertEqual(promote(db,"api")["build"],"b2")
  self.assertEqual(capture(db,"p1",r),"replayed")
  with self.assertRaises(ValueError):capture(db,"p1",[{**r[0],"digest":"d3"}])
