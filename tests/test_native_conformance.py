import sys,unittest
from openline_connect.native_conformance import run
class TestNativeConformance(unittest.TestCase):
 def test_honest_supplier_native(self):
  result=run(sys.executable+' -m openline_connect.conformance_sample')
  self.assertEqual(result['status'],'PASS',result)
  self.assertEqual(sum(result['checks'].values()),len(result['checks']))
 def test_fabrication_negative_control(self):
  result=run(sys.executable+' -m openline_connect.conformance_defective')
  self.assertEqual(result['status'],'FAIL',result)
  self.assertFalse(result['checks']['observer_matching_local_controller'])
  self.assertFalse(result['checks']['valid_supplier_initiated_admission'])
