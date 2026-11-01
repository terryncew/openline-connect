import ast,unittest,subprocess,sys,tempfile
from pathlib import Path
from scenario import init,request,dispatch,receiver_path
from verify_standalone import audit
ROOT=Path(__file__).parent
class Boundaries(unittest.TestCase):
 def test_cleanroom_no_a_or_openline_engine_imports(self):
  disallowed=('receiver_a','candidate','conformance.consequence_controller','openline')
  for name in ('receiver_b.py','conventional_receiver.py','verify_standalone.py'):
   tree=ast.parse((ROOT/name).read_text())
   modules=[n.module or '' for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)]
   modules +=[a.name for n in ast.walk(tree) if isinstance(n,ast.Import) for a in n.names]
   self.assertFalse([x for x in modules if any(x==bad or x.startswith(bad+'.') for bad in disallowed)],name)
 def test_no_runtime_ros_imports(self):
  for name in ('receiver_a.py','receiver_b.py','controller.py'):
   self.assertNotIn('import rclpy',(ROOT/name).read_text())
 def test_forged_receipt_requires_real_controller_record(self):
  from defective_c import fake_admit
  with tempfile.TemporaryDirectory() as state:
   init(state);r=request(state,'A','A','tampered-result',2)
   fake_admit(receiver_path(state,'A'),r)
   result=audit(receiver_path(state,'A'))
   self.assertEqual(result['status'],'FAIL')
   self.assertTrue(any('FABRICATED_ADMISSION' in e for e in result['faults']))
 def test_unauthorized_request_does_not_touch_controller(self):
  with tempfile.TemporaryDirectory() as state:
   init(state);r=request(state,'A','A','bad-zone',2,zone='unexpected')
   result=dispatch(state,'A','admit',{'request':r})
   self.assertEqual(result['status'],'REFUSED')
   self.assertEqual(audit(receiver_path(state,'A'))['controller_effects'],0)
if __name__=='__main__':unittest.main()
