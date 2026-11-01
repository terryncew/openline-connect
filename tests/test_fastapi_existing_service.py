"""Optional FastAPI integration acceptance. CI must install fastapi and httpx."""
import importlib.util,unittest
from pathlib import Path

class ExistingService(unittest.TestCase):
    def test_existing_fastapi_unauthorized_replay_receipt(self):
        if importlib.util.find_spec('fastapi') is None or importlib.util.find_spec('httpx') is None:
            self.skipTest('optional fastapi/httpx extras not installed; dedicated CI must run it')
        spec=importlib.util.spec_from_file_location('existing_service', Path(__file__).resolve().parents[1]/'examples'/'fastapi_existing_service.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        result=module.run()
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['sqlite_effect_rows'],2)
        self.assertTrue(result['worker_b_original_receipt_recovered'])

if __name__=='__main__':unittest.main()
