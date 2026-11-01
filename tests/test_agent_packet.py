"""Proposed public packet smoke tests. No private repositories or founder notes required."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class PublicPacket(unittest.TestCase):
    def run_example(self, filename):
        r = subprocess.run([sys.executable, str(ROOT / 'examples' / filename)],
                           cwd=tempfile.gettempdir(), capture_output=True, text=True, timeout=20)
        self.assertEqual(r.returncode, 0, r.stderr)
        output = json.loads(r.stdout)
        self.assertEqual(output['status'], 'PASS')
        return output

    def test_only_public_sdk_custom_ticket_receiver(self):
        x = self.run_example('support_ticket_receiver.py')
        self.assertEqual(x['committed_rows'], 1)
        self.assertTrue(x['unauthorized_refused'])
        self.assertTrue(x['signed_local_sqlite_verified'])

    def test_conventional_independent_stack_reference(self):
        x = self.run_example('conventional_ticket_receiver.py')
        self.assertTrue(x['successor_recovers_original'])
        self.assertTrue(x['revoked_worker_denied'])

    def test_agent_docs_and_result_schema(self):
        for name in ('AGENTS.md', '.agents/skills/openline-connect/SKILL.md',
                     'docs/AI_EVALUATION.md', 'docs/CONFORMANCE_RESULT.md',
                     'docs/NATIVE_CONFORMANCE.md'):
            self.assertGreater((ROOT / name).stat().st_size, 100)
        schema = json.loads((ROOT / 'docs/conformance_result.schema.json').read_text())
        self.assertEqual(set(schema['required']), {'status','checks','elapsed_seconds','limitations'})
        self.assertEqual(schema['properties']['status']['enum'], ['PASS','FAIL'])

if __name__ == '__main__': unittest.main()
