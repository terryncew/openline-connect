"""Challenge: long-lived receiver cache versus durable revocation. This exposes a
documented operational limitation; it does not claim policy files are live controls.
"""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from openline_connect.onboarding import initialize, allow, read_engine

class PolicyLivenessChallenge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / 'receiver'
        initialize(self.home)
        self.grant = allow(self.home, action='record.update', target='customer-1',
                           value='approved', amount_cents=100, ttl_seconds=240)
        self.request = json.loads(Path(self.grant['fictional_agent_request']).read_text())
        self.live = read_engine(self.home)

    def remove_grant_from_file(self):
        path=self.home/'policy.json'
        policy=json.loads(path.read_text())
        policy['grants']['record.update']=[]
        path.write_text(json.dumps(policy))

    def effect_count(self):
        with sqlite3.connect(self.home/'connect.sqlite') as db:
            return db.execute('SELECT count(*) FROM records').fetchone()[0]

    def test_file_change_is_not_live_revocation_of_existing_server(self):
        self.remove_grant_from_file()
        # This is an EXECUTED limitation: the still-running server holds its copy.
        admitted=self.live.execute(**self.request)
        self.assertEqual(admitted['state'],'FULFILLED')
        self.assertEqual(self.effect_count(),1)
        fresh=read_engine(self.home)
        denied=fresh.execute(**{**self.request,'nonce':'after-restart'})
        self.assertEqual(denied['reason'],'receiver_allowlist_denied')
        self.assertEqual(self.effect_count(),1)

    def test_durable_receiver_revoke_blocks_cached_policy_without_restart(self):
        self.remove_grant_from_file()
        self.live.revoke_grant(self.grant['grant_id'])
        result=self.live.execute(**self.request)
        self.assertEqual(result['reason'],'receiver_allowlist_denied')
        self.assertEqual(self.effect_count(),0)

if __name__ == '__main__':
    unittest.main()
