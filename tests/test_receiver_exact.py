"""Receiver authority tests: actual SQLite effects, not only status codes."""
from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from openline_connect.onboarding import initialize, allow, read_engine, verify_local
from openline_connect.signing import digest, pub, sign, verify
from openline_connect.verify import inspect


class ExactAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / 'receiver'
        self.bootstrap = initialize(self.home)

    def approved(self):
        g = allow(self.home, action='record.update', target='customer-1',
                  value='approved', amount_cents=100, ttl_seconds=240)
        return g, json.loads(Path(g['fictional_agent_request']).read_text())

    def fresh_mandate(self, original, params, jti):
        buyer = (self.home / 'keys/fictional-buyer.seed').read_text().strip()
        existing = verify(original['authorization'],
                          {'fictional-buyer': pub(buyer)},
                          kind='openline.connect.mandate.v1')
        claims = {**existing, 'parameters_sha256': digest(params),
                  'target': params['target'], 'jti': jti}
        return sign(claims, buyer, 'fictional-buyer')

    def rows(self):
        with sqlite3.connect(self.home / 'connect.sqlite') as db:
            records = db.execute('SELECT record_id,content FROM records ORDER BY record_id').fetchall()
            operations = db.execute('SELECT state FROM operations ORDER BY nonce').fetchall()
            decisions = db.execute('SELECT COUNT(*) FROM decisions').fetchone()[0]
        return records, operations, decisions

    def test_changed_value_signed_by_buyer_is_denied_without_effect(self):
        grant, request = self.approved()
        params = {**request['params'], 'value': 'not-approved'}
        forged_buyer_request = self.fresh_mandate(request, params, 'different-jti')
        engine = read_engine(self.home)
        denied = engine.execute(action='record.update', params=params,
                                authorization=forged_buyer_request, nonce='change-value')
        self.assertEqual(denied['reason'], 'receiver_allowlist_denied')
        self.assertEqual(denied['state'], 'REFUSED_PRE_EFFECT')
        self.assertEqual(self.rows()[0], [])
        self.assertEqual(self.rows()[2], 1)
        correct = engine.execute(**request)
        self.assertEqual(correct['state'], 'FULFILLED')
        self.assertEqual(self.rows()[0], [('customer-1', '{"value": "approved"}')])
        self.assertEqual(self.rows()[2], 2)
        self.assertTrue(verify_local(self.home, seller_public=self.bootstrap['seller_public'],
                                     expected_seq=2, expected_head=correct['head_decision_hash'])['verified'])
        policy = json.loads((self.home / 'policy.json').read_text())
        receiver_claim = verify(policy['grants']['record.update'][0]['receiver_signature'],
                                {'seller': self.bootstrap['seller_public']},
                                kind='openline.connect.receiver_grant.v1')
        self.assertEqual(receiver_claim['parameters_sha256'], digest(request['params']))

    def test_changed_target_and_amount_below_ceiling_are_denied(self):
        _, request = self.approved()
        engine = read_engine(self.home)
        for suffix, changed in [
            ('target', {**request['params'], 'target': 'customer-2'}),
            ('amount', {**request['params'], 'amount_cents': 99}),
            ('over', {**request['params'], 'amount_cents': 101}),
        ]:
            response = engine.execute(action='record.update', params=changed,
                                      authorization=self.fresh_mandate(request, changed, suffix),
                                      nonce='modified-'+suffix)
            self.assertEqual(response['state'], 'REFUSED_PRE_EFFECT')
            self.assertEqual(response['reason'], 'receiver_allowlist_denied')
        self.assertEqual(self.rows()[0], [])
        self.assertEqual(self.rows()[2], 3)

    def test_missing_digest_and_legacy_grant_fail_closed(self):
        _, request = self.approved()
        policy_path = self.home / 'policy.json'
        policy = json.loads(policy_path.read_text())
        grant = policy['grants']['record.update'][0]
        grant.pop('parameters_sha256')
        seller = (self.home / 'keys/receiver.seed').read_text().strip()
        grant['receiver_signature'] = sign({**{k:v for k,v in grant.items()
                                            if k != 'receiver_signature'},
                                           'kind': 'openline.connect.receiver_grant.v1'},
                                          seller, 'seller')
        policy_path.write_text(json.dumps(policy))
        denied = read_engine(self.home).execute(**request)
        self.assertEqual(denied['reason'], 'receiver_allowlist_denied')
        self.assertEqual(self.rows()[0], [])
        self.assertEqual(self.rows()[2], 1)

    def test_independent_revoke_mandate_and_receiver_grant(self):
        grant, request = self.approved()
        engine = read_engine(self.home)
        engine.revoke(grant['grant_id'])
        rejected = engine.execute(**request)
        self.assertEqual(rejected['reason'], 'revoked_mandate')
        another = {**request, 'authorization': self.fresh_mandate(request, request['params'], 'new-token'),
                   'nonce': 'new-mandate'}
        allowed = engine.execute(**another)
        self.assertEqual(allowed['state'], 'FULFILLED')
        engine.revoke_grant(grant['grant_id'])
        after_restart = read_engine(self.home)
        again = {**request, 'authorization': self.fresh_mandate(request, request['params'], 'third-token'),
                 'nonce': 'after-grant-revocation'}
        denied = after_restart.execute(**again)
        self.assertEqual(denied['reason'], 'receiver_allowlist_denied')
        self.assertEqual(self.rows()[0], [('customer-1', '{"value": "approved"}')])
        self.assertEqual(self.rows()[2], 3)

    def test_replay_across_restart_and_concurrent_attempts(self):
        _, request = self.approved()
        engine = read_engine(self.home)
        def call(_):
            return engine.execute(**request)
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(call, range(16)))
        self.assertEqual(sum(x['state']=='FULFILLED' for x in responses), 16)
        self.assertEqual(sum(not x.get('replayed',False) for x in responses), 1)
        self.assertEqual(self.rows()[2], 1)
        self.assertEqual(self.rows()[0], [('customer-1', '{"value": "approved"}')])
        self.assertTrue(read_engine(self.home).execute(**request)['replayed'])

    def test_effect_entry_uses_new_clock_not_preflight_clock(self):
        _, request = self.approved()
        engine = read_engine(self.home)
        start = int(time.time())
        ticks = iter([start, start+500])
        engine.clock = lambda: next(ticks)
        denied = engine.execute(**request)
        self.assertEqual(denied['state'], 'REFUSED_PRE_EFFECT')
        self.assertIn(denied['reason'], ('authorization_expired', 'receiver_allowlist_denied'))
        self.assertEqual(self.rows()[0], [])

    def test_signed_history_without_pin_is_not_complete_history(self):
        _, request = self.approved()
        engine = read_engine(self.home)
        first = engine.execute(**request)
        second = engine.execute(action='record.update',
                                params={**request['params'], 'value':'other'},
                                authorization=self.fresh_mandate(request,
                                    {**request['params'], 'value':'other'},'other'),
                                nonce='second')
        self.assertEqual(second['state'], 'REFUSED_PRE_EFFECT')
        partial = inspect([first], {'seller':self.bootstrap['seller_public']})
        self.assertTrue(partial['verified'])
        self.assertFalse(partial['history_complete_relative_to_checkpoint'])
        with self.assertRaises(ValueError):
            inspect([first], {'seller':self.bootstrap['seller_public']},
                    expected_seq=2, expected_head=second['head_decision_hash'])
        complete = inspect([first,second], {'seller':self.bootstrap['seller_public']},
                           expected_seq=2, expected_head=second['head_decision_hash'])
        self.assertTrue(complete['history_complete_relative_to_checkpoint'])


if __name__ == '__main__':
    unittest.main()
