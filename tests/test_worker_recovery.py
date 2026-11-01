"""True cross-process recovery without administrator credential, exact scope and receipts."""
import concurrent.futures,sqlite3,time
from openline_connect.signing import pub,digest
from openline_connect.accept_bridge import make_worker_recovery
from tests.test_real_accept_http import ConnectToActualAccept

class WorkerRecovery(ConnectToActualAccept):
    def recovery(self,*,worker='worker_b',buyer='buyer-01',po='PO-A-001',sha=None,policy_seq=None,now=None,ttl=120):
        return make_worker_recovery(buyer=buyer,po=po,receiver_id='supplier',request_sha256=sha or self.first['verified_decision']['order_hash'],
                  buyer_seed=self.keys['buyer'],worker_seed=self.keys[worker],worker_public=pub(self.keys[worker]),
                  policy_seq=policy_seq or self.policy_seq,now=now or int(time.time()),ttl=ttl)
    def prepare(self):
        self.first=self.client.request(self.order('PO-A-001'));self.assertEqual(self.first['decision'],'ACCEPTED')
        self._stop();self.policy_seq+=1;self.policy=self._policy('worker_b');self._launch()
        with sqlite3.connect(self.root/'accept.sqlite') as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM business_jobs').fetchone()[0],1)
    def test_true_successor_recovery_and_denials(self):
        self.prepare()
        proof=self.recovery()
        recovered=self.client.recover_worker(**proof)
        self.assertEqual(recovered['receipt'],self.first['receipt'])
        self.assertEqual(recovered['outcome'],self.first['outcome'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda _:self.client.recover_worker(**proof),range(16)))
        self.assertTrue(all(x['receipt']==self.first['receipt'] for x in results))
        with sqlite3.connect(self.root/'accept.sqlite') as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM business_jobs').fetchone()[0],1)
        attacks=[self.recovery(worker='worker_a'),self.recovery(po='PO-OTHER'),self.recovery(buyer='buyer-99'),
                 self.recovery(sha='0'*64),self.recovery(policy_seq=1),self.recovery(now=int(time.time())-1000,ttl=1)]
        for bad in attacks:
            with self.subTest(attack=list(attacks).index(bad)):
                with self.assertRaises(ValueError):self.client.recover_worker(**bad)
        # Fresh nonce or JTI never rescues a former worker whose public key was removed from seller policy.
        for _ in range(3):
            with self.assertRaises(ValueError):self.client.recover_worker(**self.recovery(worker='worker_a'))
    def test_recovery_after_receiver_process_exit(self):
        self.prepare();self._stop();self.policy_seq+=1;self.policy=self._policy('worker_b');self._launch()
        out=self.client.recover_worker(**self.recovery());self.assertEqual(out['receipt'],self.first['receipt'])
    def test_policy_revokes_successor_identity(self):
        self.prepare()
        p=self.recovery()
        self._stop();self.policy_seq+=1;self.policy=self._policy('worker_b')
        self.policy['revoked']=[pub(self.keys['worker_b'])]
        self._launch()
        with self.assertRaises(ValueError):self.client.recover_worker(**p)
if __name__=='__main__':import unittest;unittest.main()
