"""Real H01 Connect SDK -> real unmodified PR#90 Seller/HTTP gateway.

No simulated Accept service or test-private `scenarios` import. Two OS processes,
separately configured seller and buyer signing keys; local effects only.
"""
import json,os,secrets,socket,sqlite3,subprocess,sys,tempfile,time,unittest
from pathlib import Path
import urllib.request,urllib.error
from openline_connect.signing import pub
from openline_connect.accept_bridge import AcceptClient,agent_order

class ConnectToActualAccept(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name)
  self.keys={x:secrets.token_hex(32) for x in ('seller','buyer','worker_a','worker_b','contract','inventory')}
  with socket.socket() as s:
   s.bind(('127.0.0.1',0));self.port=s.getsockname()[1]
  self.admin=secrets.token_urlsafe(18)
  (self.root/'seller.seed').write_text(self.keys['seller'])
  self.now=int(time.time());self.policy_seq=1
  self.policy=self._policy('worker_a')
  self.proc=None
  self._launch()
 def _policy(self,who):
  return {'v':1,'kind':'policy','seller':'supplier','seq':self.policy_seq,
          'nbf':self.now-120,'exp':self.now+900,'sku':'industrial-filter-17',
          'unit_cents':250000,'max_units':20,'terms':'NET30_SYNTHETIC_v1',
          'buyers':{'buyer-01':{'profile':'agent_json','public':pub(self.keys['buyer']),
                      'provider_public':pub(self.keys[who]),'shared_secret':'not-used-agent-json'}},
          'sources':{'contract':pub(self.keys['contract']),'inventory':pub(self.keys['inventory'])},'revoked':[]}
 def _launch(self):
  config={'receiver_key_path':str(self.root/'seller.seed'),'sqlite_path':str(self.root/'accept.sqlite'),
          'admin_token':self.admin,'port':self.port,'receiver_policy':self.policy}
  (self.root/'server.json').write_text(json.dumps(config))
  self.proc=subprocess.Popen([sys.executable,'-m','openline_connect.accept_process','--config',str(self.root/'server.json')],
       cwd=str(self.root),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=os.environ.copy())
  for _ in range(100):
   if self.proc.poll() is not None:
    raise RuntimeError('real_accept_server_failed:'+self.proc.stderr.read().decode()[-2000:])
   try:
    with urllib.request.urlopen('http://127.0.0.1:'+str(self.port)+'/v1/healthz',timeout=.3) as resp:
     if json.loads(resp.read())['version']=='accept.v1':break
   except (OSError,ValueError): time.sleep(.04)
  else:raise RuntimeError('real_accept_server_timeout')
  self.client=AcceptClient('http://127.0.0.1:'+str(self.port),pub(self.keys['seller']))
 def _stop(self):
  if self.proc and self.proc.poll() is None:
   self.proc.terminate()
   try:self.proc.wait(timeout=5)
   except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait(timeout=5)
  if self.proc and self.proc.stderr:self.proc.stderr.close()
 def tearDown(self):self._stop()
 def order(self,po,worker='worker_a'):
  return agent_order(buyer='buyer-01',po=po,sku='industrial-filter-17',units=2,
      unit_cents=250000,terms='NET30_SYNTHETIC_v1',buyer_seed=self.keys['buyer'],
      worker_seed=self.keys[worker],contract_seed=self.keys['contract'],
      inventory_seed=self.keys['inventory'],now=self.now)
 def test_real_cross_process_policy_succession_reconcile(self):
  # Uses ONLY publicly installed SDK and actual PR#90 seller API.
  first=self.client.request(self.order('PO-A-001'))
  self.assertEqual(first['decision'],'ACCEPTED')
  self.assertEqual(first['verified_outcome']['status'],'LOCAL_COMMIT')
  # Authorize same lost operation; same PO remains exactly-once.
  again=self.client.request(self.order('PO-A-001'))
  self.assertEqual(again['decision'],'REPLAY_SAME')
  self.assertEqual(self.client.status('buyer-01','PO-A-001',self.admin)['status'],'COMMITTED')
  exported=self.client.export_verified(self.admin)
  self.assertIn(first['receipt'],exported['receipts'])
  self._stop();self.policy_seq+=1;self.policy=self._policy('worker_b');self._launch()
  # Worker A cannot submit a fresh purchase under the new seller-owned policy.
  old=self.client.request(self.order('PO-A-NEW','worker_a'))
  self.assertEqual(old['decision'],'REFUSED')
  successor=self.client.request(self.order('PO-B-002','worker_b'))
  self.assertEqual(successor['decision'],'ACCEPTED')
  # Recovery is an operator-scoped read. Do not mislabel as worker-owned authority.
  self.assertEqual(self.client.status('buyer-01','PO-A-001',self.admin)['status'],'COMMITTED')
  with sqlite3.connect(self.root/'accept.sqlite') as db:
   self.assertEqual(db.execute('SELECT COUNT(*) FROM business_jobs').fetchone()[0],2)
  self.assertNotEqual(os.getpid(),self.proc.pid)
 def test_unsigned_request_refusal(self):
  p=self.order('PO-ATTACK');p['order']='unsigned garbage'
  res=self.client.request(p)
  self.assertEqual(res['decision'],'REFUSED')
  with sqlite3.connect(self.root/'accept.sqlite') as db:
   self.assertEqual(db.execute('SELECT COUNT(*) FROM business_jobs').fetchone()[0],0)
if __name__=='__main__':unittest.main()
