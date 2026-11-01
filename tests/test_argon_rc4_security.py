"""Independent follow-up adversarial tests. Original Argon script is preserved separately."""
import json,sqlite3,tempfile,time,threading,unittest,hashlib
from pathlib import Path
from openline_connect.onboarding import initialize, allow, read_engine, verify_local
from openline_connect.engine import ProtectionError
from openline_connect.signing import verify,sign,pub,digest
from openline_connect.local_example import register_demo

def snapshot(home):
 with sqlite3.connect(home/'connect.sqlite') as db:
  return {'records':db.execute('SELECT record_id,content FROM records ORDER BY record_id').fetchall(),
          'decisions':db.execute('SELECT count(*) FROM decisions').fetchone()[0],
          'audit':db.execute('SELECT count(*) FROM audit_entries').fetchone()[0],
          'operations':db.execute('SELECT nonce,state FROM operations ORDER BY nonce').fetchall()}
class ArgonDefectRegressions(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.home=Path(self.tmp.name)/'receiver'
  self.boot=initialize(self.home)
  self.grant=allow(self.home,action='record.update',target='c1',value='approved',amount_cents=100,ttl_seconds=300)
  self.req=json.loads(Path(self.grant['fictional_agent_request']).read_text());self.eng=read_engine(self.home)
  self.buyer=(self.home/'keys/fictional-buyer.seed').read_text().strip()
 def sign_claim(self, **changes):
  c=verify(self.req['authorization'],{'fictional-buyer':pub(self.buyer)},kind='openline.connect.mandate.v1');c.update(changes)
  return sign(c,self.buyer,'fictional-buyer')
 def test_f01_nonce_changing_replay_one_use_durable(self):
  self.assertEqual(self.eng.execute(**self.req)['state'],'FULFILLED')
  other={**self.req,'nonce':'changed-unsigned'}
  deny=read_engine(self.home).execute(**other)
  self.assertIn(deny['reason'],('replayed_mandate_jti','receiver_allowlist_denied'))
  self.assertEqual(snapshot(self.home)['records'],[('c1','{"value": "approved"}')]); self.assertEqual(snapshot(self.home)['audit'],2)
  self.assertTrue(self.eng.execute(**self.req)['replayed'])
 def test_f01_concurrent_same_authority_different_nonce(self):
  responses=[];errors=[]
  def worker(i):
   try:responses.append(read_engine(self.home).execute(**{**self.req,'nonce':'compete-'+str(i)}))
   except Exception as e:errors.append(str(e))
  threads=[threading.Thread(target=worker,args=(i,)) for i in range(12)]
  for t in threads:t.start()
  for t in threads:t.join()
  self.assertEqual(errors,[]);self.assertEqual(sum(x['state']=='FULFILLED' for x in responses),1)
  self.assertEqual(snapshot(self.home)['records'],[('c1','{"value": "approved"}')])
 def test_f02_subject_framing_and_chain_poison_blocked(self):
  for v in ('victim-ceo',''):
   with self.assertRaisesRegex(ProtectionError,'untrusted_buyer_proof'):
    self.eng.execute(**{**self.req,'nonce':'malice-'+repr(v),'authorization':self.sign_claim(subject=v)})
  self.assertEqual(snapshot(self.home)['audit'],0)
  self.assertEqual(self.eng.execute(**self.req)['state'],'FULFILLED')
  self.assertTrue(verify_local(self.home,seller_public=self.boot['seller_public'])['verified'])
 def test_f03_cross_action_grant_substitution_blocked(self):
  policy=json.loads((self.home/'policy.json').read_text())
  policy['grants']['report.generate']=[policy['grants']['record.update'][0]]
  fac='44'*32;policy['facilitator_public']=pub(fac);(self.home/'policy.json').write_text(json.dumps(policy))
  now=int(time.time());p=self.req['params']
  buyer=self.sign_claim(action='report.generate',jti='cross-action')
  assertion=sign({'kind':'openline.connect.mock_settlement.v1','seller':'fictional-supplier','action':'report.generate',
      'target':'c1','request_sha256':digest(p),'status':'SETTLED','amount':'100','tx':'tx123',
      'nbf':now-1,'exp':now+300},fac,'facilitator')
  z=read_engine(self.home).execute(action='report.generate',params=p,authorization=buyer,nonce='cross',payment={'assertion':assertion})
  self.assertEqual(z['reason'],'receiver_allowlist_denied');self.assertEqual(snapshot(self.home)['records'],[])
 def test_f04_tamper_body_rejected_verifier_and_replay(self):
  r=self.eng.execute(**self.req)
  with sqlite3.connect(self.home/'connect.sqlite') as db:
   obj=json.loads(db.execute('SELECT body FROM operations').fetchone()[0]);obj['body']={'value':'hacked'}
   db.execute('UPDATE operations SET body=?',(json.dumps(obj),))
  with self.assertRaises((ValueError,ProtectionError)):
   verify_local(self.home,seller_public=self.boot['seller_public'],expected_head=r['head_decision_hash'],expected_seq=1)
  with self.assertRaises(ProtectionError):self.eng.execute(**self.req)
 def test_f04_rotation_persisted_history(self):
  before=self.eng.execute(**self.req)
  new_seed='33'*32;self.eng.rotate(new_seed)
  self.assertEqual(read_engine(self.home).public()['current_key'],pub(new_seed))
  self.assertTrue(verify_local(self.home,seller_public=self.boot['seller_public'])['verified'])
  self.assertTrue(verify_local(self.home,seller_public=pub(new_seed))['verified'])
  second=allow(self.home,action='record.update',target='c2',value='new',amount_cents=100,ttl_seconds=300)
  self.assertEqual(read_engine(self.home).execute(**json.loads(Path(second['fictional_agent_request']).read_text()))['state'],'FULFILLED')
  self.assertTrue(verify_local(self.home,seller_public=self.boot['seller_public'])['verified'])
 def test_f05_handler_commit_rollback_forbidden(self):
  def hostile(p,db):
   db.execute('INSERT OR REPLACE INTO records VALUES(?,?)',('c1','{"value":"bad"}'))
   db.commit()
  self.eng._handlers['record.update']=(hostile,5000,True,False)
  z=self.eng.execute(**self.req)
  self.assertEqual(z['state'],'REFUSED_PRE_EFFECT')
  self.assertEqual(snapshot(self.home)['records'],[])
  self.assertEqual(snapshot(self.home)['audit'],1)
  self.assertTrue(verify_local(self.home,seller_public=self.boot['seller_public'])['verified'])
 def test_f06_nonce_squatting_pre_auth_rejected(self):
  with self.assertRaisesRegex(ProtectionError,'untrusted_buyer_proof'):
   self.eng.execute(**{**self.req,'authorization':'invalid'})
  self.assertEqual(snapshot(self.home)['decisions'],0)
  self.assertEqual(self.eng.execute(**self.req)['state'],'FULFILLED')
 def test_f06_protect_decorator_fail_closed(self):
  @self.eng.protect(action='other',max_amount_cents=100)
  def api(order_id):return {'ok':True}
  with self.assertRaises(ProtectionError):api('1',_authorization='invalid',_nonce='decor')
 def test_f07_paid_settled_pending_recovery_no_effect_after_expiry(self):
  fac='66'*32;pol=json.loads((self.home/'policy.json').read_text());pol['facilitator_public']=pub(fac)
  (self.home/'policy.json').write_text(json.dumps(pol))
  eng=read_engine(self.home);now=int(time.time());assertion=sign({
     'kind':'openline.connect.mock_settlement.v1','seller':'fictional-supplier','action':'record.update',
     'target':'c1','request_sha256':digest(self.req['params']),'status':'SETTLED','amount':'100',
     'tx':'tx-paid-restart','nbf':now-1,'exp':now+1},fac,'facilitator')
  paid={**self.req,'payment':{'assertion':assertion}}
  with self.assertRaisesRegex(RuntimeError,'SIMULATED_CRASH_AFTER_SETTLEMENT'):
   eng.execute(**paid,fault='after_settlement')
  self.assertEqual(snapshot(self.home)['audit'],0)
  # No need to sleep; simulated clock on restart is after settlement expiry.
  restarted=read_engine(self.home);restarted.clock=lambda:now+1000
  z=restarted.execute(**paid)
  self.assertEqual(z['state'],'SETTLED_UNFULFILLED_REFUND_DUE')
  self.assertEqual(z['reason'],'settlement_pending_reconciliation')
  self.assertEqual(snapshot(self.home)['records'],[])
  self.assertEqual(snapshot(self.home)['audit'],1)
  self.assertTrue(verify_local(self.home,seller_public=self.boot['seller_public'])['verified'])
  self.assertEqual(len(restarted.list_unresolved()),1)
  confirm=sign({'kind':'openline.connect.mock_compensation.v1','scope':'fictional-supplier:record.update',
                'nonce':paid['nonce'],'original_tx':'tx-paid-restart','refund_tx':'mock-refund','status':'MOCK_REFUNDED'},fac,'facilitator')
  z2=restarted.record_mock_compensation('fictional-supplier:record.update',paid['nonce'],confirm)
  self.assertEqual(z2['state'],'COMPENSATED')
  self.assertTrue(verify_local(self.home,seller_public=self.boot['seller_public'])['verified'])
  self.assertEqual(snapshot(self.home)['audit'],2)
if __name__=='__main__':unittest.main(verbosity=2)
