"""Additional attacks against a new rc4 candidate, with actual subprocess kill and SQLite checks."""
import json,os,signal,subprocess,sqlite3,sys,tempfile,time,unittest
from pathlib import Path
from openline_connect.onboarding import initialize,allow,read_engine,verify_local
from openline_connect.signing import sign,pub,digest,verify
from openline_connect.engine import ProtectionError

class Extra(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.home=Path(self.t.name)/'receiver'
  self.root=initialize(self.home);self.g=allow(self.home,action='record.update',target='customer-1',value='approved',amount_cents=100,ttl_seconds=300)
  self.request=json.loads(Path(self.g['fictional_agent_request']).read_text())
 def test_used_grant_blocks_fresh_signed_jti(self):
  e=read_engine(self.home);self.assertEqual(e.execute(**self.request)['state'],'FULFILLED')
  seed=(self.home/'keys/fictional-buyer.seed').read_text().strip()
  c=verify(self.request['authorization'],{'fictional-buyer':pub(seed)},kind='openline.connect.mandate.v1')
  new=sign({**c,'jti':'different-and-properly-signed'},seed,'fictional-buyer')
  denial=read_engine(self.home).execute(**{**self.request,'nonce':'new-nonce','authorization':new})
  self.assertEqual(denial['state'],'REFUSED_PRE_EFFECT')
  self.assertEqual(denial['reason'],'receiver_allowlist_denied')
 def test_paid_zero_assertion_is_not_effect_and_repeated_tx_blocked(self):
  fac='12'*32;seed=(self.home/'keys/receiver.seed').read_text().strip();buyer=(self.home/'keys/fictional-buyer.seed').read_text().strip()
  p={'target':'report-1','amount_cents':500};now=int(time.time())
  policy=json.loads((self.home/'policy.json').read_text());policy['facilitator_public']=pub(fac)
  g={'id':'paid-grant','action':'report.generate','subject':'fictional-buyer','target':'report-1','grant_mode':'exact_parameters_v1','parameters_sha256':digest(p),'max_amount_cents':500,'expires_at':now+300,'active':True}
  g['receiver_signature']=sign({**g,'kind':'openline.connect.receiver_grant.v1'},seed,'seller')
  policy['grants']['report.generate']=[g];(self.home/'policy.json').write_text(json.dumps(policy))
  c={'kind':'openline.connect.mandate.v1','subject':'fictional-buyer','seller':'fictional-supplier','action':'report.generate','target':'report-1','parameters_sha256':digest(p),'max_amount_cents':500,'nbf':now-1,'exp':now+300,'jti':'payjti'}
  auth=sign(c,buyer,'fictional-buyer')
  def pay(amount,tx):return sign({'kind':'openline.connect.mock_settlement.v1','seller':'fictional-supplier','action':'report.generate','target':'report-1','request_sha256':digest(p),'status':'SETTLED','amount':amount,'tx':tx,'nbf':now-1,'exp':now+300},fac,'facilitator')
  with self.assertRaisesRegex(ProtectionError,'invalid_atomic_amount'):
   read_engine(self.home).execute(action='report.generate',params=p,authorization=auth,nonce='zero',payment={'assertion':pay('0','tx0')})
  self.assertEqual(read_engine(self.home).execute(action='report.generate',params=p,authorization=auth,nonce='paid',payment={'assertion':pay('500','tx1')})['state'],'FULFILLED')
  c2={**c,'jti':'other'};a2=sign(c2,buyer,'fictional-buyer')
  response=read_engine(self.home).execute(action='report.generate',params=p,authorization=a2,nonce='newpaid',payment={'assertion':pay('500','tx1')})
  self.assertEqual(response['state'],'REFUSED_PRE_EFFECT')
  with sqlite3.connect(self.home/'connect.sqlite') as db:
   self.assertEqual(db.execute('SELECT count(*) FROM records').fetchone()[0],1)
 def test_sigkill_uncommitted_handler_rolls_back_everything(self):
  source=Path(__import__('openline_connect').__file__).parent.parent
  code='''import os,signal,sys,json
from openline_connect.onboarding import read_engine
from pathlib import Path
home=Path(sys.argv[1]);req=json.loads(Path(sys.argv[2]).read_text());e=read_engine(home)
def kill(p,db):
 db.execute('INSERT INTO records VALUES (?,?)',('customer-1','{"value":"ghost"}'))
 os.kill(os.getpid(),signal.SIGKILL)
e._handlers['record.update']=(kill,5000,True,False)
e.execute(**req)
'''
  env={**os.environ,'PYTHONPATH':str(source)}
  p=subprocess.run([sys.executable,'-c',code,str(self.home),self.g['fictional_agent_request']],env=env,timeout=10)
  self.assertEqual(p.returncode,-signal.SIGKILL)
  with sqlite3.connect(self.home/'connect.sqlite') as db:
   self.assertEqual(db.execute('SELECT count(*) FROM records').fetchone()[0],0)
   self.assertEqual(db.execute('SELECT count(*) FROM operations').fetchone()[0],0)
   self.assertEqual(db.execute('SELECT count(*) FROM audit_entries').fetchone()[0],0)
  self.assertEqual(read_engine(self.home).execute(**self.request)['state'],'FULFILLED')
if __name__=='__main__':unittest.main(verbosity=2)
