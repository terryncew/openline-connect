"""Author-side adversarial regression tests; NOT the missing outsider's scripts."""
import json,sqlite3,tempfile,unittest,secrets,concurrent.futures
from pathlib import Path
from openline_connect.onboarding import initialize,read_engine,allow_bounded,issue_fictional_bounded_invocation,allow
from openline_connect.engine import ProtectionError
from openline_connect.key_history import inspect as inspect_key_history

class AdoptionRepair(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.home=Path(self.tmp.name);initialize(self.home)
  path=self.home/'policy.json';pol=json.loads(path.read_text());pol['effect_sql']={'tables':['invoices'],'functions':[]};path.write_text(json.dumps(pol))
  with sqlite3.connect(self.home/'connect.sqlite') as db:
   db.execute('CREATE TABLE invoices (id TEXT PRIMARY KEY, amount INTEGER, vendor TEXT)')
  self.g=allow_bounded(self.home,action='invoice.approve',grant_name='grant-one',
         permitted_keys=['target','dept_id','vendor_id','amount_cents'],fixed_params={'dept_id':'eng'},
         target_restrictions={'vendor_id':['acme','beta']},max_amount_per_op=300,
         max_cumulative_amount=600,max_uses=3,ttl_seconds=300)
  self.eng=read_engine(self.home)
  def handler(p,db):
   db.execute('INSERT INTO invoices VALUES(?,?,?)',(p['target'],p['amount_cents'],p['vendor_id']))
   return {'id':p['target']}
  self.eng.register('invoice.approve',handler,max_amount_cents=500)
 def args(self,idx=0,amount=200,delegation='del-a',worker='worker-A',seed='23'*32,**kwargs):
  params={'target':f'INV-{idx}','dept_id':'eng','vendor_id':'acme','amount_cents':amount}
  params.update(kwargs.pop('params',{}))
  p=issue_fictional_bounded_invocation(self.home,action='invoice.approve',params=params,
         grant_id=self.g['grant_id'],delegation_id=delegation,worker_subject=worker,
         worker_seed=seed,**kwargs)
  return {k:p[k] for k in ('action','params','authorization','nonce') if k in p}|({'task_id':p['task_id']} if 'task_id' in p else {})
 def counts(self):
  with self.eng.db() as db:
   return (db.execute('SELECT COUNT(*) FROM invoices').fetchone()[0],
           db.execute('SELECT kind,used_count,cumulative_amount FROM capacity_usage ORDER BY kind').fetchall())
 def test_three_actions_and_limits(self):
  for i in range(3):self.assertEqual(self.eng.execute(**self.args(i))['decision'],'ALLOW')
  self.assertEqual(self.counts()[0],3)
  reject=self.eng.execute(**self.args(4,amount=1))
  self.assertEqual(reject['decision'],'DENY');self.assertEqual(reject['reason'],'bounded_capacity_exhausted')
  self.assertEqual(self.counts()[1],[('delegation',3,600),('receiver',3,600)])
 def test_target_keys_amount_and_fixed_rejections(self):
  for idx,params in enumerate([{'vendor_id':'stranger'}, {'dept_id':'marketing'},
                                {'new_key':'injected'}, {'amount_cents':301},
                                {'amount_cents':1.5},{'amount_cents':True}, {'amount_cents':-1}]):
   req=self.args(idx,params=params)
   self.assertNotEqual(self.eng.execute(**req)['decision'],'ALLOW',params)
  self.assertEqual(self.counts()[0],0)
  self.assertEqual(self.counts()[1],[])
 def test_delegation_widening_denied(self):
  for idx,limits in enumerate([{'permitted_keys':['target','dept_id','vendor_id','amount_cents','other']},
                               {'allowed_actions':['invoice.approve','admin.destroy']},
                               {'allowed_worker_subjects':['worker-A','worker-B','rogue']},
                               {'max_uses':4},{'max_cumulative_amount':601},{'max_amount_per_op':301},
                               {'target_restrictions':{'vendor_id':['acme','evil']}},
                               {'fixed_params':{'dept_id':'marketing'}}]):
   req=self.args(idx,delegation_limits=limits)
   result=self.eng.execute(**req)
   self.assertEqual(result['decision'],'DENY',(limits,result))
   self.assertEqual(result['reason'],'delegation_scope_widening',(limits,result))
  self.assertEqual(self.counts()[1],[])
 def test_nonapproved_worker_denied_even_with_buyer_delegation(self):
  attempt=self.args(31,worker='rogue',seed='99'*32)
  with self.assertRaises(ProtectionError) as err:
   self.eng.execute(**attempt)
  self.assertEqual(err.exception.code,'delegation_scope_mismatch')
  self.assertEqual(self.counts(),(0,[]))
 def test_revocation_expiry_and_cross_worker(self):
  self.assertEqual(self.eng.execute(**self.args(1))['decision'],'ALLOW')
  self.eng.revoke('del-a')
  self.assertNotEqual(self.eng.execute(**self.args(2))['decision'],'ALLOW')
  self.assertEqual(self.eng.execute(**self.args(3,delegation='del-b',worker='worker-B',seed='34'*32))['decision'],'ALLOW')
  self.eng.revoke_grant('grant-one')
  self.assertNotEqual(self.eng.execute(**self.args(4,delegation='del-b',worker='worker-B',seed='34'*32))['decision'],'ALLOW')
  self.assertEqual(self.counts()[0],2)
 def test_failure_rolls_back_capacity_and_effect(self):
  r=self.eng.execute(**self.args(1),fault='effect_raises')
  self.assertEqual(r['decision'],'INDETERMINATE')
  self.assertEqual(self.counts(),(0,[]))
  for i in range(3):self.assertEqual(self.eng.execute(**self.args(10+i))['decision'],'ALLOW')
  self.assertEqual(self.counts()[0],3)
 def test_replay_and_worker_successor_task(self):
  a=self.args(8,task_id='task-same')
  first=self.eng.execute_task(**a)
  self.assertEqual(first['decision'],'ALLOW')
  second=self.eng.execute_task(**a)
  self.assertEqual(second['receipt'],first['receipt']);self.assertTrue(second['replayed'])
  self.eng.revoke('del-a')
  b=self.args(8,delegation='del-b',worker='worker-B',seed='34'*32,task_id='task-same')
  recovered=self.eng.inspect_task(task_id='task-same',action=b['action'],params=b['params'],authorization=b['authorization'])
  self.assertEqual(recovered['receipt'],first['receipt'])
  again=self.eng.execute_task(**b)
  self.assertEqual(again['receipt'],first['receipt'])
  self.assertEqual(self.counts()[0],1)
  self.assertEqual(self.counts()[1],[('delegation',1,200),('receiver',1,200)])
 def test_parallel_budget_exhaustion(self):
  requests=[self.args(100+i,amount=200) for i in range(9)]
  with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
   out=list(pool.map(lambda p:self.eng.execute(**p),requests))
  self.assertEqual(sum(r['decision']=='ALLOW' for r in out),3)
  self.assertEqual(self.counts()[0],3)
  self.assertEqual(self.counts()[1],[('delegation',3,600),('receiver',3,600)])
 def test_capacity_tamper_refused(self):
  self.assertEqual(self.eng.execute(**self.args(0))['decision'],'ALLOW')
  with self.eng.db() as db:db.execute("UPDATE capacity_usage SET used_count=0 WHERE kind='receiver'")
  result=self.eng.execute(**self.args(1))
  self.assertEqual(result['decision'],'DENY')
  self.assertEqual(result['reason'],'capacity_state_tampered')
  self.assertEqual(self.counts()[0],1)
 def test_capacity_row_deletion_cannot_reset_budget(self):
  self.assertEqual(self.eng.execute(**self.args(0))['decision'],'ALLOW')
  with self.eng.db() as db:
   db.execute("DELETE FROM capacity_usage WHERE kind='receiver'")
  denied=self.eng.execute(**self.args(1))
  self.assertEqual(denied['decision'],'DENY')
  self.assertEqual(denied['reason'],'capacity_state_tampered')
  self.assertEqual(self.counts()[0],1)
 def test_reused_delegation_id_cannot_expand_scope(self):
  self.assertEqual(self.eng.execute(**self.args(0,delegation_limits={'max_uses':1}))['decision'],'ALLOW')
  candidate=self.args(1,delegation_limits={'max_uses':3})
  denied=self.eng.execute(**candidate)
  self.assertEqual(denied['decision'],'DENY')
  self.assertEqual(denied['reason'],'capacity_state_tampered')
  self.assertEqual(self.counts()[0],1)
 def test_nonce_and_mandate_replay(self):
  req=self.args(1)
  self.assertEqual(self.eng.execute(**req)['decision'],'ALLOW')
  replay=self.eng.execute(**req)
  self.assertTrue(replay['replayed']);self.assertEqual(self.counts()[0],1)
  altered={**req,'nonce':'different-nonce'}
  self.assertNotEqual(self.eng.execute(**altered)['decision'],'ALLOW')
  self.assertEqual(self.counts()[0],1)
 def test_key_history_rotation_supported(self):
  public=self.eng.public();old=public['key_epochs'][0]['public']
  self.assertFalse(hasattr(self.eng,'rotate_seller_key'))
  token=self.eng.rotate('62'*32)
  history=self.eng.public()['key_epochs']
  self.assertTrue(inspect_key_history(history,old)['verified']);self.assertEqual(history[-1]['rotation'],token)
 def test_real_stable_hash_and_nonfinite_rejection(self):
  with self.eng.db() as db:
   db.execute('ALTER TABLE invoices ADD COLUMN ratio REAL')
   db.execute('INSERT INTO invoices(id,amount,vendor,ratio) VALUES(?,?,?,?)',('a',1,'acme',1.25))
   first=self.eng._application_tables_hash(db)
   self.assertEqual(first,self.eng._application_tables_hash(db))
   db.execute('UPDATE invoices SET ratio=?',(float('-0.0'),))
   neg_zero=self.eng._application_tables_hash(db)
   db.execute('UPDATE invoices SET ratio=?',(0.0,))
   self.assertEqual(neg_zero,self.eng._application_tables_hash(db))
   db.execute('UPDATE invoices SET ratio=?',(float('inf'),))
   with self.assertRaises(ProtectionError) as e:self.eng._application_tables_hash(db)
   self.assertEqual(e.exception.code,'nonfinite_application_sql_real')
 def test_protect_requires_explicit_effect_target(self):
  @self.eng.protect(action='invoice.other')
  def missing_target(value,db):
   db.execute('INSERT INTO invoices VALUES(?,?,?)',(value,10,'acme'))
  with self.assertRaises(ProtectionError) as err:
   missing_target('something',_authorization=None,_nonce='no-target')
  self.assertEqual(err.exception.code,'explicit_effect_target_required')
  self.assertEqual(self.counts(),(0,[]))
 def test_protect_signatures(self):
  with tempfile.TemporaryDirectory() as h:
   initialize(h)
   allow(h,action='write.positional',params={'target':'item1','amount_cents':1})
   allow(h,action='write.mapping',params={'target':'item2','amount_cents':1})
   engine=read_engine(h)
   @engine.protect(action='write.positional')
   def positional(target,/,amount_cents,db):
    db.execute('INSERT INTO records VALUES(?,?)',(target,str(amount_cents)))
    return {'id':target}
   @engine.protect(action='write.mapping')
   def mapping(params,db):
    db.execute('INSERT INTO records VALUES(?,?)',(params['target'],'ok'))
    return {'id':params['target']}
   files=sorted((Path(h)/'grants').glob('*.json'))
   byaction={j['action']:j for j in (json.loads(x.read_text()) for x in files)}
   p=byaction['write.positional']
   self.assertEqual(positional('item1',amount_cents=1,_authorization=p['authorization'],_nonce=p['nonce']),{'id':'item1'})
   p=byaction['write.mapping']
   self.assertEqual(mapping({'target':'item2','amount_cents':1},_authorization=p['authorization'],_nonce=p['nonce']),{'id':'item2'})
   with self.assertRaises(ProtectionError):
    positional('item4',amount_cents=1,db=object(),_authorization=p['authorization'],_nonce='invalid')

if __name__=='__main__':unittest.main()

# Platform-independent multiprocessing target; no shares of a live SQLite connection.
def _process_attempt(home, params, index, outgoing):
 try:
  from openline_connect.onboarding import read_engine,issue_fictional_bounded_invocation
  engine=read_engine(home)
  def effect(p,db):
   db.execute('INSERT INTO invoices VALUES(?,?,?)',(p['target'],p['amount_cents'],p['vendor_id']))
   return {'id':p['target']}
  engine.register('invoice.approve',effect,max_amount_cents=500)
  x=issue_fictional_bounded_invocation(home,action='invoice.approve',params=params,
      grant_id='grant-one',delegation_id='del-a',worker_subject='worker-A',worker_seed='23'*32)
  r=engine.execute(**{k:x[k] for k in ('action','params','authorization','nonce')})
  outgoing.put((index,r['decision'],r.get('reason')))
 except Exception as e:outgoing.put((index,'EXCEPTION',repr(e)))

class AdditionalSecurity(unittest.TestCase):
 setUp=AdoptionRepair.setUp
 args=AdoptionRepair.args
 counts=AdoptionRepair.counts
 def test_cross_process_capacity(self):
  import multiprocessing
  ctx=multiprocessing.get_context('spawn');queue=ctx.Queue()
  ps=[]
  for i in range(5):
   data={'target':f'process-{i}','dept_id':'eng','vendor_id':'acme','amount_cents':200}
   p=ctx.Process(target=_process_attempt,args=(str(self.home),data,i,queue));ps.append(p);p.start()
  results=[queue.get(timeout=30) for _ in ps]
  for p in ps:p.join(timeout=30)
  self.assertTrue(all(p.exitcode==0 for p in ps))
  self.assertEqual(sum(x[1]=='ALLOW' for x in results),3,results)
  self.assertEqual(self.counts()[0],3)
  self.assertEqual(self.counts()[1],[('delegation',3,600),('receiver',3,600)])
 def test_sql_authorizer_failure_does_not_consume_capacity(self):
  engine=read_engine(self.home)
  def bad(p,db):db.execute('INSERT INTO revocations VALUES(?,?)',('evil',0))
  engine.register('invoice.approve',bad,max_amount_cents=500)
  r=engine.execute(**self.args(1))
  self.assertEqual(r['decision'],'INDETERMINATE')
  self.assertEqual(self.counts(),(0,[]))
 def test_bounded_grant_key_rotation_without_counter_reset(self):
  self.assertEqual(self.eng.execute(**self.args(0))['decision'],'ALLOW')
  old=self.eng.public()['key_epochs'][0]['public']
  self.eng.rotate('57'*32)
  self.assertTrue(inspect_key_history(self.eng.public()['key_epochs'],old)['verified'])
  self.assertEqual(self.eng.execute(**self.args(1))['decision'],'ALLOW')
  self.assertEqual(self.counts()[1],[('delegation',2,400),('receiver',2,400)])
 def test_delegation_expiration_and_grant_expiration(self):
  req=self.args(0)
  t=self.eng.clock()
  self.eng.clock=lambda:t+301
  r=self.eng.execute(**req)
  self.assertEqual(r['decision'],'DENY')
  self.assertEqual(self.counts(),(0,[]))
