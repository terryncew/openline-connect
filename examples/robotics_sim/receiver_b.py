"""Clean-room independent VDA-5050-style fleet/REST JSON adapter. No Receiver A imports."""
import argparse,json,os,sqlite3,sys
from pathlib import Path
from wire import read,write,sign,verify,sha,now
from runtime import db,controller

class IndependentFleetB:
 def __init__(self,home):
  self.path=Path(home);self.meta=read(self.path/'identity.json');self.id=self.meta['receiver_id'];self.owner=self.meta['owner_pub']
 def doc(self,name,kind):return verify(read(self.path/name)['jws'],self.owner,'factory',kind)
 def denial(self,why,req,component=None):
  e=req.get('effect_id','') if isinstance(req,dict) else ''
  signed=sign({'kind':'robot.task.refusal.v1','receiver_id':self.id,'effect_id':e,'status':'REFUSED','reason':why,'changed_dependency':component,'at':now()},self.meta['seed'],self.id)
  with db(self.path/'gate.sqlite') as c:c.execute('INSERT INTO decisions(effect_id,reason,receipt) VALUES(?,?,?)',(e,why,signed))
  return {'status':'REFUSED','reason':why,'receipt':signed,'changed_dependency':component}
 def validate_identity(self,raw,operation):
  permit=self.doc('permit.json','robot.work.permit.v1');facility=self.doc('facility.json','robot.facility.manifest.v1')
  if permit.get('receiver_id')!=self.id or permit.get('factory_id')!=facility.get('factory_id'):raise ValueError('WRONG_FLEET_OPERATOR')
  if permit['worker_epoch']!=self.meta['worker_epoch']:raise ValueError('EPOCH_NOT_ACTIVE')
  if now()<permit['valid_from'] or now()>=permit['valid_until']:raise ValueError('PERMIT_EXPIRED')
  worker=verify(raw['worker_jws'],permit['delegated_worker_pubkey'],permit['worker_id'],'robot.worker.request.v1')
  required={'op':operation,'receiver_id':self.id,'permit_id':permit['permit_id'],'worker_epoch':permit['worker_epoch'],'campaign':permit['campaign'],'effect_id':raw['effect_id']}
  if any(worker.get(k)!=v for k,v in required.items()) or not isinstance(worker.get('nonce'),str) or not worker['nonce']:raise ValueError('DELEGATION_NOT_AUTHORIZED')
  if operation=='admit':
   for key in ('source_station','destination_station','workcell_id','zone','units','payload_kg'):
    if worker.get(key)!=raw.get(key):raise ValueError('TAMPERED_FLEET_ORDER')
  return permit,facility,worker
 def physical_policy(self,p,f,raw):
  job=p['job_spec']
  if p['workcell_id']!=raw['workcell_id'] or p['zone']!=raw['zone']:raise ValueError('UNAUTHORIZED_WORKCELL')
  if (job['action'],job['source_station'],job['destination_station'])!=(raw['action'],raw['source_station'],raw['destination_station']):raise ValueError('TASK_PARAMETERS')
  if type(raw['units']) is not int or raw['units']<1 or raw['units']>10:raise ValueError('BATCH_POLICY')
  if type(raw['payload_kg']) is not int or raw['payload_kg']<=0 or raw['payload_kg']>job['max_payload_kg']:raise ValueError('PAYLOAD_POLICY')
  deps=p.get('dependencies')
  if not isinstance(deps,dict) or not deps or '*' in deps:raise ValueError('DEPENDENCY_UNKNOWN_FAIL_CLOSED')
  if p.get('required_config_digest')!=sha(deps):raise ValueError('CONFIG_MANIFEST_HASH_MISMATCH')
  for component,expected in deps.items():
   if f['components'].get(component)!=expected:raise ValueError('STALE_COMMISSIONING_CONFIG:'+component)
  if f['procedures'].get(p['procedure_id'])!=p['required_procedure_version']:raise ValueError('STALE_PROCEDURE_VERSION')
 def submit_order(self,raw,crash=False):
  try:
   permit,facility,worker=self.validate_identity(raw,'admit');self.physical_policy(permit,facility,raw)
   digest=sha(worker)
   with db(self.path/'gate.sqlite') as c:
    c.execute('BEGIN IMMEDIATE')
    old=c.execute('SELECT receipt,request_sha,controller_receipt FROM admitted WHERE effect_id=?',(raw['effect_id'],)).fetchone()
    if old:
     if old[1]!=digest:raise ValueError('DUPLICATE_EFFECT_CONFLICT')
     c.commit();return {'status':'ADMITTED','receipt':old[0],'controller_receipt':old[2],'replayed':True}
    total=c.execute('SELECT COALESCE(SUM(units),0) FROM admitted WHERE campaign=?',(permit['campaign'],)).fetchone()[0]
    if total+raw['units']>permit['job_spec']['max_units']:raise ValueError('CAPACITY_EXHAUSTED')
    permit_jws=read(self.path/'permit.json')['jws'];permit_hash=sha(permit_jws.encode())
    admission=sign({'kind':'robot.controller.admit.v1','receiver_id':self.id,'campaign':permit['campaign'],'effect_id':raw['effect_id'],'units':raw['units'],'permit_sha':permit_hash,'request_sha':digest,'expires':now()+90},self.meta['seed'],self.id)
    try:
     ctrl=controller(self.path,'admit',{'admission_token':admission,'campaign':permit['campaign'],'effect_id':raw['effect_id'],'units':raw['units'],'permit_sha':permit_hash,'request_sha':digest})
    except Exception:
     c.rollback();return {'status':'UNKNOWN','reason':'CONTROLLER_RESPONSE_UNAVAILABLE'}
    ck=verify(ctrl['controller_receipt'],self.meta['controller_pub'],self.id+'-controller','robot.controller.commit.v1')
    if ck['bypass'] or ck['request_sha']!=digest or ck['permit_sha']!=permit_hash:raise ValueError('CONTROLLER_PROOF_MISMATCH')
    ticket=sign({'kind':'robot.task.admission.v1','receiver_id':self.id,'permit_id':permit['permit_id'],'revision':permit['revision'],'campaign':permit['campaign'],'effect_id':raw['effect_id'],'units':raw['units'],'request_sha':digest,'controller_receipt_sha':sha(ctrl['controller_receipt'].encode()),'status':'ADMITTED','at':now()},self.meta['seed'],self.id)
    c.execute('INSERT INTO admitted(effect_id,campaign,permit_id,revision,units,request_sha,receipt,controller_receipt,dependencies) VALUES(?,?,?,?,?,?,?,?,?)',(raw['effect_id'],permit['campaign'],permit['permit_id'],permit['revision'],raw['units'],digest,ticket,ctrl['controller_receipt'],json.dumps(permit['dependencies'],sort_keys=True)))
    c.commit()
   if crash:os._exit(79)
   return {'status':'ADMITTED','receipt':ticket,'controller_receipt':ctrl['controller_receipt'],'replayed':False}
  except (ValueError,KeyError,TypeError,sqlite3.Error) as exc:
   error=str(exc);return self.denial(error,raw,error.partition(':')[2] if error.startswith('STALE_COMMISSIONING_CONFIG:') else None)
 def reconcile(self,raw):
  try:
   permit,_,_=self.validate_identity(raw,'recover')
   with db(self.path/'gate.sqlite') as c:cached=c.execute('SELECT campaign,receipt,controller_receipt FROM admitted WHERE effect_id=?',(raw['effect_id'],)).fetchone()
   if cached is None:return {'status':'UNKNOWN','reason':'NO_RECEIVER_RECEIPT'}
   token=sign({'kind':'robot.recovery.authorization.v1','effect_id':raw['effect_id'],'campaign':cached[0]},self.meta['seed'],self.id)
   check=controller(self.path,'recover',{'effect_id':raw['effect_id'],'campaign':cached[0],'recovery_auth':token})
   if check['status']=='ADMITTED' and check['controller_receipt']==cached[2]:return {'status':'ADMITTED','receipt':cached[1],'controller_receipt':cached[2],'replayed':True}
   return {'status':'UNKNOWN','reason':'CONTROLLER_NOT_MATCHED'}
  except (ValueError,KeyError,TypeError,sqlite3.Error) as e:return self.denial(str(e),raw)
 def apply_manifest(self,ev,fresh):
  change=verify(ev,self.owner,'factory','robot.facility.change.v1');previous=self.doc('facility.json','robot.facility.manifest.v1');updated=verify(fresh,self.owner,'factory','robot.facility.manifest.v1')
  k=change['component']
  if updated['factory_id']!=previous['factory_id'] or updated['sequence']!=previous['sequence']+1 or updated['sequence']!=change['sequence']:raise ValueError('BAD_CHANGE_SEQUENCE')
  if change['prior_manifest_sha']!=sha(read(self.path/'facility.json')['jws'].encode()) or (previous['procedures'].get(k.partition(':')[2],'UNKNOWN') if k.startswith('procedure:') else previous['components'].get(k,'UNKNOWN'))!=change['prior_digest'] or (updated['procedures'].get(k.partition(':')[2],'UNKNOWN') if k.startswith('procedure:') else updated['components'].get(k,'UNKNOWN'))!=change['new_digest']:raise ValueError('BAD_CHANGE_PROOF')
  if {x:y for x,y in previous['components'].items() if x!=k}!={x:y for x,y in updated['components'].items() if x!=k}:raise ValueError('UNDECLARED_CHANGE')
  if k.startswith('procedure:'):
   proc=k.partition(':')[2]
   if any(v!=updated['procedures'].get(x) for x,v in previous['procedures'].items() if x!=proc):raise ValueError('UNDECLARED_PROCEDURE')
  elif previous['procedures']!=updated['procedures']:raise ValueError('UNDECLARED_PROCEDURE')
  with db(self.path/'gate.sqlite') as c:
   c.execute('BEGIN IMMEDIATE');c.execute('INSERT INTO changes VALUES(?,?,?,?,?,?)',(change['sequence'],change['change_id'],k,change['prior_digest'],change['new_digest'],ev));count=0
   for effect,rawdeps in c.execute('SELECT effect_id,dependencies FROM admitted').fetchall():
    deps=json.loads(rawdeps)
    if not deps or k in deps or (k.startswith('procedure:') and self.doc('permit.json','robot.work.permit.v1')['procedure_id']==k.partition(':')[2]) or any(x not in updated['components'] for x in deps):
     c.execute('UPDATE admitted SET impact=?,impact_event=? WHERE effect_id=?',('RECONSIDERATION_REQUIRED',change['change_id'],effect));count+=1
   c.commit()
  write(self.path/'facility.json',{'jws':fresh});return {'status':'APPLIED','affected':count,'change_id':change['change_id']}
 def new_permit(self,token):
  old=self.doc('permit.json','robot.work.permit.v1');new=verify(token,self.owner,'factory','robot.work.permit.v1')
  for k in ('permit_id','campaign','receiver_id','factory_id','job_spec'):
   if new[k]!=old[k]:raise ValueError('ILLEGAL_AMENDMENT_'+k)
  if new['revision']<=old['revision'] or new['worker_epoch']<old['worker_epoch']:raise ValueError('REPLAYED_AMENDMENT')
  self.meta['worker_epoch']=new['worker_epoch'];write(self.path/'identity.json',self.meta);write(self.path/'permit.json',{'jws':token});return {'status':'UPDATED','revision':new['revision']}
 def audit(self):
  with db(self.path/'gate.sqlite') as c:
   out=[{'effect_id':r[0],'campaign':r[1],'units':r[2],'impact':r[3],'impact_event':r[4]} for r in c.execute('SELECT effect_id,campaign,units,impact,impact_event FROM admitted ORDER BY effect_id')]
  return {'receiver_id':self.id,'admitted':out,'controller':controller(self.path,'inspect')}

def run(home,op,arg):
 b=IndependentFleetB(home)
 if op=='order':return b.submit_order(arg['request'],arg.get('crash',False))
 if op=='reconcile':return b.reconcile(arg['request'])
 if op=='manifest':return b.apply_manifest(arg['change_jws'],arg['facility_jws'])
 if op=='permit':return b.new_permit(arg['permit_jws'])
 if op=='inspect':return b.audit()
 raise ValueError('UNSUPPORTED_VDA_OPERATION')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('home');p.add_argument('op');p.add_argument('payload',nargs='?',default='{}');a=p.parse_args()
 try:print(json.dumps(run(a.home,a.op,json.loads(a.payload))))
 except Exception as e:print(json.dumps({'status':'ERROR','error':str(e)}));sys.exit(2)
