"""Receiver A: strict ROS2 Action Server state-machine SIMULATOR (not rclpy)."""
import json,os,sqlite3,sys,argparse
from pathlib import Path
from wire import read,write,sign,verify,sha,now
from runtime import db,controller,initialize_gate

class ReceiverA:
 def __init__(self,home):
  self.home=Path(home);self.info=read(self.home/'identity.json');self.facility=read(self.home/'facility.json');self.permit=read(self.home/'permit.json');self.receiver=self.info['receiver_id']
 def permit_body(self):return verify(self.permit['jws'],self.info['owner_pub'],'factory','robot.work.permit.v1')
 def facility_body(self):return verify(self.facility['jws'],self.info['owner_pub'],'factory','robot.facility.manifest.v1')
 def refuse(self,reason,request=None,component=None):
  effect=(request or {}).get('effect_id','');body={'kind':'robot.task.refusal.v1','receiver_id':self.receiver,'effect_id':effect,'status':'REFUSED','reason':reason,'changed_dependency':component,'at':now()};tok=sign(body,self.info['seed'],self.receiver)
  with db(self.home/'gate.sqlite') as c:c.execute('INSERT INTO decisions(effect_id,reason,receipt) VALUES(?,?,?)',(effect,reason,tok))
  return {'status':'REFUSED','reason':reason,'receipt':tok,'changed_dependency':component}
 def worker(self,req,op):
  p=self.permit_body();f=self.facility_body()
  if p['receiver_id']!=self.receiver or p['factory_id']!=f['factory_id']:raise ValueError('RECEIVER_IDENTITY')
  if not p['valid_from']<=now()<p['valid_until']:raise ValueError('PERMIT_EXPIRED')
  if p['worker_epoch']!=self.info['worker_epoch']:raise ValueError('STALE_WORKER_EPOCH')
  w=verify(req['worker_jws'],p['delegated_worker_pubkey'],p['worker_id'],'robot.worker.request.v1')
  if w.get('op')!=op or w.get('receiver_id')!=self.receiver or w.get('permit_id')!=p['permit_id'] or w.get('worker_epoch')!=p['worker_epoch'] or w.get('campaign')!=p['campaign'] or not w.get('nonce'):raise ValueError('WORKER_SCOPE')
  if w.get('effect_id')!=req.get('effect_id'):raise ValueError('WORKER_EFFECT_MISMATCH')
  if op=='admit' and any(w.get(k)!=req.get(k) for k in ('units','source_station','destination_station','payload_kg','workcell_id','zone')):raise ValueError('REQUEST_SIGNATURE_MISMATCH')
  return p,f,w
 def authorize_job(self,req,p,f,w):
  j=p['job_spec']
  if req['workcell_id']!=p['workcell_id'] or req['zone']!=p['zone'] or req['source_station']!=j['source_station'] or req['destination_station']!=j['destination_station'] or req.get('action')!='container_transfer':raise ValueError('WORK_SCOPE')
  if type(req['units']) is not int or not 1<=req['units']<=10 or type(req['payload_kg']) is not int or not 0<req['payload_kg']<=j['max_payload_kg']:raise ValueError('PHYSICAL_JOB_BOUNDS')
  if not isinstance(p.get('dependencies'),dict) or not p['dependencies'] or '*' in p['dependencies']:raise ValueError('DEPENDENCY_UNKNOWN_FAIL_CLOSED')
  if p.get('required_config_digest')!=sha(p['dependencies']):raise ValueError('CONFIG_MANIFEST_HASH_MISMATCH')
  for comp,digest in p['dependencies'].items():
   if comp not in f['components'] or f['components'][comp]!=digest:raise ValueError('STALE_COMMISSIONING_CONFIG:'+comp)
  if f['procedures'].get(p['procedure_id'])!=p['required_procedure_version']:raise ValueError('STALE_PROCEDURE_VERSION')
  if req['effect_id'] in ('','UNKNOWN') or len(req['effect_id'])>80:raise ValueError('EFFECT_ID')
 def admit(self,req,crash=False):
  try:
   p,f,w=self.worker(req,'admit');self.authorize_job(req,p,f,w)
   with db(self.home/'gate.sqlite') as c:
    c.execute('BEGIN IMMEDIATE')
    old=c.execute('SELECT receipt,request_sha FROM admitted WHERE effect_id=?',(req['effect_id'],)).fetchone()
    req_sha=sha(w)
    if old:
     if old[1]!=req_sha:raise ValueError('CONFLICTING_EFFECT_ID')
     c.commit();return {'status':'ADMITTED','receipt':old[0],'replayed':True}
    spent=c.execute('SELECT COALESCE(SUM(units),0) FROM admitted WHERE campaign=?',(p['campaign'],)).fetchone()[0]
    if spent+req['units']>p['job_spec']['max_units']:raise ValueError('CAMPAIGN_CAP_EXCEEDED')
    permit_sha=sha(self.permit['jws'].encode());tok=sign({'kind':'robot.controller.admit.v1','receiver_id':self.receiver,'campaign':p['campaign'],'effect_id':req['effect_id'],'units':req['units'],'permit_sha':permit_sha,'request_sha':req_sha,'expires':now()+90},self.info['seed'],self.receiver)
    try:
     proof=controller(self.home,'admit',{'admission_token':tok,'campaign':p['campaign'],'effect_id':req['effect_id'],'units':req['units'],'permit_sha':permit_sha,'request_sha':req_sha})
    except Exception:
     c.rollback();return {'status':'UNKNOWN','reason':'CONTROLLER_RESPONSE_UNAVAILABLE'}
    ct=verify(proof['controller_receipt'],self.info['controller_pub'],self.receiver+'-controller','robot.controller.commit.v1')
    if ct['effect_id']!=req['effect_id'] or ct['units']!=req['units'] or ct['bypass']:raise ValueError('CONTROLLER_RESULT_SCOPE')
    receipt=sign({'kind':'robot.task.admission.v1','receiver_id':self.receiver,'permit_id':p['permit_id'],'revision':p['revision'],'campaign':p['campaign'],'effect_id':req['effect_id'],'units':req['units'],'request_sha':req_sha,'controller_receipt_sha':sha(proof['controller_receipt'].encode()),'status':'ADMITTED','at':now()},self.info['seed'],self.receiver)
    c.execute('INSERT INTO admitted(effect_id,campaign,permit_id,revision,units,request_sha,receipt,controller_receipt,dependencies) VALUES(?,?,?,?,?,?,?,?,?)',(req['effect_id'],p['campaign'],p['permit_id'],p['revision'],req['units'],req_sha,receipt,proof['controller_receipt'],json.dumps(p['dependencies'],sort_keys=True)))
    c.commit()
   if crash:os._exit(79) # entire receiver process exits after both commits, before reply
   return {'status':'ADMITTED','receipt':receipt,'controller_receipt':proof['controller_receipt'],'replayed':False}
  except (ValueError,KeyError,TypeError,sqlite3.Error) as e:return self.refuse(str(e),req,str(e).split(':',1)[1] if 'STALE_COMMISSIONING_CONFIG:' in str(e) else None)
 def recover(self,req):
  try:
   p,f,w=self.worker(req,'recover')
   with db(self.home/'gate.sqlite') as c:old=c.execute('SELECT campaign,receipt,controller_receipt FROM admitted WHERE effect_id=?',(req['effect_id'],)).fetchone()
   if not old:return {'status':'UNKNOWN','reason':'NO_GATE_COMMIT'}
   auth=sign({'kind':'robot.recovery.authorization.v1','campaign':old[0],'effect_id':req['effect_id']},self.info['seed'],self.receiver)
   out=controller(self.home,'recover',{'recovery_auth':auth,'campaign':old[0],'effect_id':req['effect_id']})
   if out['status']!='ADMITTED' or out['controller_receipt']!=old[2]:return {'status':'UNKNOWN','reason':'CONTROLLER_DISAGREEMENT'}
   return {'status':'ADMITTED','receipt':old[1],'controller_receipt':old[2],'replayed':True}
  except (ValueError,KeyError,TypeError,sqlite3.Error) as e:return self.refuse(str(e),req)
 def change(self,change_jws,new_manifest_jws):
  change=verify(change_jws,self.info['owner_pub'],'factory','robot.facility.change.v1');prev=self.facility_body();new=verify(new_manifest_jws,self.info['owner_pub'],'factory','robot.facility.manifest.v1')
  comp=change['component'];seq=change['sequence'];old=(prev['procedures'].get(comp.partition(':')[2],'UNKNOWN') if comp.startswith('procedure:') else prev['components'].get(comp,'UNKNOWN'));value=(new['procedures'].get(comp.partition(':')[2],'UNKNOWN') if comp.startswith('procedure:') else new['components'].get(comp,'UNKNOWN'))
  if seq!=prev['sequence']+1 or new['sequence']!=seq or change['prior_digest']!=old or change['new_digest']!=value or new['factory_id']!=prev['factory_id'] or (change.get('prior_manifest_sha')!=sha(self.facility['jws'].encode())):raise ValueError('CHANGE_CHAIN_MISMATCH')
  # Also enforce that this event changed *only the declared component*.
  if any(v!=new['components'].get(k) for k,v in prev['components'].items() if k!=comp) or any(k!=comp and k not in prev['components'] for k in new['components']):raise ValueError('UNDISCLOSED_COMPONENT_CHANGE')
  if comp.startswith('procedure:'):
   procedure=comp.partition(':')[2]
   if prev['components']!=new['components'] or any(v!=new['procedures'].get(k) for k,v in prev['procedures'].items() if k!=procedure) or prev['procedures'].get(procedure,'UNKNOWN')!=change['prior_digest'] or new['procedures'].get(procedure,'UNKNOWN')!=change['new_digest']:raise ValueError('UNDISCLOSED_PROCEDURE_CHANGE')
  elif prev['procedures']!=new['procedures']:raise ValueError('UNDISCLOSED_PROCEDURE_CHANGE')
  with db(self.home/'gate.sqlite') as c:
   c.execute('BEGIN IMMEDIATE');c.execute('INSERT INTO changes VALUES(?,?,?,?,?,?)',(seq,change['change_id'],comp,old,value,change_jws))
   affected=0
   for effect,deps in c.execute('SELECT effect_id,dependencies FROM admitted').fetchall():
    d=json.loads(deps)
    if not d or comp in d or (comp.startswith('procedure:') and self.permit_body()['procedure_id']==comp.partition(':')[2]) or any(k not in new['components'] for k in d):
     c.execute('UPDATE admitted SET impact=?,impact_event=? WHERE effect_id=?',('RECONSIDERATION_REQUIRED',change['change_id'],effect));affected+=1
   c.commit()
  write(self.home/'facility.json',{'jws':new_manifest_jws});return {'status':'APPLIED','affected':affected,'change_id':change['change_id']}
 def update_permit(self,jws):
  old=self.permit_body();new=verify(jws,self.info['owner_pub'],'factory','robot.work.permit.v1')
  if new['permit_id']!=old['permit_id'] or new['campaign']!=old['campaign'] or new['revision']<=old['revision'] or new['job_spec']!=old['job_spec']:raise ValueError('ILLEGAL_PERMIT_AMENDMENT')
  if new['worker_epoch']<old['worker_epoch']:raise ValueError('WORKER_EPOCH_ROLLBACK')
  self.info['worker_epoch']=new['worker_epoch'];write(self.home/'identity.json',self.info);write(self.home/'permit.json',{'jws':jws});self.permit={'jws':jws};return {'status':'UPDATED','revision':new['revision']}
 def inspect(self):
  with db(self.home/'gate.sqlite') as c:
   records=[{'effect_id':r[0],'campaign':r[1],'units':r[2],'impact':r[3],'impact_event':r[4]} for r in c.execute('SELECT effect_id,campaign,units,impact,impact_event FROM admitted ORDER BY effect_id')]
  return {'receiver_id':self.receiver,'admitted':records,'controller':controller(self.home,'inspect')}

def run(home,op,arg):
 a=ReceiverA(home)
 if op=='admit':return a.admit(arg['request'],arg.get('crash',False))
 if op=='recover':return a.recover(arg['request'])
 if op=='change':return a.change(arg['change_jws'],arg['facility_jws'])
 if op=='permit':return a.update_permit(arg['permit_jws'])
 if op=='inspect':return a.inspect()
 raise ValueError('UNSUPPORTED_ROS_ACTION')
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('home');ap.add_argument('op');ap.add_argument('payload',nargs='?',default='{}');z=ap.parse_args()
 try:print(json.dumps(run(z.home,z.op,json.loads(z.payload))))
 except Exception as e:print(json.dumps({'status':'ERROR','error':str(e)}));sys.exit(2)
