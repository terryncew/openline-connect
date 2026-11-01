"""14 real-process receiver/controller attacks with disclosed SQLite and journal inspection.
Every case has its own fresh disposable fixture. Tests are independent of return-value claims.
"""
import argparse,ast,json,os,sqlite3,subprocess,sys,tempfile,time
from pathlib import Path
from wire import read,write,verify,sign,sha,now
from scenario import init,dispatch,receiver_path,request
from runtime import controller,db
from verify_standalone import audit
ROOT=Path(__file__).parent

def fresh():
 home=Path(tempfile.mkdtemp(prefix='olrobot-test-'));init(home);return home

def member(which):return 'A' if which=='A' else 'B'
def check(x,msg=''): 
 if not x:raise AssertionError(msg or 'FAILED_INVARIANT')
def rows(root,which):return audit(receiver_path(root,which))
def admitted(root,which):return dispatch(root,which,'inspect')['admitted']
def effect_count(root,which):return len(dispatch(root,which,'inspect')['controller']['rows'])
def rotate(root,which):
 from wire import verify
 p=receiver_path(root,which);owner=read(root/'owner.json');old=verify(read(p/'permit.json')['jws'],owner['pub'],'factory','robot.work.permit.v1')
 successor=member(which);successor='B' if successor=='A' else 'A';w=read(root/('worker-'+successor+'.json'))
 old.update({'revision':old['revision']+1,'worker_epoch':old['worker_epoch']+1,'worker_id':w['name'],'delegated_worker_pubkey':w['pub']})
 return successor,dispatch(root,which,'permit',{'permit_jws':sign(old,owner['seed'],'factory')})
def alter(root,targets,component,newvalue=None):
 owner=read(root/'owner.json');res={}
 for which in targets:
  home=receiver_path(root,which);before=read(home/'facility.json')['jws'];old=verify(before,owner['pub'],'factory','robot.facility.manifest.v1');new=json.loads(json.dumps(old));new['sequence']+=1
  val=newvalue or sha(component+'-changed')
  prior=old['procedures'].get(component.split(':',1)[1],'UNKNOWN') if component.startswith('procedure:') else old['components'].get(component,'UNKNOWN')
  if component.startswith('procedure:'):new['procedures'][component.split(':',1)[1]]=val
  else:new['components'][component]=val
  event={'kind':'robot.facility.change.v1','change_id':'event-'+str(new['sequence'])+'-'+component,'sequence':new['sequence'],'component':component,'prior_digest':prior,'new_digest':val,'prior_manifest_sha':sha(before.encode()),'at':now()}
  res[which]=dispatch(root,which,'change',{'change_jws':sign(event,owner['seed'],'factory'),'facility_jws':sign(new,owner['seed'],'factory')})
 return res

def run_case(index,which):
 root=fresh();who=member(which);home=receiver_path(root,which)
 def req(effect,units=2,worker=None,**kwargs):return request(root,which,worker or who,effect,units,**kwargs)
 def submit(r,crash=False):return dispatch(root,which,'admit',{'request':r,'crash':crash})
 if index==1:
  res=submit(req('unauthorized-1',workcell_id='Other_Cell'));check(res['status']=='REFUSED');res=submit(req('unauthorized-2',payload=95));check(res['status']=='REFUSED' and effect_count(root,which)==0)
 elif index==2:
  check(submit(req('stale-previous'))['status']=='ADMITTED');alter(root,[which],'Station_A_calibration' if which=='A' else 'Station_C_calibration');res=submit(req('stale-new'));check(res['reason'].startswith('STALE_COMMISSIONING_CONFIG') and admitted(root,which)[0]['impact']=='RECONSIDERATION_REQUIRED')
 elif index==3:
  check(submit(req('sop-prior'))['status']=='ADMITTED');res=alter(root,[which],'procedure:SOP-XFER-CONTAINER','2026.2');check(res[which]['status']=='APPLIED');res=submit(req('sop-stale'));check(res['reason']=='STALE_PROCEDURE_VERSION' and admitted(root,which)[0]['impact']=='RECONSIDERATION_REQUIRED')
 elif index==4:
  old=req('revoked-new-nonce');new,updated=rotate(root,which);check(updated['status']=='UPDATED');res=submit(old);check(res['status']=='REFUSED' and effect_count(root,which)==0);res=submit(req('revoked-new-nonce-2',worker=new));check(res['status']=='ADMITTED')
 elif index==5:
  check(submit(req('succession-previous'))['status']=='ADMITTED');lost=submit(req('succession-lost'),crash=True);check(lost['status']=='UNKNOWN' and lost['returncode']==79);successor,_=rotate(root,which);recovered=dispatch(root,which,'recover',{'request':req('succession-lost',worker=successor,op='recover')});check(recovered['status']=='ADMITTED' and recovered['replayed'] and effect_count(root,which)==2)
 elif index==6:
  r=req('duplicate');one=submit(r);two=submit(r);check(one['status']=='ADMITTED' and two['replayed'] and two['receipt']==one['receipt'] and effect_count(root,which)==1)
 elif index==7:
  lost=submit(req('killed-process'),crash=True);check(lost['returncode']==79);recovered=dispatch(root,which,'recover',{'request':req('killed-process',op='recover')});check(recovered['status']=='ADMITTED' and effect_count(root,which)==1)
 elif index==8:
  cap_batch=10 if which=='A' else 2
  check(submit(req('cap-one',cap_batch))['status']=='ADMITTED');check(submit(req('cap-two',cap_batch))['status']=='ADMITTED');successor,_=rotate(root,which);res=submit(req('cap-three',1,worker=successor));check(res['status']=='REFUSED' and effect_count(root,which)==2)
 elif index==9:
  r=req('tampered-1');r['destination_station']='Station_X';check(submit(r)['status']=='REFUSED');s=req('tampered-2');s['units']=9;check(submit(s)['status']=='REFUSED' and effect_count(root,which)==0)
 elif index==10:
  r=req('fake-gate');p=subprocess.run([sys.executable,str(ROOT/'defective_c.py'),str(home),json.dumps(r)],capture_output=True,text=True,timeout=15);check(p.returncode==0);obs=rows(root,which);check(obs['status']=='FAIL' and any('FABRICATED_ADMISSION' in f for f in obs['faults']));return {'status':'PASS','observed_faults':obs['faults'],'negative':True}
 elif index==11:
  identity=home/'controller'/'identity.json';backup=home/'controller'/'identity.off';identity.rename(backup)
  try:res=submit(req('controller-outage'))
  finally:backup.rename(identity)
  check(res['status']=='UNKNOWN' and effect_count(root,which)==0);check(submit(req('controller-recovered'))['status']=='ADMITTED')
 elif index==12:
  check(submit(req('cross-first'))['status']=='ADMITTED');other='B' if which=='A' else 'A'
  otherwho=member(other);otherreq=request(root,other,otherwho,'cross-other',2);check(dispatch(root,other,'admit',{'request':otherreq})['status']=='ADMITTED')
  forged=dispatch(root,other,'inspect')['controller']['rows'][0]['controller_receipt']
  with db(home/'gate.sqlite') as c:c.execute('UPDATE admitted SET controller_receipt=? WHERE effect_id=?',(forged,'cross-first'))
  obs=rows(root,which);check(obs['status']=='FAIL' and any('CONTROLLER_RECEIVER_DISAGREE' in f for f in obs['faults']));return {'status':'PASS','observed_faults':obs['faults'],'negative':True}
 elif index==13:
  check(submit(req('impact-prior'))['status']=='ADMITTED');other='B' if which=='A' else 'A';check(dispatch(root,other,'admit',{'request':request(root,other,member(other),'impact-other',2)})['status']=='ADMITTED')
  changed='Station_A_calibration' if which=='A' else 'Station_C_calibration';alter(root,[which,other],changed)
  own=admitted(root,which);unrelated=admitted(root,other);check(own[0]['impact']=='RECONSIDERATION_REQUIRED' and unrelated[0]['impact']=='VALID')
  with db(home/'gate.sqlite') as c:c.execute('UPDATE admitted SET dependencies=? WHERE effect_id=?',('{}','impact-prior'))
  alter(root,[which],'UNMAPPED_NEW_COMPONENT',sha('unknown-facility'))
  check(admitted(root,which)[0]['impact']=='RECONSIDERATION_REQUIRED')
  owner=read(root/'owner.json');perm=verify(read(home/'permit.json')['jws'],owner['pub'],'factory','robot.work.permit.v1');perm['revision']+=1;perm['dependencies']={};perm['required_config_digest']=sha({});check(dispatch(root,which,'permit',{'permit_jws':sign(perm,owner['seed'],'factory')})['status']=='UPDATED')
  refused=submit(req('unknown-dependency'));check(refused['status']=='REFUSED' and 'DEPENDENCY_UNKNOWN' in refused['reason'])
 elif index==14:
  response=controller(home,'raw',{'campaign':'bypassed','effect_id':'raw-bypass','units':1});check(response['status']=='ADMITTED');obs=rows(root,which);check(obs['status']=='FAIL' and any('UNAUTHORIZED_CONTROLLER_BYPASS_DETECTED' in f for f in obs['faults']));return {'status':'PASS','observed_faults':obs['faults'],'negative':True}
 else:raise ValueError('UNKNOWN_CASE')
 obs=rows(root,which);check(obs['status']=='PASS' or (index==13 and obs['status']=='FAIL' and 'UNKNOWN_DEPENDENCY_HISTORY' in obs['faults']),str(obs));return {'status':'PASS','controller_rows':obs['controller_effects'],'receiver_rows':obs['receiver_effects'],'known_negative':obs['faults'] if index==13 else []}

SCENARIOS=['unauthorized scope/payload','stale configuration','procedure version change','revoked worker fresh nonce','successor recovered UNKNOWN','idempotent duplicate','process SIGKILL after commit','epoch/cap conflict','signed parameter tamper','fabricated admission without controller','controller outage UNKNOWN','cross-receiver receipt substitution','affected/unaffected + unknown dependency','direct dispatch controller bypass']
def run_all(which='A'):
 from concurrent.futures import ThreadPoolExecutor,as_completed
 jobs=list(range(1,15));times={};results={};t0=time.monotonic()
 # Each case uses a distinct fully isolated simulator with own signing keys and databases.
 with ThreadPoolExecutor(max_workers=3) as ex:
  future={ex.submit(run_case,n,which):n for n in jobs}
  for f in as_completed(future):
   k=future[f]
   try:out=f.result();results[k]={'name':SCENARIOS[k-1],**out}
   except Exception as e:results[k]={'name':SCENARIOS[k-1],'status':'FAIL','error':repr(e)}
 return {'target':which,'passed':sum(x['status']=='PASS' for x in results.values()),'total':14,'duration_seconds':round(time.monotonic()-t0,3),'scenarios':[{'case':k,**results[k]} for k in sorted(results)]}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--target',choices=['A','B','V'],default='A');p.add_argument('--json',action='store_true');x=p.parse_args();r=run_all(x.target);print(json.dumps(r,indent=2));sys.exit(0 if r['passed']==14 else 1)
