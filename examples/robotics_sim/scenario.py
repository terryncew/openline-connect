"""Owner-only fixtures and scripted 10-step local demonstration. No commercial robot commands."""
import json,subprocess,sys,time,uuid
from pathlib import Path
from wire import keys,read,write,sign,sha,now,public
from runtime import initialize_gate
from controller import initialize as init_controller

def receiver_path(root,which):return Path(root)/('receiver_a' if which=='A' else 'receiver_b' if which=='B' else 'conventional')
def dispatch(root,which,op,payload=None):
 script='receiver_a.py' if which=='A' else 'receiver_b.py' if which=='B' else 'conventional_receiver.py'
 operation=op if which=='A' else {'admit':'order','recover':'reconcile','change':'manifest','permit':'permit','inspect':'inspect'}[op]
 cmd=[sys.executable]+(['-O'] if sys.flags.optimize else [])+[str(Path(__file__).with_name(script)),str(receiver_path(root,which)),operation,json.dumps(payload or {},sort_keys=True)]
 p=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
 if p.returncode==79:return {'status':'UNKNOWN','reason':'CRASH_AFTER_CONTROLLER_COMMIT','returncode':79}
 try:data=json.loads(p.stdout)
 except Exception:raise RuntimeError('NO_RECEIVER_REPLY '+p.stderr[:200])
 return data

def permit_template(owner,receiver_id,who,worker,facility,revision=1,epoch=1):
 north=who=='A';workcell='Workcell_North' if north else 'Workcell_South'
 source,dest=('Station_A','Station_B') if north else ('Station_C','Station_D')
 deps= ['Station_A_calibration','Station_B_calibration','Arm_kinematics_v2'] if north else ['Station_C_calibration','Station_D_calibration']
 return {'kind':'robot.work.permit.v1','domain_type':'robotics.work_permit.v1','factory_id':owner['factory_id'],'receiver_id':receiver_id,'permit_id':'permit-'+who.lower()+'-001','campaign':'campaign-'+who.lower(),'revision':revision,'workcell_id':workcell,'zone':'zone-north-robot' if north else 'zone-south-robot','job_spec':{'action':'container_transfer','source_station':source,'destination_station':dest,'max_units':20 if north else 4,'max_payload_kg':50},'dependencies':{d:facility['components'][d] for d in deps},'required_config_digest':sha({d:facility['components'][d] for d in deps}),'procedure_id':'SOP-XFER-CONTAINER','required_procedure_version':facility['procedures']['SOP-XFER-CONTAINER'],'worker_id':worker['name'],'delegated_worker_pubkey':worker['pub'],'worker_epoch':epoch,'valid_from':now()-100,'valid_until':now()+3600}

def init(root):
 root=Path(root);root.mkdir(parents=True,exist_ok=True)
 owner_seed,owner_pub=keys();owner={'seed':owner_seed,'pub':owner_pub,'factory_id':'factory-demo-01'};write(root/'owner.json',owner)
 workers={}
 for name in ('A','B'):
  seed,pub=keys();workers[name]={'name':'Worker-'+name,'seed':seed,'pub':pub};write(root/('worker-'+name+'.json'),workers[name])
 components={k:sha(k+'-v1') for k in ('Station_A_calibration','Station_B_calibration','Arm_kinematics_v2','Station_C_calibration','Station_D_calibration','Station_C_sensor')}
 facility={'kind':'robot.facility.manifest.v1','factory_id':owner['factory_id'],'sequence':1,'components':components,'procedures':{'SOP-XFER-CONTAINER':'2026.1'}}
 for which in ('A','B','V'):
  home=receiver_path(root,which);home.mkdir(parents=True,exist_ok=True)
  rseed,rpub=keys();controller_pub=init_controller(home/'controller',rpub,'robot-receiver-'+which.lower())
  info={'seed':rseed,'public':rpub,'owner_pub':owner_pub,'receiver_id':'robot-receiver-'+which.lower(),'controller_pub':controller_pub,'worker_epoch':1,'adapter':'ROS2_ACTION_SIMULATED' if which=='A' else 'VDA_JSON_SIMULATED' if which=='B' else 'CONVENTIONAL_SQLITE_REFERENCE'}
  write(home/'identity.json',info);initialize_gate(home)
  write(home/'facility.json',{'jws':sign(facility,owner_seed,'factory')})
  permit=permit_template(owner,info['receiver_id'],which,workers['A' if which=='A' else 'B'],facility)
  write(home/'permit.json',{'jws':sign(permit,owner_seed,'factory')})
 write(root/'state.json',{'next_nonce':0,'unknown':[],'events':[]});return root

def request(root,which,worker,effect_id,units=5,payload=30,op='admit',nonce=None,**overrides):
 root=Path(root);worker_info=read(root/('worker-'+worker+'.json'));permit=read(receiver_path(root,which)/'permit.json')
 from wire import verify
 pp=verify(permit['jws'],read(root/'owner.json')['pub'],'factory','robot.work.permit.v1')
 j=pp['job_spec']
 fields={'effect_id':effect_id,'units':units,'payload_kg':payload,'action':j['action'],'source_station':j['source_station'],'destination_station':j['destination_station'],'workcell_id':pp['workcell_id'],'zone':pp['zone']};fields.update(overrides)
 w={'kind':'robot.worker.request.v1','op':op,'receiver_id':pp['receiver_id'],'permit_id':pp['permit_id'],'worker_epoch':pp['worker_epoch'],'campaign':pp['campaign'],'nonce':nonce or uuid.uuid4().hex,**fields}
 return {**fields,'worker_jws':sign(w,worker_info['seed'],worker_info['name'])}

def amend_worker(root):
 root=Path(root);owner=read(root/'owner.json');w=read(root/'worker-B.json');home=receiver_path(root,'A');from wire import verify
 permit=verify(read(home/'permit.json')['jws'],owner['pub'],'factory','robot.work.permit.v1');permit.update({'revision':permit['revision']+1,'worker_epoch':permit['worker_epoch']+1,'worker_id':w['name'],'delegated_worker_pubkey':w['pub']})
 return dispatch(root,'A','permit',{'permit_jws':sign(permit,owner['seed'],'factory')})

def apply_change(root,component='Station_A_calibration',newval=None):
 root=Path(root);owner=read(root/'owner.json');from wire import verify
 previous_token=read(receiver_path(root,'A')/'facility.json')['jws'];old=verify(previous_token,owner['pub'],'factory','robot.facility.manifest.v1')
 changed=json.loads(json.dumps(old));changed['sequence']+=1;newval=newval or sha(component+'-v2')
 if component.startswith('procedure:'):changed['procedures'][component.partition(':')[2]]=newval
 else:changed['components'][component]=newval
 event={'kind':'robot.facility.change.v1','change_id':'factory-change-'+str(changed['sequence'])+'-'+component,'sequence':changed['sequence'],'component':component,'prior_digest':(old['procedures'].get(component.partition(':')[2],'UNKNOWN') if component.startswith('procedure:') else old['components'].get(component,'UNKNOWN')),'new_digest':newval,'prior_manifest_sha':sha(previous_token.encode()),'at':now()}
 ev=sign(event,owner['seed'],'factory');token=sign(changed,owner['seed'],'factory')
 result={x:dispatch(root,x,'change',{'change_jws':ev,'facility_jws':token}) for x in ('A','B')};return result

def reapprove(root):
 root=Path(root);owner=read(root/'owner.json');from wire import verify
 home=receiver_path(root,'A');p=verify(read(home/'permit.json')['jws'],owner['pub'],'factory','robot.work.permit.v1');f=verify(read(home/'facility.json')['jws'],owner['pub'],'factory','robot.facility.manifest.v1')
 p['revision']+=1;p['dependencies']={name:f['components'][name] for name in p['dependencies']};p['required_config_digest']=sha(p['dependencies']);return dispatch(root,'A','permit',{'permit_jws':sign(p,owner['seed'],'factory')})

def execute_walkthrough(root,verbose=True):
 root=Path(root);init(root);events=[]
 def add(step,label,record):
  events.append({'step':step,'label':label,'result':record});print(f'{step:02d} {label}: {record.get("status", "")}',flush=True) if verbose else None;return record
 a=add(1,'five units under Worker A',dispatch(root,'A','admit',{'request':request(root,'A','A','xfer-001',5)}))
 assert a['status']=='ADMITTED'
 crash=add(2,'controller commits xfer-002 then receiver exits',dispatch(root,'A','admit',{'request':request(root,'A','A','xfer-002',5),'crash':True}))
 assert crash['status']=='UNKNOWN' and crash['returncode']==79
 add(3,'owner revokes A and authorizes successor B',amend_worker(root))
 recovered=add(4,'B recovers original admission',dispatch(root,'A','recover',{'request':request(root,'A','B','xfer-002',op='recover')}))
 assert recovered['status']=='ADMITTED' and recovered['replayed']
 denial=add(5,'revoked A fresh nonce rejected',dispatch(root,'A','admit',{'request':request(root,'A','A','xfer-003',5)}))
 assert denial['status']=='REFUSED'
 add(6,'Station_A v1 to v2 targeted change',apply_change(root))
 stale=add(7,'A old config refuses remaining batch',dispatch(root,'A','admit',{'request':request(root,'A','B','xfer-003',10)}))
 assert stale['status']=='REFUSED' and stale['reason'].startswith('STALE_COMMISSIONING_CONFIG')
 other=add(8,'unaffected B order passes',dispatch(root,'B','admit',{'request':request(root,'B','B','south-001',2)}))
 assert other['status']=='ADMITTED'
 add(9,'factory issues calibration reapproval',reapprove(root))
 finish=add(10,'remaining ten admitted under revision',dispatch(root,'A','admit',{'request':request(root,'A','B','xfer-003',10)}))
 assert finish['status']=='ADMITTED'
 audit=dispatch(root,'A','inspect');assert sum(x['units'] for x in audit['admitted'])==20 and len(audit['controller']['rows'])==3
 assert [x['impact'] for x in audit['admitted'] if x['effect_id'] in ('xfer-001','xfer-002')]==['RECONSIDERATION_REQUIRED']*2
 result={'events':events,'north':audit,'south':dispatch(root,'B','inspect'),'ros2':'SIMULATED'};write(root/'walkthrough_results.json',result);return result
