"""Intentionally defective C: conformance must reject all four flaw classes, exit 1."""
import json,subprocess,sys
from conformance import fresh,request,receiver_path,rotate,alter,rows,controller
from pathlib import Path
ROOT=Path(__file__).parent

def attempt(which,kind):
 root=fresh();home=receiver_path(root,which)
 if kind=='revocation':
  req=request(root,which,'A' if which=='A' else 'B','C-revoked',2);rotate(root,which)
 elif kind=='stale_config':
  alter(root,[which],'Station_A_calibration' if which=='A' else 'Station_C_calibration');req=request(root,which,'A' if which=='A' else 'B','C-stale',2)
 elif kind=='ambiguous_dependencies':
  req=request(root,which,'A' if which=='A' else 'B','C-unmapped',2);from wire import read,write,verify,sign,sha
  owner=read(root/'owner.json');p=verify(read(home/'permit.json')['jws'],owner['pub'],'factory','robot.work.permit.v1');p['dependencies']={};p['required_config_digest']=sha({});p['revision']+=1;write(home/'permit.json',{'jws':sign(p,owner['seed'],'factory')})
 else:
  controller(home,'raw',{'effect_id':'C-raw','campaign':'C-bypass','units':1});return rows(root,which)
 p=subprocess.run([sys.executable,str(ROOT/'defective_c.py'),str(home),json.dumps(req)],capture_output=True,text=True,timeout=15)
 assert p.returncode==0
 return rows(root,which)

def main():
 results=[]
 for k in ('revocation','stale_config','ambiguous_dependencies','direct_dispatch'):
  out=attempt('A',k);results.append({'attack':k,'status':'FAIL','reason':'Defective C does not bind receiver authorization to controller consequence','observer_faults':out['faults']})
 print(json.dumps({'target':'DefectiveReceiverC','passed':0,'total':4,'status':'FAIL_EXPECTED','cases':results},indent=2))
 return 1
if __name__=='__main__':sys.exit(main())
