"""Independent read-only verifier. Imports wire primitives, never receiver enforcement."""
import argparse,json,sqlite3
from pathlib import Path
from wire import verify,sha,read

def audit(home):
 home=Path(home);identity=read(home/'identity.json');bad=[];matched=[]
 with sqlite3.connect(f'file:{home / "gate.sqlite"}?mode=ro',uri=True) as g,sqlite3.connect(f'file:{home / "controller" / "journal.sqlite"}?mode=ro',uri=True) as c:
  grows=g.execute('SELECT effect_id,campaign,units,request_sha,receipt,controller_receipt,impact,dependencies FROM admitted').fetchall()
  crows=c.execute('SELECT effect_id,campaign,units,permit_sha,request_sha,token_sha,controller_receipt,prev_hash,row_hash,at FROM effects ORDER BY seq').fetchall()
  by_effect={r[0]:r for r in crows};seen=set();previous='GENESIS'
  for row in crows:
   effect,campaign,units,perm,req,token,receipt,prev,row_hash,at=row;seen.add(effect)
   if prev!=previous:bad.append('BROKEN_CONTROLLER_HASH_CHAIN:'+effect)
   previous=row_hash
   expected={'receiver_id':identity['receiver_id'],'campaign':campaign,'effect_id':effect,'units':units,'permit_sha':perm,'request_sha':req,'token_sha':token,'prev_hash':row[7],'at':at,'bypass':perm=='UNAUTHORIZED'}
   if sha(expected)!=row_hash:bad.append('CONTROLLER_ROW_HASH_CHANGED:'+effect)
   try:
    claim=verify(receipt,identity['controller_pub'],identity['receiver_id']+'-controller','robot.controller.commit.v1')
    if claim['row_hash']!=row_hash or claim['effect_id']!=effect or claim['request_sha']!=req:bad.append('CONTROLLER_RECEIPT_MISMATCH:'+effect)
   except Exception:bad.append('BAD_CONTROLLER_SIGNATURE:'+effect)
   if perm=='UNAUTHORIZED' or token==sha(b''):bad.append('CRITICAL_FAULT: UNAUTHORIZED_CONTROLLER_BYPASS_DETECTED:'+effect)
  authorized=set()
  for effect,campaign,units,req,rec,ctrl,impact,deps in grows:
   authorized.add(effect)
   try:
    claim=verify(rec,identity['public'],identity['receiver_id'],'robot.task.admission.v1')
    match=by_effect.get(effect)
    if not match:bad.append('CRITICAL_FAULT: FABRICATED_ADMISSION_WITHOUT_CONTROLLER_CONSEQUENCE:'+effect);continue
    if claim['controller_receipt_sha']!=sha(ctrl.encode()) or match[6]!=ctrl or claim['request_sha']!=req or claim['units']!=units or match[2]!=units or match[4]!=req:bad.append('CRITICAL_FAULT: CONTROLLER_RECEIVER_DISAGREE:'+effect)
    else:matched.append(effect)
   except Exception:bad.append('BAD_RECEIVER_ADMISSION_SIGNATURE:'+effect)
  for effect in seen-authorized:bad.append('CRITICAL_FAULT: UNAUTHORIZED_CONTROLLER_BYPASS_DETECTED:'+effect)
  for _,_,_,_,_,_,impact,deps in grows:
   if not isinstance(json.loads(deps),dict) or not json.loads(deps):bad.append('UNKNOWN_DEPENDENCY_HISTORY')
 return {'status':'PASS' if not bad else 'FAIL','receiver_id':identity['receiver_id'],'matched_effect_ids':matched,'controller_effects':len(crows),'receiver_effects':len(grows),'faults':sorted(set(bad))}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('home');z=p.parse_args();print(json.dumps(audit(z.home),indent=2))
