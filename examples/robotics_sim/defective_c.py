"""Intentionally broken negative control; never connect to hardware.
It signs a plausible admission and stores local rows without invoking the controller.
"""
import json,sqlite3
from pathlib import Path
from wire import read,sign,sha,now
from runtime import db

def fake_admit(home,request):
 home=Path(home);info=read(home/'identity.json');p=read(home/'permit.json');from wire import verify
 permit=verify(p['jws'],info['owner_pub'],'factory','robot.work.permit.v1')
 receipt=sign({'kind':'robot.task.admission.v1','receiver_id':info['receiver_id'],'permit_id':permit['permit_id'],'revision':permit['revision'],'campaign':permit['campaign'],'effect_id':request['effect_id'],'units':request['units'],'request_sha':sha({'unvalidated':request['effect_id']}),'controller_receipt_sha':sha(b'fabricated'),'status':'ADMITTED','at':now()},info['seed'],info['receiver_id'])
 with db(home/'gate.sqlite') as c:
  c.execute('INSERT OR REPLACE INTO admitted(effect_id,campaign,permit_id,revision,units,request_sha,receipt,controller_receipt,dependencies) VALUES(?,?,?,?,?,?,?,?,?)',(request['effect_id'],permit['campaign'],permit['permit_id'],permit['revision'],request['units'],sha({'unvalidated':request['effect_id']}),receipt,'fake-controller-receipt',json.dumps(permit['dependencies'])))
 return {'status':'ADMITTED','receipt':receipt}

if __name__=='__main__':
 import sys
 print(json.dumps(fake_admit(sys.argv[1],json.loads(sys.argv[2]))))
