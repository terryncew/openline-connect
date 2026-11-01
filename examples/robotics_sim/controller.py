"""Simulated *controller-owned* journal. No physical hardware. Raw dispatch is a deliberate bypass negative control."""
import argparse,json,sqlite3,sys
from pathlib import Path
from wire import sign,verify,read,write,sha,keys,now,public

def connect(path):
 c=sqlite3.connect(path,timeout=10,isolation_level=None);c.execute('PRAGMA journal_mode=WAL');c.execute('PRAGMA synchronous=FULL');return c

def initialize(home,receiver_pub,receiver_id):
 home=Path(home);home.mkdir(parents=True,exist_ok=True);secret,pub=keys();write(home/'identity.json',{'seed':secret,'public':pub,'receiver_pub':receiver_pub,'receiver_id':receiver_id})
 with connect(home/'journal.sqlite') as c:
  c.execute('CREATE TABLE IF NOT EXISTS effects(seq INTEGER PRIMARY KEY AUTOINCREMENT, campaign TEXT, effect_id TEXT, units INTEGER, permit_sha TEXT, request_sha TEXT, token_sha TEXT, controller_receipt TEXT, prev_hash TEXT, row_hash TEXT, at INTEGER, UNIQUE(campaign,effect_id))')
  c.execute('CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY, effect_id TEXT, kind TEXT, at INTEGER)')
 return pub

def run(home,op,arg=None):
 home=Path(home);identity=read(home/'identity.json');path=home/'journal.sqlite'
 with connect(path) as c:
  if op=='inspect':return {'rows':[dict(zip([x[1] for x in c.execute('PRAGMA table_info(effects)')],row)) for row in c.execute('SELECT * FROM effects ORDER BY seq')],'attempts':c.execute('SELECT effect_id,kind FROM attempts ORDER BY id').fetchall()}
  if op=='recover':
   # Only a signed caller authorization and receiver-scoped identity may disclose evidence.
   tok=verify(arg['recovery_auth'],identity['receiver_pub'],identity['receiver_id'],'robot.recovery.authorization.v1')
   if tok.get('effect_id')!=arg['effect_id'] or tok.get('campaign')!=arg['campaign']:raise ValueError('RECOVERY_SCOPE')
   row=c.execute('SELECT controller_receipt FROM effects WHERE campaign=? AND effect_id=?',(arg['campaign'],arg['effect_id'])).fetchone()
   return {'status':'ADMITTED','controller_receipt':row[0],'replayed':True} if row else {'status':'UNKNOWN'}
  if op not in ('admit','raw'):raise ValueError('BAD_CONTROLLER_OP')
  if op=='admit':
   tok=verify(arg['admission_token'],identity['receiver_pub'],identity['receiver_id'],'robot.controller.admit.v1')
   if tok.get('receiver_id')!=identity['receiver_id'] or tok.get('expires',0)<=now():raise ValueError('INVALID_ADMISSION_TOKEN')
   for k in ('campaign','effect_id','units','permit_sha','request_sha'):
    if tok.get(k)!=arg.get(k):raise ValueError('ADMISSION_TOKEN_SCOPE_'+k)
   if type(arg['units']) is not int or not 1<=arg['units']<=20:raise ValueError('UNITS')
  else:
   # Deliberate raw dispatcher: in real integrations it must be blocked by controller/PLC ACLs.
   # Here it is deliberately present so the observer demonstrates *detection* not prevention.
   arg=dict(arg);arg.setdefault('campaign','unsafe');arg.setdefault('effect_id','raw-unsafe');arg.setdefault('units',1);arg.setdefault('permit_sha','UNAUTHORIZED');arg.setdefault('request_sha','UNAUTHORIZED')
  c.execute('BEGIN IMMEDIATE')
  try:
   c.execute('INSERT INTO attempts(effect_id,kind,at) VALUES(?,?,?)',(arg['effect_id'],op,now()))
   existing=c.execute('SELECT controller_receipt FROM effects WHERE campaign=? AND effect_id=?',(arg['campaign'],arg['effect_id'])).fetchone()
   if existing:
    c.commit();return {'status':'ADMITTED','controller_receipt':existing[0],'replayed':True}
   prev=c.execute('SELECT row_hash FROM effects ORDER BY seq DESC LIMIT 1').fetchone();prev=prev[0] if prev else 'GENESIS'
   token_sha=sha(arg.get('admission_token','').encode());timestamp=now()
   row={'receiver_id':identity['receiver_id'],'campaign':arg['campaign'],'effect_id':arg['effect_id'],'units':arg['units'],'permit_sha':arg['permit_sha'],'request_sha':arg['request_sha'],'token_sha':token_sha,'prev_hash':prev,'at':timestamp,'bypass':op=='raw'}
   row_hash=sha(row)
   cur=c.execute('INSERT INTO effects(campaign,effect_id,units,permit_sha,request_sha,token_sha,controller_receipt,prev_hash,row_hash,at) VALUES(?,?,?,?,?,?,?,?,?,?)',(arg['campaign'],arg['effect_id'],arg['units'],arg['permit_sha'],arg['request_sha'],token_sha,'',prev,row_hash,timestamp))
   receipt=sign({'kind':'robot.controller.commit.v1','controller_id':identity['receiver_id']+'-controller','controller_seq':cur.lastrowid,'row_hash':row_hash,**row},identity['seed'],identity['receiver_id']+'-controller')
   c.execute('UPDATE effects SET controller_receipt=? WHERE seq=?',(receipt,cur.lastrowid));c.commit()
   return {'status':'ADMITTED','controller_receipt':receipt,'replayed':False}
  except Exception:c.rollback();raise

if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('home');ap.add_argument('op');ap.add_argument('payload',nargs='?',default='{}');a=ap.parse_args()
 try:print(json.dumps(run(a.home,a.op,json.loads(a.payload))))
 except Exception as e:print(json.dumps({'error':str(e),'status':'ERROR'}));sys.exit(2)
