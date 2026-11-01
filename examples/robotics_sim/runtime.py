"""Transport and SQLite conveniences only; contains zero security decisions."""
import subprocess,sys,json,sqlite3
from pathlib import Path

def controller(home,op,payload=None):
 cmd=[sys.executable]+(['-O'] if sys.flags.optimize else [])+[str(Path(__file__).with_name('controller.py')),str(Path(home)/'controller'),op,json.dumps(payload or {},sort_keys=True)]
 p=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
 try:out=json.loads(p.stdout)
 except Exception:raise RuntimeError('CONTROLLER_NO_RESPONSE '+p.stderr[:250])
 if p.returncode:raise ValueError('CONTROLLER_'+str(out.get('error','UNKNOWN')))
 return out

def db(path):
 c=sqlite3.connect(path,isolation_level=None,timeout=15);c.execute('PRAGMA journal_mode=WAL');c.execute('PRAGMA synchronous=FULL');return c

def initialize_gate(home):
 with db(Path(home)/'gate.sqlite') as c:
  c.execute('CREATE TABLE IF NOT EXISTS admitted(effect_id TEXT PRIMARY KEY,campaign TEXT,permit_id TEXT,revision INT,units INT,request_sha TEXT,receipt TEXT,controller_receipt TEXT,dependencies TEXT,impact TEXT DEFAULT "VALID",impact_event TEXT DEFAULT "")')
  c.execute('CREATE TABLE IF NOT EXISTS changes(seq INT PRIMARY KEY,change_id TEXT UNIQUE,component TEXT,prior TEXT,current TEXT,change_jws TEXT)')
  c.execute('CREATE TABLE IF NOT EXISTS decisions(id INTEGER PRIMARY KEY, effect_id TEXT,reason TEXT,receipt TEXT)')
