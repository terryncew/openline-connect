"""Exercise the exact H01 engine and the sqlite3 authorizer, not token matching."""
import json,sqlite3,tempfile,unittest
from pathlib import Path
from openline_connect.onboarding import initialize,allow,read_engine
from openline_connect.engine import _EffectDB,ProtectionError

class SQLAuthorityTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.home=Path(self.tmp.name)/'h';initialize(self.home)
  self.grant=allow(self.home,action='record.update',target='r1',value='ok',amount_cents=20,ttl_seconds=300)
  self.req=json.loads(Path(self.grant['fictional_agent_request']).read_text())
  with sqlite3.connect(self.home/'connect.sqlite') as db:
   db.execute('CREATE TABLE orders(id TEXT PRIMARY KEY, value TEXT)')
   db.execute('CREATE TABLE orders_extra(id TEXT PRIMARY KEY, value TEXT)')
   db.execute('CREATE TABLE sensitive_hidden(id TEXT PRIMARY KEY, value TEXT)')
  pol=json.loads((self.home/'policy.json').read_text());pol['effect_sql']={'tables':['orders'],'functions':['count']}
  (self.home/'policy.json').write_text(json.dumps(pol))
  self.eng=read_engine(self.home)
 def test_capability_allowed_on_real_engine(self):
  def handler(p,db):
   db.execute('INSERT INTO orders(id,value) VALUES (?,?)',('r1','yes'))
   return {'count':db.execute('SELECT count(*) FROM orders AS o WHERE o.id=?',('r1',)).fetchone()[0]}
  self.eng._handlers['record.update']=(handler,5000,True,False)
  res=self.eng.execute(**self.req)
  self.assertEqual(res['state'],'FULFILLED')
  with sqlite3.connect(self.home/'connect.sqlite') as db:self.assertEqual(db.execute('SELECT count(*) FROM orders').fetchone()[0],1)
 def test_all_paths_denied(self):
  stmts=[
   'SELECT * FROM records',
   'SELECT * FROM orders JOIN sensitive_hidden USING(id)',
   'SELECT * FROM (SELECT * FROM revocations)',
   'SELECT * FROM orders UNION SELECT token_id,at FROM revocations',
   'SELECT * FROM orders_extra',
   'SELECT * FROM \"orders\" WHERE exists (SELECT 1 FROM sqlite_master)',
   'UPDATE operations SET state=\'FULFILLED\'',
   'DELETE FROM orders_extra',
   'INSERT INTO audit_entries (outcome,body) VALUES(\'x\',\'y\')',
   'CREATE TABLE newtable(x)',
   'DROP TABLE orders',
   'PRAGMA writable_schema = 1',
   "ATTACH DATABASE ':memory:' AS alternate",
   'BEGIN IMMEDIATE',
   'ROLLBACK',
   'SAVEPOINT dangerous',
   'SELECT sqlite_version() FROM orders',
   'SELECT count(*) FROM orders /* AUTHORIZED */ JOIN revocations AS r ON 1=1',
  ]
  with sqlite3.connect(self.home/'connect.sqlite') as db:
   gate=_EffectDB(db,('orders',),('count',))
   for sql in stmts:
    with self.subTest(sql=sql):
     with self.assertRaises((ProtectionError,sqlite3.DatabaseError)):
      gate.execute(sql)
 def test_cannot_grant_security_tables(self):
  pol=json.loads((self.home/'policy.json').read_text())
  pol['effect_sql']['tables']=['decisions'];(self.home/'policy.json').write_text(json.dumps(pol))
  with self.assertRaises(ValueError):read_engine(self.home)

if __name__=='__main__':unittest.main()
