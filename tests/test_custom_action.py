"""Only released APIs used: custom developer action + receiver SQL authorization."""
import json,secrets,sqlite3,tempfile,unittest
from pathlib import Path
from openline_connect.onboarding import initialize,allow,read_engine
from openline_connect.engine import ProtectionError

class CustomAction(unittest.TestCase):
 def test_custom_table_and_unlisted_rejected(self):
  with tempfile.TemporaryDirectory() as h:
   info=initialize(h);home=Path(h)
   policy=json.loads((home/'policy.json').read_text());policy['effect_sql']={'tables':['purchase_requests'],'functions':[]}
   (home/'policy.json').write_text(json.dumps(policy))
   with sqlite3.connect(home/'connect.sqlite') as db:
    db.execute('CREATE TABLE purchase_requests(order_id TEXT PRIMARY KEY, approved INTEGER)')
    db.execute('CREATE TABLE unauthorized(order_id TEXT PRIMARY KEY)')
   exact={'target':'PO-NATIVE-001','order_id':'PO-NATIVE-001','amount_cents':300}
   grant=allow(home,action='procurement.approve_order',params=exact,ttl_seconds=60)
   engine=read_engine(home)
   def commit(params, db):
    db.execute('INSERT INTO purchase_requests(order_id,approved) VALUES(?,?)',(params['order_id'],1))
    return {'ok':True,'order_id':params['order_id']}
   engine.register('procurement.approve_order',commit,max_amount_cents=500,atomic=True)
   request=json.loads(Path(grant['fictional_agent_request']).read_text())
   first=engine.execute(**request);self.assertEqual(first['decision'],'ALLOW')
   replay=engine.execute(**request);self.assertTrue(replay.get('replayed'))
   with sqlite3.connect(home/'connect.sqlite') as db:
    self.assertEqual(db.execute('SELECT COUNT(*) FROM purchase_requests').fetchone()[0],1)
   from openline_connect.onboarding import verify_local
   proof=verify_local(home,seller_public=info['seller_public'],verify_records=True)
   self.assertTrue(proof['application_tables_match_signed_outcome'])
   with sqlite3.connect(home/'connect.sqlite') as db:
    db.execute('UPDATE purchase_requests SET approved=0 WHERE order_id=?',('PO-NATIVE-001',))
   with self.assertRaises(ValueError):
    verify_local(home,seller_public=info['seller_public'],verify_records=True)
   # A vendor-provided handler cannot escape granted SQLite table scope via comments/aliases/CTE.
   for sql in ['SELECT * FROM unauthorized','SELECT * FROM (SELECT * FROM unauthorized) AS x',
               'SELECT * FROM purchase_requests /* unauthorized */ UNION SELECT * FROM unauthorized',
               'INSERT INTO unauthorized VALUES(?)','DROP TABLE purchase_requests',
               'BEGIN','PRAGMA writable_schema=ON']:
    with self.subTest(sql=sql):
     from openline_connect.engine import _EffectDB
     with engine.db() as db:
      with self.assertRaises(ProtectionError):_EffectDB(db,('purchase_requests',)).execute(sql,('x',) if '?' in sql else ())
 def test_cli_action_not_record_update(self):
  from openline_connect.cli import main
  with tempfile.TemporaryDirectory() as home:
   initialize(home)
   main(['allow','--home',home,'--action','procurement.approve_order','--params-json',json.dumps({'target':'PO-1','order_id':'PO-1','amount_cents':10})])
if __name__=='__main__':unittest.main()
