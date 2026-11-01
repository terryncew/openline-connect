"""Real HTTP worker A/B recovery through unchanged ConnectEngine."""
import json, secrets, sqlite3, tempfile, unittest
from pathlib import Path
from openline_connect.onboarding import (
    initialize, allow, read_engine, verify_local, issue_fictional_delegated_task)

class TaskRecovery(unittest.TestCase):
    def test_exact_signed_successor_and_no_duplicate_effect(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from openline_connect.fastapi_route import mount_guarded_route
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            trust=initialize(root)
            policy=json.loads((root/'policy.json').read_text())
            policy['effect_sql']={'tables':['tickets'],'functions':[]}
            (root/'policy.json').write_text(json.dumps(policy))
            with sqlite3.connect(root/'connect.sqlite') as db:
                db.execute('CREATE TABLE tickets (ticket TEXT PRIMARY KEY, owner TEXT)')
            app=FastAPI()
            engine=read_engine(root)
            def assign(params, db):
                db.execute('INSERT INTO tickets VALUES(?,?)',(params['target'],params['owner']))
                return {'ticket':params['target']}
            mount_guarded_route(app,engine,path='/assign',action='support.assign',
                                handler=assign,max_amount_cents=0)
            params={'target':'CASE-129','owner':'queue-b','amount_cents':0}
            allow(root,action='support.assign',params=params)
            engine.reload_policy()
            def cred(w):
                return issue_fictional_delegated_task(root,action='support.assign',
                    params=params,task_id='job-129',worker_subject=w,
                    worker_seed=secrets.token_hex(32))
            a,b=cred('worker-a'),cred('worker-b')
            def body(x):return {k:x[k] for k in ('params','authorization','nonce','task_id')}
            with TestClient(app) as client:
                first=client.post('/assign',json=body(a))
                self.assertEqual(first.status_code,200,first.text)
                self.assertEqual(first.json()['decision'],'ALLOW')
                engine.revoke(a['delegation_id'])
                old=client.post('/assign',json={**body(a),'nonce':'new-nonce'})
                self.assertNotEqual(old.status_code,200)
                old_recover=client.post('/assign',json={**body(a),'recover_only':True})
                self.assertNotEqual(old_recover.status_code,200)
                new=client.post('/assign',json={**body(b),'recover_only':True})
                self.assertEqual(new.status_code,200,new.text)
                self.assertEqual(new.json()['receipt'],first.json()['receipt'])
                self.assertEqual(new.json()['outcome'],first.json()['outcome'])
                self.assertTrue(new.json()['replayed'])
                again=client.post('/assign',json=body(b))
                self.assertEqual(again.status_code,200,again.text)
                self.assertEqual(again.json()['receipt'],first.json()['receipt'])
                for changed in ({'recover_only':'true'},{'task_id':None,'recover_only':True},
                                {'nonce':12},{'task_id':''},{'authorization':' '},
                                {'action':'caller-chosen'}):
                    result=client.post('/assign',json={**body(b),**changed})
                    self.assertEqual(result.status_code,400,(changed,result.text))
                tamper=client.post('/assign',json={**body(b),
                    'params':{**params,'owner':'evil'},'recover_only':True})
                self.assertNotEqual(tamper.status_code,200)
                self.assertEqual(client.post('/assign',content=b'{"params":{},"params":{}}',
                    headers={'content-type':'application/json'}).status_code,400)
            with sqlite3.connect(root/'connect.sqlite') as db:
                self.assertEqual(db.execute('SELECT ticket,owner FROM tickets').fetchall(),
                                 [('CASE-129','queue-b')])
            self.assertTrue(verify_local(root,seller_public=trust['seller_public'],
                                         verify_records=True)['verified'])

if __name__=='__main__':unittest.main()
