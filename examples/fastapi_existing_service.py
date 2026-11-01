"""A pre-existing fictional ticket service with ONE receiver-owned route protected.

Run: python -m pip install '.[fastapi]' httpx
     python examples/fastapi_existing_service.py
No network listener, external effect, customer data, or real tokens. TestClient
sends ASGI HTTP requests to the exact route and audits actual SQLite rows.
"""
import json
import secrets
import sqlite3
import tempfile
from pathlib import Path
from fastapi import FastAPI
from fastapi.testclient import TestClient
from openline_connect.fastapi_route import mount_guarded_route
from openline_connect.onboarding import initialize, allow, read_engine, verify_local, issue_fictional_delegated_task


def run():
    with tempfile.TemporaryDirectory(prefix='existing-service-openline-') as temp:
        root = Path(temp)
        trust = initialize(root)
        policy = json.loads((root/'policy.json').read_text())
        policy['effect_sql'] = {'tables':['support_tickets'], 'functions':[]}
        (root/'policy.json').write_text(json.dumps(policy))
        with sqlite3.connect(root/'connect.sqlite') as db:
            db.execute('CREATE TABLE support_tickets(ticket TEXT PRIMARY KEY, assigned_to TEXT NOT NULL)')
        app = FastAPI(title='Pre-existing support service')
        @app.get('/tickets/health')
        def health(): return {'service':'support', 'status':'up'}
        engine = read_engine(root)
        def assign(params, authorized_db):
            authorized_db.execute('INSERT INTO support_tickets(ticket,assigned_to) VALUES(?,?)',
                                  (params['ticket'],params['assigned_to']))
            return {'ticket':params['ticket'],'assigned_to':params['assigned_to']}
        mount_guarded_route(app, engine, path='/tickets/assign',action='support.assign',
                            handler=assign,max_amount_cents=0)
        params={'ticket':'CASE-17','assigned_to':'queue-b','target':'CASE-17','amount_cents':0}
        grant=allow(root,action='support.assign',params=params,ttl_seconds=180)
        engine.reload_policy()  # Only the receiver operator may reload its signed grant file.
        request=json.loads(Path(grant['fictional_agent_request']).read_text())
        signed_body={k:request[k] for k in ('params','authorization','nonce')}
        with TestClient(app) as client:
            assert client.get('/tickets/health').status_code==200
            denied=client.post('/tickets/assign',json={'params':params,'authorization':'bad','nonce':'bad'})
            assert denied.status_code in (200,400,403),denied.text
            assert denied.status_code!=200 or denied.json()['decision']!='ALLOW'
            first=client.post('/tickets/assign',json=signed_body)
            assert first.status_code==200 and first.json()['decision']=='ALLOW',first.text
            replay=client.post('/tickets/assign',json=signed_body)
            assert replay.status_code==200 and replay.json().get('replayed'),replay.text
            tampered={**signed_body,'params':{**params,'assigned_to':'queue-evil'},'nonce':'fresh-nonce-2'}
            bad=client.post('/tickets/assign',json=tampered)
            assert bad.status_code!=200 or bad.json()['decision']!='ALLOW',bad.text
            duplicate_json=('{'+'"params":{},"params":{},"authorization":"x","nonce":"x"'+'}').encode()
            assert client.post('/tickets/assign',content=duplicate_json,headers={'content-type':'application/json'}).status_code==400
        # Reuse the same pre-existing HTTP route for signed worker succession.
        params2={'ticket':'CASE-18','assigned_to':'queue-c','target':'CASE-18','amount_cents':0}
        allow(root,action='support.assign',params=params2,ttl_seconds=180)
        engine.reload_policy()
        worker_a=issue_fictional_delegated_task(root,action='support.assign',params=params2,
            task_id='task-18',worker_subject='worker-a',worker_seed=secrets.token_hex(32))
        worker_b=issue_fictional_delegated_task(root,action='support.assign',params=params2,
            task_id='task-18',worker_subject='worker-b',worker_seed=secrets.token_hex(32))
        def request_of(worker):
            return {k:worker[k] for k in ('params','authorization','nonce','task_id')}
        with TestClient(app) as client:
            admitted=client.post('/tickets/assign',json=request_of(worker_a))
            if admitted.status_code!=200 or admitted.json().get('decision')!='ALLOW':
                raise RuntimeError('worker_a_admission_failed:'+admitted.text)
            original=admitted.json()  # Simulate a lost reply to the worker.
            engine.revoke(worker_a['delegation_id'])
            fresh=client.post('/tickets/assign',json={**request_of(worker_a),'nonce':'fresh'})
            if fresh.status_code==200:raise RuntimeError('revoked_worker_admitted')
            recovered=client.post('/tickets/assign',
                       json={**request_of(worker_b),'recover_only':True})
            if recovered.status_code!=200:
                raise RuntimeError('successor_recovery_failed:'+recovered.text)
            if (recovered.json().get('receipt')!=original['receipt'] or
                recovered.json().get('outcome')!=original['outcome'] or
                not recovered.json().get('replayed')):
                raise RuntimeError('recovered_receipt_not_original')
        with sqlite3.connect(root/'connect.sqlite') as db:
            rows=db.execute('SELECT ticket,assigned_to FROM support_tickets ORDER BY ticket').fetchall()
        if rows!=[('CASE-17','queue-b'),('CASE-18','queue-c')]:
            raise RuntimeError('unexpected_duplicate_effects:'+repr(rows))
        receipt=verify_local(root,seller_public=trust['seller_public'],verify_records=True)
        assert receipt['verified'] and receipt['application_tables_match_signed_outcome']
        return {'status':'PASS','existing_service_route':'/tickets/health',
                'protected_route':'/tickets/assign','unauthorized_refused':True,
                'exact_scope_tamper_refused':True,'duplicate_json_refused':True,
                'replay_no_second_effect':True,'sqlite_effect_rows':len(rows),
                'worker_a_revoked':True,'worker_b_original_receipt_recovered':True,
                'no_duplicate_effects':True,
                'pinned_receipt_verification':True,'scope':'synthetic local sqlite only',
                'fixture_key_warning':'Buyer and seller seed colocated only in offline demonstration'}

if __name__=='__main__':
    print(json.dumps(run(),sort_keys=True))
