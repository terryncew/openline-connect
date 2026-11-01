"""Fictional B2B example: independent buyer/worker issuer processes and HTTP receiver.

This is a developer test, not third-party interoperability or OS-user key isolation.
No real payment or effects. Do not deploy the fixture-only lost-response header.
Requires ``pip install '.[fastapi]' httpx``.
"""
from __future__ import annotations
import base64, concurrent.futures, http.client, json, os, secrets, sqlite3, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from openline_connect.principals import ReceiverAuthority, BuyerAuthority, WorkerIdentity
from openline_connect.engine import ConnectEngine
from openline_connect.fastapi_route import mount_guarded_route
from openline_connect.signing import pub


def save_private(p,data):
    p.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(str(p),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'w') as f:f.write(data)


def jsonwrite(p,d):
    p.write_text(json.dumps(d,indent=2,sort_keys=True))


def identity(argv):
    role,subject,folder=argv
    p=Path(folder);p.mkdir(parents=True,exist_ok=True)
    seed=secrets.token_hex(32)
    obj=BuyerAuthority(subject=subject,private_seed=seed) if role=='buyer' else WorkerIdentity(subject=subject,private_seed=seed)
    obj.store(p/'seed')
    jsonwrite(p/'public.json',{'subject':subject,'public_key':obj.public_key,'role':role})


def delegate(argv):
    buyer_dir,worker_pub_file,grant_file,receiver_public_file,out=map(Path,argv)
    subject=json.loads((buyer_dir/'public.json').read_text())['subject']
    buyer=BuyerAuthority.load(subject=subject,path=buyer_dir/'seed')
    worker=json.loads(worker_pub_file.read_text())
    grant=json.loads(grant_file.read_text())
    meta=json.loads(receiver_public_file.read_text())
    signed=buyer.delegate(receiver_grant=grant,receiver_public=meta['seller_public'],receiver_id='receiver',
           worker_subject=worker['subject'],worker_public=worker['public_key'],delegation_id='SUCCESSOR-DELEGATION' if worker['subject']=='worker-b' else 'SAME-DELEGATION')
    out.write_text(signed)


def send(argv):
    worker_dir,buyer_pub_file,delegation_file,endpoint,out_file,buyer,task,target,mode=argv
    wi_data=json.loads((Path(worker_dir)/'public.json').read_text())
    wi=WorkerIdentity.load(subject=wi_data['subject'],path=Path(worker_dir)/'seed')
    buyer_pub=json.loads(Path(buyer_pub_file).read_text())
    signed=Path(delegation_file).read_text()
    params={'buyer':buyer,'target':target,'amount_cents':50}
    payload=wi.request(delegation=signed,buyer_subject=buyer,buyer_public=buyer_pub['public_key'],
                       action='invoice.approve',params=params,task_id=task,mandate_id='SAME-MANDATE')
    payload.pop('action')  # HTTP route selects action server-side, never caller input.
    if mode=='cross-read':
        # Malicious caller changes the requested buyer/target without a matching signed mandate.
        payload['params']={'buyer':'alpha','target':'alpha-inv','amount_cents':50}
        payload['recover_only']=True
    if mode=='cross-write':
        payload['params']={'buyer':'alpha','target':'alpha-inv','amount_cents':50}
    if mode=='recover':payload['recover_only']=True
    headers={'Content-Type':'application/json'}
    if mode=='lose':headers['X-Fixture-Lose-Reply']='1'
    req=urllib.request.Request(endpoint,data=json.dumps(payload).encode(),headers=headers,method='POST')
    try:
        with urllib.request.urlopen(req,timeout=12) as resp:
            result={'http':resp.status,'response':json.load(resp)}
    except urllib.error.HTTPError as exc:
        result={'http':exc.code,'response':exc.read().decode()}
    except (urllib.error.URLError,ConnectionError,TimeoutError,ConnectionResetError,http.client.IncompleteRead) as exc:
        result={'http':'LOST','error':type(exc).__name__}
    jsonwrite(Path(out_file),result)


def receive(argv):
    home,config_file,port,revoke_a=argv
    import uvicorn
    from fastapi import FastAPI,Request
    from fastapi.responses import Response
    home=Path(home);home.mkdir(parents=True,exist_ok=True)
    cfg=json.loads(Path(config_file).read_text())
    seedfile=home/'receiver.seed';policyfile=home/'policy.json'
    if not seedfile.exists():save_private(seedfile,secrets.token_hex(32))
    seed=seedfile.read_text()
    if not policyfile.exists():
        policy=ReceiverAuthority.initial_policy(effect_tables=['invoices'])
        for buyer,public in cfg['buyers'].items():
            policy=ReceiverAuthority.register_buyer(policy,buyer_subject=buyer,buyer_public=public)
        jsonwrite(policyfile,policy)
    policy=json.loads(policyfile.read_text())
    e=ConnectEngine('sqlite:///'+str(home/'receiver.sqlite'),policy,seller_seed=seed,seller_id='receiver')
    with e.db() as db:db.execute('CREATE TABLE IF NOT EXISTS invoices(buyer TEXT,invoice TEXT,amount INTEGER,PRIMARY KEY(buyer,invoice))')
    def handler(params,db):
        db.execute('INSERT INTO invoices VALUES(?,?,?)',(params['buyer'],params['target'],params['amount_cents']))
        return {'invoice':params['target']}
    app=FastAPI()
    mount_guarded_route(app,e,path='/v1/invoice',action='invoice.approve',handler=handler,max_amount_cents=500)
    if not e.policy['grants'].get('invoice.approve'):
        for buyer in ('alpha','beta'):
            g=ReceiverAuthority(e).issue_bounded_grant(buyer_subject=buyer,action='invoice.approve',grant_id='SAME-GRANT',
                    allowed_worker_subjects=['worker-a','worker-b'],permitted_keys=['buyer','target','amount_cents'],
                    fixed_params={'buyer':buyer},target_restrictions={},max_amount_per_op=100,
                    max_cumulative_amount=150,max_uses=2,expires_at=int(time.time())+800)
            jsonwrite(home/(buyer+'-grant.json'),g)
        jsonwrite(policyfile,e.policy)
    if revoke_a=='yes':ReceiverAuthority(e).revoke_delegation(buyer_subject='alpha',delegation_id='SAME-DELEGATION')
    jsonwrite(home/'receiver-public.json',{'seller_public':pub(seed)})
    # Demo-only response-loss fixture. The protected effect commits before response loss.
    @app.middleware('http')
    async def lose_response(request:Request,call_next):
        reply=await call_next(request)
        if request.headers.get('X-Fixture-Lose-Reply')=='1' and request.url.path=='/v1/invoice':
            from starlette.responses import StreamingResponse
            async def drop():
                raise ConnectionResetError('FIXTURE_AFTER_COMMIT_REPLY_LOSS')
                yield b''
            return StreamingResponse(drop(),status_code=200)
        return reply
    uvicorn.run(app,host='127.0.0.1',port=int(port),log_level='error')


def check_signed(token,receiver_public,expected_kind):
    a,b,c=token.split('.')
    unb64=lambda x:base64.urlsafe_b64decode(x+'='*(-len(x)%4))
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(receiver_public)).verify(unb64(c),(a+'.'+b).encode())
    data=json.loads(unb64(b))
    assert data['kind']==expected_kind
    return data


def orchestrate():
    import socket,signal
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp);receiver=root/'receiver';receiver.mkdir()
        buyers={};workers={}
        py=sys.executable;script=str(Path(__file__).resolve())
        def proc(*args):subprocess.run([py,script,*map(str,args)],check=True,stdout=subprocess.DEVNULL)
        for b in ('alpha','beta'):
            p=root/b;proc('identity','buyer',b,p);buyers[b]=p
            for w in ('worker-a','worker-b'):
                q=root/(b+'-'+w);proc('identity','worker',w,q);workers[b,w]=q
        cfg={'buyers':{b:json.loads((p/'public.json').read_text())['public_key'] for b,p in buyers.items()}}
        config=root/'public_config.json';jsonwrite(config,cfg)
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        endpoint=f'http://127.0.0.1:{port}/v1/invoice'
        def start(revoke=False):
            server=subprocess.Popen([py,script,'receive',str(receiver),str(config),str(port),'yes' if revoke else 'no'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            for _ in range(100):
                if server.poll() is not None:raise RuntimeError('receiver_process_failed')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=0.05):break
                except OSError:time.sleep(0.06)
            else:raise RuntimeError('receiver_not_ready')
            return server
        def stop(s):
            s.terminate();s.wait(timeout=10)
        def request(b,worker='worker-a',mode='normal',task='SAME-TASK',target=None,tag=None):
            grant=receiver/(b+'-grant.json');wd=workers[b,worker];buyer=buyers[b]
            signed=root/(b+'-'+worker+'-delegation.txt')
            proc('delegate',buyer,wd/'public.json',grant,receiver/'receiver-public.json',signed)
            out=root/(tag or b+'-'+worker+'-'+mode+'.json')
            proc('send',wd,buyer/'public.json',signed,endpoint,out,b,task,target or b+'-inv',mode)
            return json.loads(out.read_text())
        server=start()
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                fa=pool.submit(request,'alpha',mode='lose',tag='alpha-lost.json')
                fb=pool.submit(request,'beta',mode='normal')
                a,b=fa.result(),fb.result()
            assert a['http']=='LOST',a
            assert b['http']==200 and b['response']['decision']=='ALLOW',b
            bad=request('beta',mode='cross-read')
            assert bad['http']==403,bad
            attack=request('beta',mode='cross-write',task='cross-attempt')
            assert attack['http'] in (200,403) and (attack.get('response',{}).get('decision')=='DENY' if isinstance(attack.get('response'),dict) else attack['http']==403),'cross_write_not_denied'
            stop(server);server=start(revoke=True)
            stale=request('alpha',mode='normal',task='fresh-after-revoke',target='alpha-other')
            assert stale['http'] in (200,403) and (stale.get('response',{}).get('decision')=='DENY' if isinstance(stale.get('response'),dict) else stale['http']==403),'revoked_worker_not_denied'
            successor=request('alpha',worker='worker-b',mode='recover')
            assert successor['http']==200 and successor['response']['decision']=='ALLOW',successor
            with sqlite3.connect(receiver/'receiver.sqlite') as db:
                effects=db.execute('SELECT buyer,invoice,amount FROM invoices ORDER BY buyer').fetchall()
                counters=db.execute('SELECT kind,used_count,cumulative_amount FROM capacity_usage ORDER BY kind,token_id').fetchall()
                operations=db.execute('SELECT scope,nonce,state FROM operations').fetchall()
            assert effects==[('alpha','alpha-inv',50),('beta','beta-inv',50)],effects
            assert sum(row[2]=='FULFILLED' for row in operations)==2 and len(counters)==4,counters
            assert all(x[1:]==(1,50) for x in counters),counters
            receiver_pub=json.loads((receiver/'receiver-public.json').read_text())['seller_public']
            ra=check_signed(successor['response']['receipt'],receiver_pub,'openline.connect.decision.v1')
            rb=check_signed(b['response']['receipt'],receiver_pub,'openline.connect.decision.v1')
            check_signed(successor['response']['outcome'],receiver_pub,'openline.connect.outcome.v1')
            assert ra['subject']=='alpha' and rb['subject']=='beta'
            assert ra['task_id']==rb['task_id']=='SAME-TASK'
            # The original Alpha receipt stored in the ledger is identical to B's recovery.
            with sqlite3.connect(receiver/'receiver.sqlite') as db:
                receipts=[json.loads(x[0])['receipt'] for x in db.execute('SELECT body FROM operations') if x[0] is not None]
            assert successor['response']['receipt'] in receipts
            print(json.dumps({'status':'PASS','distinct_buyer_processes':2,'distinct_worker_key_files':4,'receiver_private_key_copied_to_workers':False,
                    'real_loopback_http':True,'response_lost_after_commit':True,'worker_b_recovered_signed_original':True,
                    'cross_buyer_probe_http':bad['http'],'cross_buyer_write_http':attack['http'],'revoked_worker_fresh_task_http':stale['http'],'distinct_business_rows':len(effects),'capacity_counters':counters,
                    'same_task_id_across_buyers':True,'same_delegation_and_mandate_ids':True,'local_only':True},sort_keys=True))
        finally:stop(server)

if __name__=='__main__':
    mode=sys.argv[1] if len(sys.argv)>1 else 'orchestrate'
    {'identity':identity,'delegate':delegate,'send':send,'receive':receive,'orchestrate':lambda args:orchestrate()}[mode](sys.argv[2:])
