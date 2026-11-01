"""Offline **real** Accept gateway demonstration, in a separate local process.

This is fictional evaluation, not procurement integration, live money, or a
public standard. It uses installed openline_accept.Seller and `accept.v1`.
"""
from __future__ import annotations
import json,os,secrets,socket,sqlite3,subprocess,sys,tempfile,time,urllib.request
from pathlib import Path
from .signing import pub
from .accept_bridge import AcceptClient,agent_order,make_worker_recovery

def walkthrough(output=None):
    if output is None:
        with tempfile.TemporaryDirectory(prefix='openline-unified-rc001-') as scratch:
            return _run(Path(scratch))
    home=Path(output)
    home.mkdir(parents=True,exist_ok=False)
    os.chmod(home,0o700)
    return _run(home)

def _write_private(path,value):
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as f:
        f.write(value)

def _run(root):
    seed={name:secrets.token_hex(32) for name in ('seller','buyer','worker_a','worker_b','contract','inventory')}
    t=int(time.time());admin=secrets.token_urlsafe(20)
    _write_private(root/'receiver.seed',seed['seller'])
    db=root/'seller.sqlite'
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    def policy(seq,worker):
        return {'v':1,'kind':'policy','seller':'supplier','seq':seq,'nbf':t-60,'exp':t+600,
            'sku':'industrial-filter-17','unit_cents':250000,'max_units':20,
            'terms':'NET30_SYNTHETIC_v1','buyers':{'buyer-01':{'profile':'agent_json',
            'public':pub(seed['buyer']),'provider_public':pub(seed[worker]),
            'shared_secret':'unused-for-agent-json'}},
            'sources':{'contract':pub(seed['contract']),'inventory':pub(seed['inventory'])},'revoked':[]}
    process=None
    def start(seq,worker):
        config={'receiver_key_path':str(root/'receiver.seed'), 'sqlite_path':str(db),
                'admin_token':admin,'port':port,'receiver_policy':policy(seq,worker)}
        path=root/'server-config.json'
        if path.exists():path.unlink()
        _write_private(path,json.dumps(config))
        p=subprocess.Popen([sys.executable,'-m','openline_connect.accept_process','--config',str(path)],
                           stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,cwd=str(root))
        for _ in range(150):
            if p.poll() is not None:
                detail=p.stderr.read().decode(errors='replace')[-500:]
                raise RuntimeError('accept_process_failed:'+detail)
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/v1/healthz',timeout=.2) as r:
                    if json.loads(r.read()).get('version')=='accept.v1':return p
            except (OSError,ValueError):time.sleep(.03)
        raise RuntimeError('accept_process_not_ready')
    def stop(p):
        if p is not None and p.poll() is None:
            p.terminate()
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
        if p is not None and p.stderr:p.stderr.close()
    def order(po,who):
        return agent_order(buyer='buyer-01',po=po,sku='industrial-filter-17',units=2,
            unit_cents=250000,terms='NET30_SYNTHETIC_v1',buyer_seed=seed['buyer'],
            worker_seed=seed[who],contract_seed=seed['contract'],inventory_seed=seed['inventory'],now=t)
    try:
        process=start(1,'worker_a')
        client=AcceptClient(f'http://127.0.0.1:{port}',pub(seed['seller']))
        good=client.request(order('PO-001','worker_a'))
        if good['decision']!='ACCEPTED':raise RuntimeError('initial_admission_failed')
        again=client.request(order('PO-001','worker_a'))
        if again['decision']!='REPLAY_SAME':raise RuntimeError('duplicate_not_idempotent')
        tampered=order('PO-BAD','worker_a');tampered['order']='unsigned'
        refusal=client.request(tampered)
        if refusal['decision']!='REFUSED':raise RuntimeError('unsigned_not_refused')
        # Simulate lost first HTTP result; operator retains a privileged status route.
        recovered=client.status('buyer-01','PO-001',admin)
        if not recovered or recovered['status']!='COMMITTED':raise RuntimeError('reconcile_failed')
        stop(process);process=start(2,'worker_b')
        old=client.request(order('PO-002','worker_a'))
        if old['decision']!='REFUSED':raise RuntimeError('old_worker_accepted')
        recovery_proof=make_worker_recovery(buyer='buyer-01',po='PO-001',receiver_id='supplier',
            request_sha256=good['verified_decision']['order_hash'],buyer_seed=seed['buyer'],
            worker_seed=seed['worker_b'],worker_public=pub(seed['worker_b']),policy_seq=2,now=int(time.time()))
        successor_recovery=client.recover_worker(**recovery_proof)
        if successor_recovery['receipt']!=good['receipt']:raise RuntimeError('recovery_changed_original_signed_receipt')
        successor=client.request(order('PO-003','worker_b'))
        if successor['decision']!='ACCEPTED':raise RuntimeError('successor_rejected')
        verified=client.export_verified(admin)
        with sqlite3.connect(db) as conn:
            total=conn.execute('SELECT COUNT(*) FROM business_jobs').fetchone()[0]
        if total!=2:raise RuntimeError('local_duplicate_effect')
        return {'result':'PASS','wire':'accept.v1','actor':'real PR90 Seller subprocess',
                'receiver_pid_separate':process.pid!=os.getpid(),
                'accepted_A':good['decision'],'replayed':again['decision'],
                'unsigned':refusal['decision'],'revoked_A':old['decision'],
                'accepted_B':successor['decision'],'operator_recovered_state':recovered['status'],
                'worker_scoped_recovered_original':successor_recovery['receipt']==good['receipt'],
                'local_sqlite_effect_rows':total,'verified_signed_decisions':len(verified['receipts']),
                'scope':'FICTIONAL_SQLITE_ONLY_NOT_EXTERNAL_DELIVERY','public_wire_unification':False}
    finally:stop(process)