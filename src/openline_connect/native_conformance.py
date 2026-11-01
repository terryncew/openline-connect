"""Installed, supplier-initiated controller-admission conformance (FICTIONAL SQLite only).

Implements PR121's key negative-control lesson: the verifier observes a controller
owned by the runner rather than trusting supplier-signed outcomes/SQLite rows.
This is an experimental `native-conformance.v1`, not an industry standard.
"""
from __future__ import annotations
import argparse,hashlib,json,os,secrets,shlex,socket,sqlite3,subprocess,sys,tempfile,time,urllib.request,urllib.error
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from pathlib import Path
from .signing import sign,verify,digest,pub

def post(url, body, admin=None):
    data=json.dumps(body,sort_keys=True,separators=(',',':')).encode()
    req=urllib.request.Request(url, data, {'Content-Type':'application/json',**({'X-Runner-Admin':admin} if admin else {})},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=3) as r:return json.loads(r.read())
    except urllib.error.HTTPError as e:return {'error':json.loads(e.read()).get('error','http_failure'),'http_status':e.code}

def read(url):
    with urllib.request.urlopen(url,timeout=3) as r:return json.loads(r.read())

class Controller:
    def __init__(self, cfg):
        self.db=cfg['db'];self.seed=cfg['controller_seed'];self.owner_pub=cfg['owner_pub'];self.receiver=cfg['receiver'];self.admin=cfg['admin']
        with sqlite3.connect(self.db) as db:
            db.execute('CREATE TABLE IF NOT EXISTS effects(id TEXT PRIMARY KEY,units INTEGER,action TEXT,target TEXT,context TEXT,original_worker TEXT,receipt TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS control(epoch INTEGER NOT NULL,context TEXT NOT NULL)')
            if db.execute('SELECT COUNT(*) FROM control').fetchone()[0]==0:db.execute('INSERT INTO control VALUES(1,?)',(cfg['context'],))
            db.execute('CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY AUTOINCREMENT,effect_id TEXT,result TEXT)')
    def state(self):
        with sqlite3.connect(self.db) as db:
            e,c=db.execute('SELECT epoch,context FROM control').fetchone()
            return {'epoch':e,'context':c,'receiver':self.receiver,'controller_public':pub(self.seed)}
    def admin_update(self,op,arg):
        with sqlite3.connect(self.db) as db:
            if op=='epoch':db.execute('UPDATE control SET epoch=?',(arg,))
            elif op=='context':db.execute('UPDATE control SET context=?',(arg,))
            else:raise ValueError('unknown_operator_command')
    def admission(self,obj):
        now=int(time.time());p=obj['permit'];req=obj['request'];effect=req.get('effect_id','')
        with sqlite3.connect(self.db,timeout=10,isolation_level=None) as db:
            db.execute('BEGIN IMMEDIATE')
            def reject(reason):
                db.execute('INSERT INTO attempts(effect_id,result) VALUES(?,?)',(effect,reason));db.commit();return {'error':reason}
            try:
                auth=verify(p,{'owner':self.owner_pub},kind='openline.conformance.permit.v1')
                worker=verify(req['worker_jws'],{'worker':auth['worker_public']},kind='openline.conformance.worker.v1')
            except (ValueError,KeyError,TypeError):return reject('invalid_signed_authority')
            epoch,context=db.execute('SELECT epoch,context FROM control').fetchone()
            if (auth.get('receiver')!=self.receiver or auth.get('action')!='fictional.procurement.commit' or
                auth.get('target')!='supplier-order' or auth.get('epoch')!=epoch or
                auth.get('worker_public')!=worker.get('worker_public')):return reject('authority_or_worker_epoch_mismatch')
            if (type(auth.get('nbf')) is not int or type(auth.get('exp')) is not int or
                not auth['nbf']<=now<auth['exp'] or type(worker.get('exp')) is not int or now>=worker['exp']):
                return reject('authorization_expired')
            if (type(req.get('units')) is not int or not 1<=req['units']<=20 or
                type(auth.get('max_units')) is not int or auth['max_units']!=20 or
                req.get('target')!=auth.get('target') or worker.get('effect_id')!=effect or
                worker.get('units')!=req.get('units') or worker.get('target')!=req.get('target') or
                type(effect) is not str or not 1<=len(effect)<=100):return reject('signed_task_scope_mismatch')
            old=db.execute('SELECT units,action,target,context,receipt FROM effects WHERE id=?',(effect,)).fetchone()
            if old:
                if old[0]!=req['units'] or old[2]!=req['target']:return reject('conflicting_effect_id')
                db.commit();return {'admitted':True,'replayed':True,'controller_receipt':old[4]}
            if obj.get('recover_only'):return reject('unknown_effect')
            if auth.get('context')!=context:return reject('stale_approved_context')
            total=db.execute('SELECT COALESCE(SUM(units),0) FROM effects').fetchone()[0]
            if total+req['units']>auth['max_units']:return reject('cumulative_units_exceeded')
            body={'kind':'openline.conformance.controller.v1','receiver':self.receiver,'effect_id':effect,
                  'units':req['units'],'action':auth['action'],'target':auth['target'],'context':context,
                  'worker_public':auth['worker_public'],'epoch':epoch,'at':now}
            signed=sign(body,self.seed,'controller')
            db.execute('INSERT INTO effects VALUES(?,?,?,?,?,?,?)',(effect,req['units'],auth['action'],auth['target'],context,auth['worker_public'],signed))
            db.execute('INSERT INTO attempts(effect_id,result) VALUES(?,?)',(effect,'ADMITTED'));db.commit()
            return {'admitted':True,'replayed':False,'controller_receipt':signed}

def serve(config):
    ctl=Controller(json.loads(Path(config).read_text()))
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*a):pass
        def reply(self,code,val):
            blob=json.dumps(val,sort_keys=True).encode()
            self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(blob)));self.end_headers();self.wfile.write(blob)
        def do_GET(self):
            if self.path=='/state':return self.reply(200,ctl.state())
            return self.reply(404,{'error':'unknown_route'})
        def do_POST(self):
            n=int(self.headers.get('Content-Length','0'))
            if not 0<n<65536:return self.reply(413,{'error':'invalid_size'})
            try:payload=json.loads(self.rfile.read(n))
            except Exception:return self.reply(400,{'error':'invalid_json'})
            if self.path=='/admin':
                if not secrets.compare_digest(self.headers.get('X-Runner-Admin',''),ctl.admin):return self.reply(403,{'error':'admin_denied'})
                try:ctl.admin_update(payload['op'],payload['value']);return self.reply(200,{'updated':True})
                except Exception:return self.reply(400,{'error':'bad_update'})
            if self.path=='/admit':
                try:
                    result=ctl.admission(payload);return self.reply(200 if result.get('admitted') else 403,result)
                except Exception:return self.reply(403,{'error':'malformed_admission'})
            return self.reply(404,{'error':'unknown_route'})
    host=ThreadingHTTPServer(('127.0.0.1',int(json.loads(Path(config).read_text())['port'])),Handler)
    try:host.serve_forever()
    finally:host.server_close()

def check_journal(db_path,public_key,expected):
    """Read-only observer independent of supplier-side claimed rows."""
    with sqlite3.connect(f'file:{db_path}?mode=ro',uri=True) as db:
        rows=db.execute('SELECT id,units,action,target,context,original_worker,receipt FROM effects ORDER BY id').fetchall()
    actual={}
    for eid,units,action,target,context,worker,receipt in rows:
        claim=verify(receipt,{'controller':public_key},kind='openline.conformance.controller.v1')
        if (claim.get('effect_id')!=eid or claim.get('units')!=units or claim.get('action')!=action or
            claim.get('target')!=target or claim.get('context')!=context or claim.get('worker_public')!=worker):
            raise ValueError('controller_receipt_journal_mismatch')
        actual[eid]=receipt
    if actual!=expected:raise ValueError('controller_effect_set_mismatch')
    return {'verified':True,'effect_count':len(actual),'total_units':sum(row[1] for row in rows)}

def run(target,output=None):
    start=time.perf_counter();check={};temp=tempfile.TemporaryDirectory(prefix='openline-native-conformance-')
    root=Path(temp.name);owner=secrets.token_hex(32);a=secrets.token_hex(32);b=secrets.token_hex(32);controller=secrets.token_hex(32);admin=secrets.token_urlsafe(24)
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    url=f'http://127.0.0.1:{port}';db=str(root/'controller.sqlite');cfg={'db':db,'owner_pub':pub(owner),'controller_seed':controller,'receiver':'test-supplier','admin':admin,'context':'config-v1','port':port}
    (root/'controller_private.json').write_text(json.dumps(cfg));env=dict(os.environ);env.pop('OPENLINE_CONFORMANCE_OWNER_SEED',None)
    proc=subprocess.Popen([sys.executable,'-m','openline_connect.native_conformance','serve',str(root/'controller_private.json')],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=env)
    try:
        for _ in range(100):
            if proc.poll() is not None:raise RuntimeError('controller_start_failed')
            try:read(url+'/state');break
            except OSError:time.sleep(.04)
        else:raise RuntimeError('controller_start_timeout')
        def permit(worker,epoch=1,context='config-v1',expiry=120):
            now=int(time.time());return sign({'kind':'openline.conformance.permit.v1','receiver':'test-supplier','action':'fictional.procurement.commit','target':'supplier-order',
              'max_units':20,'worker_public':pub(worker),'context':context,'epoch':epoch,'nbf':now-2,'exp':now+expiry},owner,'owner')
        def req(worker,effect='unit-001',units=5,expiry=120):
            now=int(time.time());return {'effect_id':effect,'units':units,'target':'supplier-order',
              'worker_jws':sign({'kind':'openline.conformance.worker.v1','effect_id':effect,'units':units,
                        'target':'supplier-order','worker_public':pub(worker),'exp':now+expiry},worker,'worker')}
        args=shlex.split(target)
        if not args:raise ValueError('empty_adapter_command')
        def invoke(worker,permit_token,request,recover=False,crash=False):
            packet={'permit':permit_token,'request':request,'controller_url':url,'controller_public':pub(controller),'owner_public':pub(owner),
                    'supplier_db':str(root/'supplier.sqlite'),'recover_only':recover,'crash_after_commit':crash}
            return subprocess.run(args,input=json.dumps(packet),text=True,capture_output=True,timeout=10,env=env)
        expected={};p1=permit(a);r1=req(a)
        output1=invoke(a,p1,r1)
        if output1.returncode==0:
            try:
                result=json.loads(output1.stdout);rec=result.get('controller_receipt')
                if rec:verify(rec,{'controller':pub(controller)},kind='openline.conformance.controller.v1')
            except (ValueError,KeyError,TypeError):rec=None
        else:rec=None
        check['valid_supplier_initiated_admission']=rec is not None
        if rec:expected['unit-001']=rec
        check['observer_matching_local_controller']=False
        try:check_journal(db,pub(controller),expected);check['observer_matching_local_controller']=bool(rec)
        except (ValueError,sqlite3.Error):pass
        def remote_attempts():
            with sqlite3.connect(db) as con:return con.execute("SELECT COUNT(*) FROM attempts WHERE result NOT IN ('ADMITTED')").fetchone()[0]
        before_bad=remote_attempts()
        bad=invoke(a,p1,req(a,'bad-evil',units=21))
        check['overcap_refused']=bad.returncode!=0
        bad=invoke(a,p1,req(b,'bad-key'))
        check['wrong_worker_refused']=bad.returncode!=0
        bad=invoke(a,permit(a,expiry=-1),req(a,'bad-exp'))
        check['expiry_refused']=bad.returncode!=0
        # Old epoch worker loses ability even with new signed nonce/JTI.
        post(url+'/admin',{'op':'epoch','value':2},admin)
        bad=invoke(a,p1,req(a,'bad-revoked-fresh-nonce'))
        check['revoked_epoch_refused']=bad.returncode!=0
        p2=permit(b,epoch=2);result=invoke(b,p2,req(b,'unit-001'),recover=True)
        check['successor_recovers_exact_original']=(result.returncode==0 and json.loads(result.stdout).get('controller_receipt')==rec) if rec else False
        result=invoke(b,p2,req(b,'unit-002'),crash=True)
        check['real_subprocess_crash_after_commit']=result.returncode!=0
        # Probe controller state by authoritative receipt, not the supplier's stdout.
        with sqlite3.connect(db) as con:
            row=con.execute("SELECT receipt FROM effects WHERE id='unit-002'").fetchone()
        if row:expected['unit-002']=row[0]
        result=invoke(b,p2,req(b,'unit-002'),recover=True)
        check['unknown_recovery_no_duplicate']=(result.returncode==0 and row is not None and json.loads(result.stdout).get('controller_receipt')==row[0])
        post(url+'/admin',{'op':'context','value':'config-v2'},admin)
        bad=invoke(b,p2,req(b,'bad-stale'))
        check['stale_context_refused']=bad.returncode!=0
        check['reject_before_controller_side_effect_or_attempt']=remote_attempts()==before_bad
        check['final_controller_ledger_match']=False
        try:check_journal(db,pub(controller),expected);check['final_controller_ledger_match']=True
        except (ValueError,sqlite3.Error):pass
        # A sham implementation must NOT pass merely for outputting a JWS and an SQLite row.
        allpass=all(check.values());results={'status':'PASS' if allpass else 'FAIL','checks':check,
            'elapsed_seconds':round(time.perf_counter()-start,3),'limitations':'local controller/journal only; no real external effect, hostile OS isolation or physical claims'}
        if output:Path(output).write_text(json.dumps(results,indent=2))
        return results
    finally:
        proc.terminate()
        try:proc.wait(timeout=3)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
        if proc.stderr:proc.stderr.close()
        temp.cleanup()

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode');parser.add_argument('config',nargs='?');parser.add_argument('--target');parser.add_argument('--output');args=parser.parse_args()
    if args.mode=='serve':serve(args.config)
    elif args.mode=='run':
        result=run(args.target,args.output);print(json.dumps(result,sort_keys=True));sys.exit(0 if result['status']=='PASS' else 1)
