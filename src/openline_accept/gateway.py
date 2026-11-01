"""Loopback-only local evaluation gateway. Not an enterprise perimeter or OAuth service."""
import hmac, json, ipaddress, re
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote
from .engine import Seller

LIMIT=262144
VERSION='accept.v1'

def strict_json(raw):
    def pairs(ls):
        x={}
        for k,v in ls:
            if k in x:raise ValueError('duplicate_json_key')
            x[k]=v
        return x
    return json.loads(raw,object_pairs_hook=pairs)

def make_handler(seller,admin_token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,fmt,*args): pass
        def _reply(self,status,obj):
            raw=json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
            self.send_response(status)
            self.send_header('Content-Type','application/json')
            self.send_header('Cache-Control','no-store')
            self.send_header('Content-Length',str(len(raw)))
            self.end_headers();self.wfile.write(raw)
        def _admin(self):
            value=self.headers.get('Authorization','')
            return hmac.compare_digest(value,'Bearer '+admin_token)
        def do_GET(self):
            if self.path=='/v1/healthz':return self._reply(200,{'version':VERSION,'status':'ok','scope':'local-evaluation'})
            if self.path=='/v1/seller-key':return self._reply(200,{'version':VERSION,'seller_public':seller.trust['seller_public'],'arm':seller.arm})
            if not self._admin():return self._reply(401,{'error':'admin_auth_required'})
            if self.path=='/v1/receipts':return self._reply(200,{'version':VERSION,'arm':seller.arm,'seller_public':seller.trust['seller_public'],'receipts':seller.export_receipts(),'outcomes':seller.export_outcomes()})
            m=re.fullmatch(r'/v1/orders/([A-Za-z0-9_-]{1,100})/([A-Za-z0-9_-]{1,120})',self.path)
            if m:
                state=seller.reconcile(unquote(m[2]),buyer=unquote(m[1]))
                return self._reply(200 if state else 404,{'version':VERSION,'order':state})
            return self._reply(404,{'error':'unknown_endpoint'})
        def do_POST(self):
            if self.path=='/v1/worker-recover':
                if self.headers.get('Content-Type','').split(';')[0].strip()!='application/json':
                    return self._reply(415,{'error':'json_required'})
                try:size=int(self.headers.get('Content-Length','-1'))
                except ValueError:size=-1
                if size<0 or size>LIMIT:return self._reply(413,{'error':'body_limit'})
                try:
                    v=strict_json(self.rfile.read(size))
                    if type(v) is not dict or v.get('version')!=VERSION or set(v)!={'version','buyer','po','delegation','worker_proof'}:
                        raise ValueError('recovery_wire_shape')
                    result=seller.recover_worker({k:v[k] for k in ('buyer','po','delegation','worker_proof')})
                    return self._reply(200,result)
                except (ValueError,KeyError,TypeError,IndexError):return self._reply(400,{'error':'invalid_request'})
                except Exception as e:
                    from .engine import Rejected
                    if isinstance(e,Rejected):return self._reply(403 if e.status=='REFUSED' else 409,{'error':e.reason})
                    return self._reply(500,{'error':'reconciliation_failed_no_new_effect'})
            cancel=re.fullmatch(r'/v1/orders/([A-Za-z0-9_-]{1,100})/([A-Za-z0-9_-]{1,120})/cancel',self.path)
            if cancel:
                if not self._admin():return self._reply(401,{'error':'admin_auth_required'})
                try:
                    change=seller.cancel(cancel[2],buyer=cancel[1])
                    return self._reply(200,{'version':VERSION,'status':'LOCAL_CANCELLED','change':change})
                except ValueError:return self._reply(409,{'error':'unknown_or_already_cancelled'})
            if self.path!='/v1/orders':return self._reply(404,{'error':'unknown_endpoint'})
            if self.headers.get('Content-Type','').split(';')[0].strip()!='application/json':
                return self._reply(415,{'error':'json_required'})
            try:size=int(self.headers.get('Content-Length','-1'))
            except ValueError:size=-1
            if size<0 or size>LIMIT:return self._reply(413,{'error':'body_limit'})
            try:
                v=strict_json(self.rfile.read(size))
                if type(v) is not dict or set(v)!={'version','buyer','profile','order','mandate','evidence'}:raise ValueError('request_schema')
                if v['version']!=VERSION: return self._reply(400,{'error':'unsupported_version'})
                result=seller.submit({k:v[k] for k in ('buyer','profile','order','mandate','evidence')})
                code={'ACCEPTED':200,'REPLAY_SAME':200,'REFUSED':403,'INDETERMINATE':409}.get(result['decision'],500)
                return self._reply(code,{'version':VERSION,**result})
            except (ValueError,KeyError,TypeError,IndexError):return self._reply(400,{'error':'invalid_request'})
            except Exception:
                # Local operator logs required; never leak internal DB/key errors to clients.
                return self._reply(500,{'error':'internal_failure_no_commit_guarantee_reconcile_required'})
    return Handler

def serve(seller,admin_token,host='127.0.0.1',port=8765):
    if not ipaddress.ip_address(host).is_loopback:raise ValueError('No non-loopback binding permitted in private v0.1')
    httpd=ThreadingHTTPServer((host,port),make_handler(seller,admin_token))
    try:httpd.serve_forever(poll_interval=.1)
    finally:httpd.server_close()
