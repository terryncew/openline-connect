"""Independent fixture receiver: no OpenLine engine, solely JWS primitives and its own SQLite."""
import json,sqlite3,sys,urllib.request,urllib.error,time
from .signing import verify
def read(url):
    with urllib.request.urlopen(url,timeout=3) as response:return json.loads(response.read())

def post(url,body):
    req=urllib.request.Request(url,json.dumps(body,sort_keys=True,separators=(',',':')).encode(),
                               {'Content-Type':'application/json'},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=3) as response:return json.loads(response.read())
    except urllib.error.HTTPError as exc:return {'error':json.loads(exc.read()).get('error','http_error')}


def main():
    packet=json.loads(sys.stdin.read())
    state=read(packet['controller_url']+'/state')
    # A receiver makes its own pre-admission choice; harness does NOT invoke effects.
    try:
        body=verify(packet['permit'],{'owner':packet['owner_public']},kind='openline.conformance.permit.v1')
        w=verify(packet['request']['worker_jws'],{'worker':body['worker_public']},kind='openline.conformance.worker.v1')
        if w.get('effect_id')!=packet['request'].get('effect_id') or w.get('units')!=packet['request'].get('units') or w.get('target')!=packet['request'].get('target'):
            raise ValueError('local_worker_scope')
        if (type(packet['request']['units']) is not int or not 1<=packet['request']['units']<=20 or
           body.get('receiver')!=state['receiver'] or body.get('epoch')!=state['epoch'] or
           (not packet.get('recover_only') and body.get('context')!=state['context']) or
           not body.get('nbf',0)<=int(time.time())<body.get('exp',0) or
           type(w.get('exp')) is not int or int(time.time())>=w['exp']):
            raise ValueError('local_receiver_policy')
    except Exception as e:sys.exit(3)
    res=post(packet['controller_url']+'/admit',{'permit':packet['permit'],'request':packet['request'],'recover_only':packet.get('recover_only',False)})
    if not res.get('admitted'):sys.exit(4)
    verify(res['controller_receipt'],{'controller':packet['controller_public']},kind='openline.conformance.controller.v1')
    # Own supplier SQLite state, distinct from underlying controller journal.
    with sqlite3.connect(packet['supplier_db']) as db:
        db.execute('CREATE TABLE IF NOT EXISTS effects(effect_id TEXT PRIMARY KEY, controller_receipt TEXT NOT NULL)')
        db.execute('INSERT OR IGNORE INTO effects VALUES (?,?)',(packet['request']['effect_id'],res['controller_receipt']))
    if packet.get('crash_after_commit'):sys.exit(79)
    print(json.dumps(res))
if __name__=='__main__':main()
