"""Seller-owned offline purchase-order intake, intentionally equal policy in both arms.
Effect boundary is only this SQLite transaction; supplier fulfillment is not proven.
"""
import json, sqlite3, time
from contextlib import closing
from pathlib import Path
from .adapters import read_cxml,read_agent,FormatError
from .transport import sign,verify,sha,public

class Rejected(Exception):
    def __init__(self,status,reason):self.status=status;self.reason=reason

def check(token,keys,kind,arm,reason='signature_or_trust'):
    try:return verify(token,keys,kind,arm)
    except (ValueError,TypeError,KeyError,IndexError,AttributeError,UnicodeError) as e:raise Rejected('REFUSED',reason) from e

class Seller:
    def __init__(self,path,arm,seller_seed,trust,action=None):
        from .business import SqliteLocalAction
        self.action = action if action is not None else SqliteLocalAction()
        self.path=str(path);self.arm=arm;self.seed=seller_seed;self.trust=trust
        if public(seller_seed)!=trust['seller_public']:raise ValueError('seller_key_mismatch')
        Path(path).parent.mkdir(parents=True,exist_ok=True)
        with closing(self.conn()) as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS policy(seq INTEGER PRIMARY KEY,token TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS orders(po TEXT NOT NULL,buyer TEXT NOT NULL,amount INTEGER NOT NULL,sku TEXT NOT NULL,units INTEGER NOT NULL,request_sha TEXT NOT NULL,status TEXT NOT NULL, PRIMARY KEY(buyer,po));
            CREATE TABLE IF NOT EXISTS receipts(seq INTEGER PRIMARY KEY AUTOINCREMENT,po TEXT,token TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS changes(seq INTEGER PRIMARY KEY AUTOINCREMENT,po TEXT,token TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS outcomes(seq INTEGER PRIMARY KEY AUTOINCREMENT,po TEXT,token TEXT NOT NULL);
            ''')
            self.action.install(db)
    def conn(self):
        db=sqlite3.connect(self.path,timeout=8,isolation_level=None)
        db.execute('PRAGMA busy_timeout=8000')
        return db
    def install(self,token):
        p=check(token,{'seller':self.trust['seller_public']},'policy',self.arm)
        if p.get('seller')!='supplier' or type(p.get('seq')) is not int or p['seq']<1:raise ValueError('invalid_policy')
        with closing(self.conn()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                prev=db.execute('SELECT MAX(seq) FROM policy').fetchone()[0] or 0
                if p['seq']<=prev:raise ValueError('rollback_policy')
                db.execute('INSERT INTO policy VALUES(?,?)',(p['seq'],token));db.commit()
            except BaseException:db.rollback();raise
    def _policy(self,db):
        row=db.execute('SELECT token FROM policy ORDER BY seq DESC LIMIT 1').fetchone()
        if not row:raise Rejected('INDETERMINATE','policy_unavailable')
        return check(row[0],{'seller':self.trust['seller_public']},'policy',self.arm)
    def submit(self,payload,now=None):
        """Atomic seller decision+local order. Caller may lose reply; read-only status by PO available.
        Signed mandate/PO/evidence must be from independent keys pinned by seller policy.
        """
        if now is None: now=int(time.time())
        started=time.perf_counter_ns();p=None;normalized=None;po=None
        raw=payload['order'];profile=payload['profile'];buyer=payload['buyer']
        req_hash=sha({'raw':raw,'profile':profile,'buyer':buyer,'mandate':payload['mandate'],'evidence':payload['evidence']})
        with closing(self.conn()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                try:
                    p=self._policy(db)
                    if now<p['nbf'] or now>=p['exp']:raise Rejected('INDETERMINATE','policy_expired')
                    buyer_cfg=p['buyers'].get(buyer)
                    if not buyer_cfg:raise Rejected('REFUSED','unknown_buyer')
                    if buyer_cfg['profile']!=profile:raise Rejected('REFUSED','unauthorized_profile')
                    mandate=check(payload['mandate'],{buyer:buyer_cfg['public']},'buyer_mandate',self.arm)
                    if mandate['buyer']!=buyer or mandate['seller']!='supplier' or not mandate['nbf']<=now<mandate['exp']:
                        raise Rejected('REFUSED','mandate_scope_or_expiry')
                    if mandate['jti'] in p['revoked']:raise Rejected('REFUSED','revoked_mandate')
                    if profile in ('sap_cxml','coupa_cxml','procurement_cxml'):
                        normalized=read_cxml(raw,expected_profile=('sap_cxml' if profile=='procurement_cxml' else profile),buyer_id=buyer,seller_id='supplier',shared_secret=buyer_cfg['shared_secret'])
                        if profile=='procurement_cxml':normalized['profile']=profile
                    elif profile=='agent_json':
                        agent=check(raw,{buyer:buyer_cfg['provider_public']},'agent_purchase',self.arm)
                        normalized=read_agent(agent['purchase'],buyer_id=buyer,seller_id='supplier')
                        if agent['mandate_sha']!=sha(payload['mandate']):raise Rejected('REFUSED','agent_mandate_binding')
                    else:raise Rejected('REFUSED','unknown_format')
                    po=normalized['po']
                    if (mandate['po']!=po or mandate['max_cents']<normalized['total_cents'] or
                        mandate['sku']!=normalized['sku'] or mandate['profile']!=profile or normalized['terms']!=p['terms']):
                        raise Rejected('REFUSED','mandate_or_terms')
                    if normalized['sku']!=p['sku'] or normalized['unit_cents']!=p['unit_cents'] or normalized['units']>p['max_units']:
                        raise Rejected('REFUSED','seller_price_or_inventory')
                    if sorted(payload['evidence'])!=sorted(mandate['evidence_hashes']):raise Rejected('REFUSED','evidence_binding')
                    if len(payload['evidence'])!=2:raise Rejected('REFUSED','two_sources_required')
                    seen=set()
                    for token in payload['evidence']:
                        # Hint is not authority: try pinned verifier candidates only; bounded 2.
                        matching=[]
                        for issuer,key in p['sources'].items():
                            try:
                                evidence=verify(token,{issuer:key},'business_evidence',self.arm)
                                matching.append(evidence)
                            except (KeyError,ValueError,TypeError):pass
                        if len(matching)!=1:raise Rejected('REFUSED','evidence_signature')
                        e=matching[0];issuer=e['issuer']
                        if issuer in seen or e['buyer']!=buyer or e['po']!=po or not e['nbf']<=now<e['exp']:
                            raise Rejected('INDETERMINATE','stale_or_duplicate_evidence')
                        if not e['approved']:raise Rejected('REFUSED','source_disapproved')
                        seen.add(issuer)
                    if seen!={'contract','inventory'}:raise Rejected('REFUSED','source_coverage')
                    prev=db.execute('SELECT buyer,amount,sku,units,request_sha,status FROM orders WHERE buyer=? AND po=?',(buyer,po)).fetchone()
                    if prev:
                        if prev[4]!=req_hash:raise Rejected('REFUSED','po_conflict')
                        raise Rejected('REPLAY_SAME','reconciled_existing_order')
                    # SQLite is the only effect boundary. No external ERP/delivery.
                    db.execute('INSERT INTO orders VALUES(?,?,?,?,?,?,?)',(po,buyer,normalized['total_cents'],normalized['sku'],normalized['units'],req_hash,'COMMITTED'))
                    self.action.commit(db, normalized)
                    result,reason='ACCEPTED','local_order_committed'
                except FormatError as e:result,reason='REFUSED','format_'+str(e)
                except (KeyError,TypeError,ValueError) as e:result,reason='REFUSED','schema_or_evidence'
                except Rejected as e:result,reason=e.status,e.reason
                if normalized and po:
                    status=db.execute('SELECT status FROM orders WHERE buyer=? AND po=?',(buyer,po)).fetchone()
                    effect=status[0] if status else None
                else:effect=None
                record={'v':1,'kind':'seller_decision','seller':'supplier','buyer':buyer,'po':po,
                        'decision':result,'reason':reason,'order_hash':req_hash,'normalized_hash':sha(normalized),
                        'policy_seq':p['seq'] if p else None,'local_effect':effect,
                        'at':now,'scope':'synthetic_sqlite_order_only_not_ERP_fulfillment'}
                token=sign(record,self.seed,'seller',self.arm)
                outcome_body={'v':1,'kind':'seller_outcome','seller':'supplier','buyer':buyer,
                              'po':po,'decision_sha256':sha(token),'request_sha256':req_hash,
                              'status':('LOCAL_COMMIT' if result=='ACCEPTED' else 'PRIOR_COMMIT_NO_NEW_EFFECT' if result=='REPLAY_SAME' else 'NO_EFFECT'),
                              'local_effect':effect,'at':now,'scope':'synthetic_sqlite_order_only_not_ERP_fulfillment'}
                outcome_token=sign(outcome_body,self.seed,'seller',self.arm)
                db.execute('INSERT INTO receipts(po,token) VALUES(?,?)',(po,token))
                db.execute('INSERT INTO outcomes(po,token) VALUES(?,?)',(po,outcome_token));db.commit()
                return {'decision':result,'reason':reason,'po':po,'receipt':token,'outcome':outcome_token,'latency_us':(time.perf_counter_ns()-started)//1000}
            except BaseException:db.rollback();raise
    def recover_worker(self, payload, now=None):
        """Read-only buyer-authorized successor recovery of an already committed PO.

        The seller pins buyer + currently active worker public keys through its own
        policy; neither the worker nor the buyer obtains an admin token. The
        decision/outcome pair is retrieved from the seller's durable SQLite log.
        """
        if now is None:now=int(time.time())
        if type(payload) is not dict or set(payload)!={'buyer','po','delegation','worker_proof'}:
            raise Rejected('REFUSED','bad_recovery_shape')
        buyer,po=payload['buyer'],payload['po']
        if type(buyer) is not str or type(po) is not str or not (1<=len(buyer)<=100 and 1<=len(po)<=120):
            raise Rejected('REFUSED','bad_recovery_identity')
        with closing(self.conn()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                policy=self._policy(db)
                if not policy['nbf']<=now<policy['exp']:
                    raise Rejected('INDETERMINATE','current_policy_expired')
                cfg=policy.get('buyers',{}).get(buyer)
                if not isinstance(cfg,dict):raise Rejected('REFUSED','unknown_recovery_buyer')
                delegation=check(payload['delegation'],{buyer:cfg['public']},'worker_recovery_delegation',self.arm)
                worker=check(payload['worker_proof'],{buyer:cfg['provider_public']},'worker_recovery_proof',self.arm)
                receiver='supplier'
                common={'buyer':buyer,'po':po,'receiver_id':receiver}
                if any(delegation.get(k)!=v or worker.get(k)!=v for k,v in common.items()):
                    raise Rejected('REFUSED','recovery_scope_mismatch')
                if (delegation.get('worker_public')!=cfg['provider_public'] or
                    worker.get('worker_public')!=cfg['provider_public'] or
                    delegation.get('policy_seq')!=policy['seq'] or
                    type(delegation.get('nbf')) is not int or type(delegation.get('exp')) is not int or
                    not delegation['nbf']<=now<delegation['exp'] or
                    type(worker.get('nbf')) is not int or type(worker.get('exp')) is not int or
                    not worker['nbf']<=now<worker['exp'] or
                    worker.get('delegation_sha256')!=sha(payload['delegation']) or
                    type(worker.get('nonce')) is not str or not (8<=len(worker['nonce'])<=128) or
                    type(delegation.get('request_sha256')) is not str or
                    len(delegation['request_sha256'])!=64):
                    raise Rejected('REFUSED','invalid_recovery_succession')
                if any(j in policy.get('revoked',[]) for j in
                       (delegation.get('jti'),worker.get('jti'),cfg['provider_public'])):
                    raise Rejected('REFUSED','recovery_revoked')
                row=db.execute('SELECT request_sha,status FROM orders WHERE buyer=? AND po=?',(buyer,po)).fetchone()
                if not row:raise Rejected('REFUSED','unknown_recovery_order')
                if row[0]!=delegation['request_sha256'] or row[1]!='COMMITTED':
                    raise Rejected('REFUSED','recovery_order_hash_mismatch')
                # Both arrays append one row per request in the same transaction.
                # Verify the signed original ACCEPTED decision and matching outcome,
                # not later REPLAY_SAME/REFUSED claims that happen to share PO.
                for rec,out in db.execute("SELECT r.token,o.token FROM receipts r JOIN outcomes o ON o.seq=r.seq WHERE r.po=? ORDER BY r.seq",(po,)):
                    dc=check(rec,{'seller':self.trust['seller_public']},'seller_decision',self.arm)
                    oc=check(out,{'seller':self.trust['seller_public']},'seller_outcome',self.arm)
                    if (dc.get('buyer')==buyer and dc.get('po')==po and dc.get('decision')=='ACCEPTED' and
                        dc.get('order_hash')==row[0] and oc.get('decision_sha256')==sha(rec) and
                        oc.get('request_sha256')==row[0] and oc.get('status')=='LOCAL_COMMIT'):
                        db.commit()
                        return {'version':'accept.v1','decision':'ACCEPTED','receipt':rec,'outcome':out,
                                'recovered':True,'po':po,'buyer':buyer,'effect':'PRIOR_LOCAL_COMMIT_NO_NEW_EFFECT'}
                raise Rejected('INDETERMINATE','original_signed_receipt_missing')
            except BaseException:
                if db.in_transaction:db.rollback()
                raise

    def reconcile(self,po,*,buyer):
        with closing(self.conn()) as db:
            row=db.execute('SELECT po,buyer,amount,sku,units,status FROM orders WHERE buyer=? AND po=?',(buyer,po)).fetchone()
            return dict(zip(('po','buyer','amount','sku','units','status'),row)) if row else None
    def cancel(self,po,*,buyer,reason='buyer_request'):
        with closing(self.conn()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                row=db.execute('SELECT status FROM orders WHERE buyer=? AND po=?',(buyer,po)).fetchone()
                if not row:raise ValueError('unknown_order')
                if row[0]=='CANCELLED':raise ValueError('repeat_cancel')
                db.execute('UPDATE orders SET status=? WHERE buyer=? AND po=?',('CANCELLED',buyer,po))
                data={'v':1,'kind':'seller_change','buyer':buyer,'po':po,'new_status':'CANCELLED','reason':reason,'scope':'local_only'}
                token=sign(data,self.seed,'seller',self.arm)
                db.execute('INSERT INTO changes(po,token) VALUES(?,?)',(po,token));db.commit()
                return token
            except BaseException:db.rollback();raise
    def counts(self):
        with closing(self.conn()) as db:
            return {'orders':db.execute('SELECT COUNT(*) FROM orders').fetchone()[0],
                    'decisions':db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0],
                    'changes':db.execute('SELECT COUNT(*) FROM changes').fetchone()[0],
                    'outcomes':db.execute('SELECT COUNT(*) FROM outcomes').fetchone()[0],
                    'business_jobs':db.execute('SELECT COUNT(*) FROM business_jobs').fetchone()[0]}
    def export_receipts(self):
        with closing(self.conn()) as db:return [r[0] for r in db.execute('SELECT token FROM receipts ORDER BY seq')]
    def export_outcomes(self):
        with closing(self.conn()) as db:return [r[0] for r in db.execute('SELECT token FROM outcomes ORDER BY seq')]
    def impact(self,history,old_evidence,new_evidence):
        """Only referenced attested evidence tracked; output is suggested human review."""
        return sorted({h['po'] for h in history if h['evidence_hash']==old_evidence and old_evidence!=new_evidence})
