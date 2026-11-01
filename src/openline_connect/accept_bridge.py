"""Public Connect SDK bridge for the real Accept PR#90 `accept.v1` HTTP API.

An explicit, versioned compatibility adapter. It is NOT a claim that `connect.v1`,
`rights.v1`, and `robotics.v1` have one production authority profile.
The buyer and evidence issuers keep their signing keys; the seller pins public keys.
"""
from __future__ import annotations
import json,urllib.request,urllib.error
from .signing import sign,verify,digest,pub

class AcceptClient:
    def __init__(self,base_url,seller_public,*,timeout=3):
        if not isinstance(base_url,str) or not base_url.startswith('http://127.0.0.1:'):
            raise ValueError('loopback_only_this_release')
        self.url=base_url.rstrip('/')
        self.seller_public=seller_public
        self.timeout=timeout
    def request(self,body):
        raw=json.dumps({'version':'accept.v1',**body},sort_keys=True,separators=(',',':')).encode()
        req=urllib.request.Request(self.url+'/v1/orders',raw,{'Content-Type':'application/json'},method='POST')
        try:
            with urllib.request.urlopen(req,timeout=self.timeout) as response:out=json.loads(response.read())
        except urllib.error.HTTPError as e:
            out=json.loads(e.read())
        if 'receipt' not in out or 'outcome' not in out:
            raise ValueError('no_signed_accept_receipt:'+str(out.get('error','unknown')))
        decision=verify(out['receipt'],{'seller':self.seller_public},kind='seller_decision')
        outcome=verify(out['outcome'],{'seller':self.seller_public},kind='seller_outcome')
        expected_hash=digest({'raw':body['order'],'profile':body['profile'],'buyer':body['buyer'],
                              'mandate':body['mandate'],'evidence':body['evidence']})
        if (outcome.get('decision_sha256')!=digest_token(out['receipt']) or
            decision.get('decision')!=out.get('decision') or
            decision.get('order_hash')!=expected_hash or
            outcome.get('request_sha256')!=expected_hash or
            decision.get('buyer')!=body['buyer'] or outcome.get('buyer')!=body['buyer'] or
            decision.get('seller')!='supplier' or outcome.get('seller')!='supplier' or
            decision.get('po')!=out.get('po') or outcome.get('po')!=out.get('po')):
            raise ValueError('receipt_outcome_or_request_mismatch')
        if out.get('decision')=='ACCEPTED' and outcome.get('status')!='LOCAL_COMMIT':
            raise ValueError('missing_local_commit_claim')
        return {**out,'verified_decision':decision,'verified_outcome':outcome}
    def recover_worker(self, *, buyer, po, delegation, worker_proof):
        """No admin credential: seller validates the buyer's exact succession grant."""
        data={'version':'accept.v1','buyer':buyer,'po':po,'delegation':delegation,'worker_proof':worker_proof}
        request=urllib.request.Request(self.url+'/v1/worker-recover',json.dumps(data,sort_keys=True,separators=(',',':')).encode(),
                                       {'Content-Type':'application/json'},method='POST')
        try:
            with urllib.request.urlopen(request,timeout=self.timeout) as res:out=json.loads(res.read())
        except urllib.error.HTTPError as exc:
            raise ValueError('worker_recovery_denied:'+str(json.loads(exc.read()).get('error'))) from exc
        if out.get('recovered') is not True or out.get('buyer')!=buyer or out.get('po')!=po or out.get('effect')!='PRIOR_LOCAL_COMMIT_NO_NEW_EFFECT':
            raise ValueError('invalid_recovery_status')
        decision=verify(out['receipt'],{'seller':self.seller_public},kind='seller_decision')
        outcome=verify(out['outcome'],{'seller':self.seller_public},kind='seller_outcome')
        if (decision.get('buyer')!=buyer or decision.get('po')!=po or decision.get('decision')!='ACCEPTED' or
            outcome.get('decision_sha256')!=digest_token(out['receipt']) or
            outcome.get('status')!='LOCAL_COMMIT' or
            outcome.get('request_sha256')!=decision.get('order_hash')):
            raise ValueError('recovered_receipt_binding_invalid')
        return {**out,'verified_decision':decision,'verified_outcome':outcome}

    def status(self,buyer,po,admin_token):
        from urllib.parse import quote
        path='/v1/orders/'+quote(buyer,safe='')+'/'+quote(po,safe='')
        req=urllib.request.Request(self.url+path,headers={'Authorization':'Bearer '+admin_token})
        with urllib.request.urlopen(req,timeout=self.timeout) as response:return json.loads(response.read())['order']
    def export_verified(self,admin_token):
        req=urllib.request.Request(self.url+'/v1/receipts',headers={'Authorization':'Bearer '+admin_token})
        with urllib.request.urlopen(req,timeout=self.timeout) as response:document=json.loads(response.read())
        for t in document['receipts']:verify(t,{'seller':self.seller_public},kind='seller_decision')
        for t in document['outcomes']:verify(t,{'seller':self.seller_public},kind='seller_outcome')
        return document

def digest_token(token):
    # Accept PR#90 transport.sha() hashes the canonical JSON representation of
    # the JWS string; hashing compact JWS bytes would be incompatible.
    return digest(token)

def agent_order(*,buyer,po,sku,units,unit_cents,terms,buyer_seed,worker_seed,contract_seed,inventory_seed,now,ttl=300):
    """Form an Accept-compliant, independently signed synthetic procurement request.

    `contract_seed` and `inventory_seed` represent external evidence issuers in
    this *fictional* local example, not permissions a buyer would own in practice.
    """
    if type(units) is not int or type(unit_cents) is not int or not 1<=units<=20 or unit_cents<=0:
        raise ValueError('invalid_units_or_price')
    if not all(isinstance(x,str) and x for x in (buyer,po,sku,terms)):
        raise ValueError('buyer_po_sku_terms_required')
    evidence=[]
    for source,seed in [('contract',contract_seed),('inventory',inventory_seed)]:
        evidence.append(sign({'v':1,'kind':'business_evidence','issuer':source,'buyer':buyer,'po':po,
                              'approved':True,'business_version':'1','nbf':now-2,'exp':now+ttl},seed,source))
    mandate=sign({'v':1,'kind':'buyer_mandate','seller':'supplier','buyer':buyer,'po':po,'sku':sku,
                  'profile':'agent_json','max_cents':units*unit_cents,'jti':'buyer-mandate-'+po,
                  'nbf':now-2,'exp':now+ttl,'evidence_hashes':sorted(evidence)},buyer_seed,buyer)
    purchase={'v':1,'profile':'agent_json','buyer':buyer,'seller':'supplier','po':po,'sku':sku,
              'units':units,'unit_cents':unit_cents,'total_cents':units*unit_cents,
              'currency':'USD','terms':terms}
    agent=sign({'v':1,'kind':'agent_purchase','buyer':buyer,'purchase':purchase,
                'mandate_sha':digest_accept_string(mandate)},worker_seed,buyer)
    return {'buyer':buyer,'profile':'agent_json','order':agent,'mandate':mandate,'evidence':evidence}

def digest_accept_string(value):
    """Accept transport.sha() uses JSON canonicalization, including quoted strings."""
    return digest(value)


def make_worker_recovery(*, buyer, po, receiver_id, request_sha256, buyer_seed,
                         worker_seed, worker_public, policy_seq, now, ttl=120, nonce=None):
    """Public wire helper: scoped, short-lived buyer delegation and worker PoP."""
    import secrets
    if not all(type(v) is str and v for v in (buyer,po,receiver_id,request_sha256,worker_public)):
        raise ValueError('invalid_worker_recovery_identity')
    if type(policy_seq) is not int or policy_seq<1 or type(now) is not int or type(ttl) is not int or not 1<=ttl<=600:
        raise ValueError('invalid_worker_recovery_epoch')
    jti=secrets.token_hex(16)
    delegation=sign({'v':1,'kind':'worker_recovery_delegation','buyer':buyer,'po':po,'receiver_id':receiver_id,
                     'request_sha256':request_sha256,'worker_public':worker_public,'policy_seq':policy_seq,
                     'nbf':now-2,'exp':now+ttl,'jti':jti},buyer_seed,buyer)
    worker_proof=sign({'v':1,'kind':'worker_recovery_proof','buyer':buyer,'po':po,'receiver_id':receiver_id,
                       'worker_public':worker_public,'delegation_sha256':digest_accept_string(delegation),
                       'nonce':nonce or secrets.token_hex(16),'nbf':now-2,'exp':now+ttl,
                       'jti':secrets.token_hex(16)},worker_seed,buyer)
    return {'buyer':buyer,'po':po,'delegation':delegation,'worker_proof':worker_proof}
