"""Independent Accept v1 signed-outcome verifier (NO openline_* imports).

The caller must pin the seller's Ed25519 public key from an independent channel.
Checks cryptographic authenticity, order/buyer binding, and claimed local outcome;
it cannot establish external effects or true controller state.
"""
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def decode_segment(segment):
    if not isinstance(segment,str) or not segment or len(segment)>350000:
        raise ValueError('invalid_segment')
    if any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in segment):
        raise ValueError('invalid_base64url')
    value=base64.urlsafe_b64decode(segment+'='*(-len(segment)%4))
    if base64.urlsafe_b64encode(value).decode().rstrip('=')!=segment:
        raise ValueError('noncanonical_segment')
    return value


def parse_signed(token, *, seller_pub, expected_kind):
    if type(token) is not str or len(token)>262144:
        raise ValueError('bad_jws_size')
    try:
        h,p,s=token.split('.')
        header=json.loads(decode_segment(h)); body=json.loads(decode_segment(p))
        if (header!={'alg':'EdDSA','typ':'JWT','kid':'seller'} or
            type(body) is not dict or body.get('v')!=1 or body.get('kind')!=expected_kind or
            canonical(header)!=decode_segment(h) or canonical(body)!=decode_segment(p)):
            raise ValueError('bad_canonical_jws_or_claim')
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(seller_pub)).verify(decode_segment(s),(h+'.'+p).encode('ascii'))
        return body
    except (KeyError,TypeError,InvalidSignature,UnicodeDecodeError,OverflowError) as exc:
        raise ValueError('invalid_signed_receipt') from exc


def verify_pair(*, receipt, outcome, seller_pub, buyer, po, request_sha256, require_commit=True):
    a=parse_signed(receipt,seller_pub=seller_pub,expected_kind='seller_decision')
    b=parse_signed(outcome,seller_pub=seller_pub,expected_kind='seller_outcome')
    if (a.get('buyer')!=buyer or b.get('buyer')!=buyer or a.get('po')!=po or b.get('po')!=po or
        a.get('seller')!='supplier' or b.get('seller')!='supplier' or
        a.get('order_hash')!=request_sha256 or b.get('request_sha256')!=request_sha256 or
        b.get('decision_sha256')!=sha(receipt)):
        raise ValueError('receipt_outcome_scope_mismatch')
    if require_commit and (a.get('decision')!='ACCEPTED' or b.get('status')!='LOCAL_COMMIT'):
        raise ValueError('claimed_commit_missing')
    return {'verified':True,'buyer':buyer,'po':po,'decision':a['decision'],
            'status':b['status'],'scope':'signed synthetic local outcome claim only'}

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description='Verify pair with an OUT-OF-BAND pinned seller public key')
    p.add_argument('--receipt',required=True);p.add_argument('--outcome',required=True)
    p.add_argument('--seller-pub',required=True);p.add_argument('--buyer',required=True)
    p.add_argument('--po',required=True);p.add_argument('--request-sha256',required=True)
    a=p.parse_args()
    print(json.dumps(verify_pair(receipt=a.receipt,outcome=a.outcome,seller_pub=a.seller_pub,
        buyer=a.buyer,po=a.po,request_sha256=a.request_sha256),sort_keys=True))
