"""Two JOSE stacks. OpenLine uses the installed package; comparator is independent.
The federation policy profile is deliberately implementation-neutral.
"""
import base64
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat,PrivateFormat,NoEncryption
from cryptography.exceptions import InvalidSignature


def canonical(o):
    return json.dumps(o,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def sha(o):
    return hashlib.sha256(canonical(o)).hexdigest()


def b64(s):
    return base64.urlsafe_b64encode(s).decode().rstrip('=')


def unb64(s):
    if not isinstance(s,str) or not s or not all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in s):
        raise ValueError('invalid_base64url')
    v=base64.urlsafe_b64decode(s+'='*(-len(s)%4))
    if b64(v)!=s:raise ValueError('noncanonical_base64url')
    return v


def public(seed):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()


def newkey():
    return Ed25519PrivateKey.generate().private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()).hex()


def sign(body,seed,kid,arm):
    if arm=='connect':
        from ._openline_wire import sign as ol_sign, private
        return ol_sign(body,private(seed),kid)
    h=b64(canonical({'alg':'EdDSA','typ':'JWT','kid':kid}))
    p=b64(canonical(body))
    msg=h+'.'+p
    sig=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).sign(msg.encode('ascii'))
    return msg+'.'+b64(sig)


def verify(token,keys,kind,arm):
    if arm=='connect':
        from ._openline_wire import verify as ol_verify
        return ol_verify(token,keys,kind=kind)
    if not isinstance(token,str) or len(token)>262144:raise ValueError('missing_or_large_token')
    try:
        x,y,z=token.split('.')
        header=json.loads(unb64(x))
        if header.keys()!={'alg','typ','kid'} or header['alg']!='EdDSA' or header['typ']!='JWT':raise ValueError('bad_header')
        kid=header['kid'];k=keys[kid]
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(k)).verify(unb64(z),(x+'.'+y).encode('ascii'))
        payload=json.loads(unb64(y))
        if not isinstance(payload,dict) or payload.get('v')!=1 or payload.get('kind')!=kind:raise ValueError('kind')
        # Bound size/canonical equality prevents duplicate-key ambiguities.
        if canonical(header)!=unb64(x) or canonical(payload)!=unb64(y):raise ValueError('noncanonical')
        return payload
    except (InvalidSignature,KeyError,TypeError,UnicodeError,AttributeError,AssertionError) as e:
        raise ValueError('untrusted_signature_or_shape') from e
