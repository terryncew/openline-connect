"""Shared *wire primitives*, no authorization or robot policy decisions."""
import base64,hashlib,json,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def canon(x): return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def sha(x): return hashlib.sha256(x if isinstance(x,bytes) else canon(x)).hexdigest()
def b64(x): return base64.urlsafe_b64encode(x).rstrip(b'=').decode()
def unb64(x): return base64.urlsafe_b64decode(x+'='*(-len(x)%4))
def keys():
 k=Ed25519PrivateKey.generate();return (k.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex(),k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex())
def public(secret): return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret)).public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
def sign(claims,seed,kid):
 h=b64(canon({'alg':'EdDSA','typ':'JWT','kid':kid}));p=b64(canon(claims));m=f'{h}.{p}'.encode();s=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).sign(m);return f'{h}.{p}.{b64(s)}'
def verify(token,pub,kid,kind=None):
 if type(token) is not str or len(token.split('.'))!=3:raise ValueError('BAD_JWS')
 h,p,s=token.split('.');header=json.loads(unb64(h));body=json.loads(unb64(p))
 if header!={'alg':'EdDSA','typ':'JWT','kid':kid} or (kind and body.get('kind')!=kind) or canon(header)!=unb64(h) or canon(body)!=unb64(p):raise ValueError('BAD_JWS_PROFILE')
 Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(unb64(s),f'{h}.{p}'.encode());return body
def read(path):
 with open(path,encoding='utf-8') as file:return json.load(file)
def write(path,data):
 from pathlib import Path
 p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(canon(data)+b'\n')
def now():return int(time.time())
