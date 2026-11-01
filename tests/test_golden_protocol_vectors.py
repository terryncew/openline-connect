"""Independent Golden JWS verification; no internal OpenLine engine imports."""
import base64,hashlib,importlib.util,json,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
ROOT=Path(__file__).resolve().parents[1]

def canonical(v):
    return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def decode(part):
    if not part or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in part):
        raise ValueError('bad_base64url')
    value=base64.urlsafe_b64decode(part+'='*(-len(part)%4))
    if base64.urlsafe_b64encode(value).decode().rstrip('=')!=part:raise ValueError('noncanonical_base64url')
    return value
def verify(token,key,kind):
    h,p,s=token.split('.')
    header=json.loads(decode(h));body=json.loads(decode(p))
    if (header.get('alg')!='EdDSA' or header.get('typ')!='JWT' or
        header.get('kid') is None or type(body) is not dict or body.get('kind')!=kind or
        canonical(header)!=decode(h) or canonical(body)!=decode(p)):
        raise ValueError('bad_canonical_claim')
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(decode(s),(h+'.'+p).encode())
    return body

class GoldenVectors(unittest.TestCase):
    def test_independent_accept_and_connect_delegation(self):
        fixture=json.loads((ROOT/'docs/GOLDEN_PROTOCOL_VECTORS.json').read_text())
        a=fixture['accept_v1']
        decision=verify(a['receipt'],a['seller_public'],'seller_decision')
        outcome=verify(a['outcome'],a['seller_public'],'seller_outcome')
        self.assertEqual(decision['buyer'],a['buyer'])
        self.assertEqual(outcome['po'],a['po'])
        self.assertEqual(decision['order_hash'],a['request_sha256'])
        self.assertEqual(outcome['request_sha256'],a['request_sha256'])
        self.assertEqual(outcome['decision_sha256'],hashlib.sha256(canonical(a['receipt'])).hexdigest())
        spec=importlib.util.spec_from_file_location('independent_accept',
                                ROOT/'examples/independent_accept_verifier.py')
        other=importlib.util.module_from_spec(spec);spec.loader.exec_module(other)
        self.assertTrue(other.verify_pair(receipt=a['receipt'],outcome=a['outcome'],
             seller_pub=a['seller_public'],buyer=a['buyer'],po=a['po'],
             request_sha256=a['request_sha256'])['verified'])
        with self.assertRaises(ValueError):
            other.verify_pair(receipt=a['receipt'],outcome=a['outcome'],
             seller_pub=a['seller_public'],buyer='altered',po=a['po'],
             request_sha256=a['request_sha256'])
        c=fixture['connect_task_v1']; principal,worker=c['delegation_chain'].split(':')
        buyer=verify(principal,c['buyer_public'],'openline.connect.delegation.v1')
        mandate=verify(worker,c['worker_public'],'openline.connect.mandate.v1')
        self.assertEqual(buyer['task_id'],mandate['task_id'])
        self.assertEqual(buyer['parameters_sha256'],mandate['parameters_sha256'])
        self.assertEqual(buyer['parameters_sha256'],hashlib.sha256(canonical(c['params'])).hexdigest())
        with self.assertRaises(Exception):
            verify(principal,c['worker_public'],'openline.connect.delegation.v1')
        broken=a['receipt'][:-1]+('A' if a['receipt'][-1]!='A' else 'B')
        with self.assertRaises(Exception):
            verify(broken,a['seller_public'],'seller_decision')

if __name__=='__main__':unittest.main()
