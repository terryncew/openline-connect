"""Independent minimal conventional Ed25519 + SQLite exact-policy baseline.

No OpenLine imports. Not a production general-purpose authorization library.
"""
import hashlib
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

def sha(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

class ConventionalReceiver:
    def __init__(self, database):
        self.database = database
        self.receiver = Ed25519PrivateKey.generate()
        self.buyer = Ed25519PrivateKey.generate()
        self.policy = {'subject':'fictional-buyer', 'action':'record.update',
                       'parameters_sha256':sha({'target':'customer-1','value':'approved','amount_cents':100}),
                       'expires_at':int(time.time())+600}
        self.policy_signature = self.receiver.sign(canonical(self.policy))
        with sqlite3.connect(self.database) as db:
            db.execute('CREATE TABLE records (target TEXT PRIMARY KEY, value TEXT)')
            db.execute('CREATE TABLE seen (nonce TEXT PRIMARY KEY, sha TEXT NOT NULL)')
            db.execute('CREATE TABLE revoked_grants (id TEXT PRIMARY KEY)')

    def request(self, params, nonce):
        request = {'subject':'fictional-buyer', 'action':'record.update',
                   'params':params, 'nonce':nonce}
        return request, self.buyer.sign(canonical(request))

    def execute(self, request, buyer_signature):
        with sqlite3.connect(self.database, isolation_level=None) as db:
            db.execute('BEGIN IMMEDIATE')
            self.receiver.public_key().verify(self.policy_signature, canonical(self.policy))
            self.buyer.public_key().verify(buyer_signature, canonical(request))
            p = request['params']
            if (request['action'] != self.policy['action'] or
                request['subject'] != self.policy['subject'] or
                sha(p) != self.policy['parameters_sha256'] or
                int(time.time()) >= self.policy['expires_at'] or
                db.execute('SELECT 1 FROM revoked_grants WHERE id=?',('receiver-1',)).fetchone()):
                db.commit()
                return 'DENY'
            existing=db.execute('SELECT sha FROM seen WHERE nonce=?',(request['nonce'],)).fetchone()
            if existing:
                db.commit()
                return 'REPLAY' if existing[0] == sha(request) else 'CONFLICT'
            db.execute('INSERT INTO seen VALUES(?,?)',(request['nonce'],sha(request)))
            db.execute('INSERT OR REPLACE INTO records VALUES(?,?)',(p['target'],p['value']))
            db.commit()
            return 'ALLOW'

    def revoke_grant(self):
        with sqlite3.connect(self.database) as db:
            db.execute('INSERT INTO revoked_grants VALUES(?)',('receiver-1',))

    def effect(self):
        with sqlite3.connect(self.database) as db:
            return db.execute('SELECT target,value FROM records ORDER BY target').fetchall()

class ConventionalParityTests(unittest.TestCase):
    def test_valid_mandate_cannot_override_receiver_exact_policy(self):
        with tempfile.TemporaryDirectory() as d:
            receiver=ConventionalReceiver(str(Path(d)/'baseline.sqlite'))
            wrong={'target':'customer-1','value':'not-approved','amount_cents':100}
            request,sig=receiver.request(wrong,'different-signed-buyer-token')
            self.assertEqual(receiver.execute(request,sig),'DENY')
            self.assertEqual(receiver.effect(),[])
            correct={'target':'customer-1','value':'approved','amount_cents':100}
            request,sig=receiver.request(correct,'correct')
            self.assertEqual(receiver.execute(request,sig),'ALLOW')
            self.assertEqual(receiver.execute(request,sig),'REPLAY')
            self.assertEqual(receiver.effect(),[('customer-1','approved')])
            amount={**correct,'amount_cents':99}
            request2,sig2=receiver.request(amount,'amount-below-ceiling')
            self.assertEqual(receiver.execute(request2,sig2),'DENY')
            receiver.revoke_grant()
            request3,sig3=receiver.request(correct,'after-revocation')
            self.assertEqual(receiver.execute(request3,sig3),'DENY')
            self.assertEqual(receiver.effect(),[('customer-1','approved')])

if __name__ == '__main__':
    unittest.main()
