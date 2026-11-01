"""Competent conventional comparison: Ed25519 + SQLite + scope/epoch/replay.

Purely fictional ticket assignment. Built by the *same* author as the OpenLine example;
this is not an independently measured developer race or a standard-library benchmark.
"""
import base64
import hashlib
import json
import secrets
import sqlite3
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(encoded):
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if b64(raw) != encoded:
        raise ValueError("noncanonical_base64")
    return raw


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign(body, key):
    header = b64(canonical({"alg": "EdDSA", "typ": "JWT"}))
    message = header + "." + b64(canonical(body))
    return message + "." + b64(key.sign(message.encode()))


def verify(token, public_bytes):
    header, body, signature = token.split(".")
    if json.loads(unb64(header)) != {"alg": "EdDSA", "typ": "JWT"}:
        raise ValueError("header")
    Ed25519PublicKey.from_public_bytes(public_bytes).verify(unb64(signature), (header + "." + body).encode())
    claim = json.loads(unb64(body))
    if canonical(claim) != unb64(body):
        raise ValueError("noncanonical")
    return claim


class Receiver:
    def __init__(self, db_path, owner_public, receipt_key):
        self.path = db_path
        self.owner_public = owner_public
        self.receipt_key = receipt_key
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE state(epoch INTEGER NOT NULL)")
            db.execute("INSERT INTO state VALUES(1)")
            db.execute("CREATE TABLE tickets(id TEXT PRIMARY KEY,assignee TEXT NOT NULL,receipt TEXT NOT NULL)")

    def execute(self, *, permit, proof, action, ticket, assignee, recover=False):
        owner = verify(permit, self.owner_public)
        # Full compact-JWS verification with pinned, owner-delegated worker public key.
        signed_worker = verify(proof, bytes.fromhex(owner["worker_public"]))
        now = int(time.time())
        if (owner["receiver"] != "tickets-owner-1" or owner["action"] != "tickets.assign" or
            owner["ticket"] != ticket or owner["assignee"] != assignee or action != owner["action"] or
            signed_worker.get("ticket") != ticket or signed_worker.get("assignee") != assignee or
            signed_worker.get("epoch") != owner["epoch"] or not owner["nbf"] <= now < owner["exp"] or
            signed_worker.get("exp", 0) <= now):
            raise ValueError("scope_or_expiry_denied")
        with sqlite3.connect(self.path, timeout=10, isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            epoch = db.execute("SELECT epoch FROM state").fetchone()[0]
            if epoch != owner["epoch"]:
                raise ValueError("revoked_worker_epoch")
            existing = db.execute("SELECT assignee,receipt FROM tickets WHERE id=?", (ticket,)).fetchone()
            if existing:
                if existing[0] != assignee:
                    raise ValueError("conflicting_replay")
                return {"receipt": existing[1], "replayed": True}
            if recover:
                raise ValueError("unknown_result")
            receipt = sign({"kind": "local_ticket_commit", "ticket": ticket, "assignee": assignee,
                            "receiver": "tickets-owner-1", "epoch": epoch}, self.receipt_key)
            db.execute("INSERT INTO tickets VALUES(?,?,?)", (ticket, assignee, receipt))
            return {"receipt": receipt, "replayed": False}

    def replace_worker(self):
        with sqlite3.connect(self.path, isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE state SET epoch=epoch+1")


def run():
    with tempfile.TemporaryDirectory(prefix="conventional-tickets-") as temporary:
        owner = Ed25519PrivateKey.generate()
        a = Ed25519PrivateKey.generate()
        b = Ed25519PrivateKey.generate()
        receiver = Receiver(str(Path(temporary) / "tickets.sqlite"), public(owner), Ed25519PrivateKey.generate())
        def grant(key, epoch):
            t = int(time.time())
            permit = sign({"receiver": "tickets-owner-1", "action": "tickets.assign",
                           "ticket": "CASE-17", "assignee": "queue-b", "worker_public": public(key).hex(),
                           "epoch": epoch, "nbf": t - 1, "exp": t + 300}, owner)
            proof = sign({"ticket": "CASE-17", "assignee": "queue-b", "epoch": epoch, "exp": t + 300}, key)
            return permit, proof
        original = grant(a, 1)
        first = receiver.execute(permit=original[0], proof=original[1], action="tickets.assign",
                                 ticket="CASE-17", assignee="queue-b")
        receiver.replace_worker()
        try:
            receiver.execute(permit=original[0], proof=original[1], action="tickets.assign",
                             ticket="CASE-17", assignee="queue-b")
            raise AssertionError("revoked_worker_accepted")
        except ValueError:
            pass
        successor = grant(b, 2)
        again = receiver.execute(permit=successor[0], proof=successor[1], action="tickets.assign",
                                 ticket="CASE-17", assignee="queue-b", recover=True)
        assert first["receipt"] == again["receipt"] and again["replayed"]
        return {"status": "PASS", "revoked_worker_denied": True, "successor_recovers_original": True,
                "committed_rows": 1, "scope": "fictional SQLite transactional effect"}


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
