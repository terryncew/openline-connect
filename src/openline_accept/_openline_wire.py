"""Bounded Ed25519 JWS profile. Adapted from PR79 JWT and PR50 strict JSON.

No algorithm/key discovery, embedded trust roots, floats or arbitrary arguments.
This is an experimental application profile of JWS, not a new authority protocol.
"""
import base64
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

MAX_BYTES = 262144


def canonical(value):
    def visit(x, depth=0):
        if depth > 24:
            raise ValueError("excessive_nesting")
        if type(x) is dict:
            if any(type(k) is not str for k in x):
                raise ValueError("non_string_key")
            for item in x.values():
                visit(item, depth + 1)
        elif type(x) is list:
            for item in x:
                visit(item, depth + 1)
        elif type(x) not in (str, int, bool, type(None)):
            raise ValueError("noncanonical_value")
    visit(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(raw) > MAX_BYTES:
        raise ValueError("oversize")
    return raw


def strict(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError("oversize")
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError("duplicate_key")
            result[k] = v
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    canonical(value)
    return value


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def enc(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def dec(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if enc(raw) != value:
        raise ValueError("noncanonical_base64url")
    return raw


def public(key):
    return key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()


def private(seed_hex):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def sign(body, key, kid):
    protected = enc(canonical({"alg": "EdDSA", "typ": "JWT", "kid": kid}))
    payload = protected + "." + enc(canonical(body))
    return payload + "." + enc(key.sign(payload.encode("ascii")))


def verify(token, keys, *, kind=None):
    if type(token) is not str or len(token) > MAX_BYTES:
        raise ValueError("missing_or_oversize_jws")
    try:
        h, p, s = token.split(".")
        header = strict(dec(h))
        if set(header) != {"alg", "typ", "kid"} or header["alg"] != "EdDSA" or header["typ"] != "JWT":
            raise ValueError("algorithm_or_header")
        key = keys[header["kid"]]
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(dec(s), (h + "." + p).encode("ascii"))
        body = strict(dec(p))
        if type(body) is not dict or body.get("v") != 1 or (kind and body.get("kind") != kind):
            raise ValueError("kind_or_version")
        return body
    except (KeyError, TypeError, InvalidSignature, UnicodeError) as exc:
        raise ValueError("signature_or_trust") from exc

