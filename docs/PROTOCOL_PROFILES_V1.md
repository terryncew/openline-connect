# OpenLine wire profiles and independent implementation contract (developer preview)

This is an **open, implementable set of versioned application profiles**, not one vendor-neutral universal wire standard. You can independently implement the documented `accept.v1` seller HTTP participant or verify signed outcomes with the public `examples/independent_accept_verifier.py`, which imports no OpenLine code. Procurement and the separately withheld robotics research use **different domain payloads and authority issuers**. Sharing the design principles does not make their messages interchangeable.

## `accept.v1` — independently operated receiving business

The receiving seller owns SQLite `orders`, acceptance policy, current buyer/worker public keys, revocation list, its signing key and durable result ledger. The buyer, worker and contract/inventory evidence issuers are distinct keys in the intended trust model. The local demo puts identities on the same machine **only as synthetic fixtures**.

- `POST /v1/orders` JSON: `{"version":"accept.v1","buyer":"...","profile":"agent_json","order":"<EdDSA JWS>","mandate":"<EdDSA JWS>","evidence":["<contract JWS>","<inventory JWS>"]}`. The seller's current receiver policy must admit the exact signed order and independent evidence; a caller-provided policy or public key does not override it.
- `POST /v1/worker-recover` JSON: `{"version":"accept.v1","buyer":"...","po":"...","delegation":"<buyer-signed JWS>","worker_proof":"<successor-signed JWS>"}`. Seller validates current provider key/epoch, exact prior request hash, buyer, PO, seller identity and delegation bounds, returns the **original seller-signed** prior decision/outcome pair and creates no new business effect. This is not authorization to place a new purchase.
- Response includes `receipt` (`seller_decision`) and `outcome` (`seller_outcome`) signed by the receiving seller. Verify both with a public key pinned out-of-band. Compare `outcome.decision_sha256 = SHA256(canonical_json(receipt_token_string))` and bind both buyer, PO and original request hash. `LOCAL_COMMIT` means synthetic SQLite commit only.
- Seller-specific error/refusal semantics include `REFUSED`, `REPLAY_SAME` and `INDETERMINATE`; clients must not infer a new effect from absence of a response. Exact retry uses `(buyer,po)` durable idempotency. A conflicting reuse of a PO must refuse.
- `accept.v1` signing uses compact JWS `base64url(canonical_header).base64url(canonical_payload).base64url(Ed25519_signature)`, with `alg:EdDSA`, `typ:JWT`, string `kid`; JSON canonicalization sorts keys, uses `,` and `:`, and ASCII escapes non-ASCII. Duplicate keys, unpinned keys, changed signed claims and noncanonical token encodings must be rejected. Token size is bounded to 262144 bytes. Replay/expiry/policy checks occur inside the receiver's trusted execution decision.
- For a runnable executable specification, inspect `tests/test_real_accept_http.py`, `src/openline_accept/gateway.py`, `src/openline_accept/engine.py`, `src/openline_connect/accept_bridge.py`, `examples/independent_accept_verifier.py`, and the negative tests. This is the exact first released profile; independent external receiver implementations have **not** been demonstrated.

## `openline.connect.*` — local application effect profile

`ConnectEngine` uses `openline.connect.mandate.v1` signed by an owner-pinned buyer key, exact canonical parameters SHA256, receiver-signed exact policy grants, expiry, local revocation, nonce ledger, and signed `openline.connect.decision.v1` / `openline.connect.outcome.v1`. A trusted handler writes only the allow-listed application tables through the passed guarded SQLite capability. This cannot sandbox arbitrary Python or external I/O. `fastapi_route.mount_guarded_route` provides an ASGI route adapter over **this same engine** (no second authorization implementation).

## Excluded robotics research profile

The private research program has an unrelated `robotics.work_permit.v1` simulation. **It is not shipped here**, pending independent redistribution and attribution clearance. There is no robot-hardware API, robotics conformance command, or compatible universal `accept.v1`/robotics wire in this cut.

## Independent verification and falsifiers

Treat signatures as attestations by their actual signing keys, not proof of physical world events. Independent verifier is supplied a seller public key through an independent trusted channel. It should reject altered signatures, buyer/PO/request hash substitutions, wrong signed kinds, fabricated outcome links, unsupported fields, and claimed `LOCAL_COMMIT` without a valid accepted decision. An independently implemented seller or controller must still enforce its own current policy and durable effect evidence; passing a signature parser alone is insufficient. Any field not described above requires checking the exact source for this developer-preview profile; do not infer production interoperability.

**No public claim here:** universal agent identity, cross-domain wire standard, remote ERP atomicity, robotic safety certification, or independently measured developer-effort advantage.


## Frozen compatibility vectors

`docs/GOLDEN_PROTOCOL_VECTORS.json` contains the independently checkable pinned Ed25519 seller decision/outcome pair and the Connect buyer+worker task delegation chain. `tests/test_golden_protocol_vectors.py` validates both without importing either engine. The exact HTTP task envelope and current-credential recovery rules are documented in `docs/TASK_RECOVERY_HTTP.md`. Signature parsing is not proof of third-party interoperability, external consequences or a universal cross-domain standard.
