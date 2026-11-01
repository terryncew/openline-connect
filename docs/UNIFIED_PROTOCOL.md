# Contract compatibility, versioned and narrowly scoped

Version `openline-connect 0.1.0rc5.dev5` provides an explicit **`accept.v1` compatibility adapter** for the bundled receiving-seller implementation.

* HTTP `POST /v1/orders`, `Content-Type: application/json`, request exactly `{version:'accept.v1',buyer,profile:'agent_json',order,mandate,evidence}`.
* `mandate`: JWS EdDSA, `kind:'buyer_mandate',v:1`, signed by the seller-pinned buyer public key, bound to buyer/supplier, specific PO, SKU, price ceiling, evidence token hashes, validity and JTI.
* `order`: JWS EdDSA, `kind:'agent_purchase',v:1`, signed by current seller-pinned provider key, binds purchase JSON and sha256(JSON-canonical(mandate_token)).
* `evidence`: two EdDSA tokens `kind:'business_evidence',v:1` from seller-pinned `contract`/`inventory` issuers.
* Response: seller-signed JWS `kind:'seller_decision'` and `kind:'seller_outcome'`, with outcome.decision_sha256 binding the decision token bytes; sender public key supplied by caller, never extracted from untrusted receipt.
* Reconciliation: operator-token `GET /v1/orders/{buyer}/{po}` and `GET /v1/receipts` remain operator-only. The bundled receiver implements **`POST /v1/worker-recover`** verifies buyer-signed delegation, successor proof, exact original buyer/PO/request hash and current seller policy epoch, then returns the original seller-signed decision/outcome without a new local effect. SDK: `AcceptClient.recover_worker(...)` and `make_worker_recovery(...)`. The source and tests for this endpoint are included here; verify the exact installed version.
* HTTP server accepts loopback only. Idempotency `(buyer, po)`, same request returns `REPLAY_SAME`, conflicting same PO returns refusal.

`openline.connect.*` mandates are accepted by the original H-01 local Connect engine, **not** by the bundled Accept gateway. `openline.rights.*` procurement claims and `robotics.work_permit.*` task claims continue to require separate domain verifiers. Any claim of one shared `openline.core.v1` wire contract is **NOT VALIDATED** by this candidate.

Signing is standard pinned Ed25519/JWS with canonical, size-bounded JSON. H-01's `signing` compatibility method uses `public_bytes(Encoding.Raw,PublicFormat.Raw)` to support cryptography 38+.
