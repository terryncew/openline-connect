# Security and authority: local fictional developer preview

## Local receiver-grant and effect-entry security model (dev1)

Receiver grants use `grant_mode=exact_parameters_v1` and a receiver-signed
`parameters_sha256` for the canonical full operation dict (target, value and
amount included). The buyer mandate binds the same bytes independently. There
is no parameter-range grant in this candidate; `max_amount_cents` remains a
secondary ceiling, NOT permission to change an otherwise approved amount.
Missing or legacy grant digests fail closed. Existing rc2 receiver grants must be
reissued intentionally before this candidate can admit a new effect.

`revoke(jti)` revokes one buyer-signed mandate. A buyer with a still-trusted
signing key may sign another mandate within the active receiver grant.
`revoke_grant(grant_id)` durably terminates that receiver authority at future
SQLite effect entries, including for replacement buyer mandates. Neither
operation undoes effects committed before revocation wins the SQLite write lock.

Receipt `verified: true` authenticates signed claims and contiguous supplied
history beginning at the genesis claim; it does not establish the ledger is
complete. `history_complete_relative_to_checkpoint` becomes true only if
both an externally pinned expected sequence and head hash are supplied.
Without an independent retained checkpoint, a valid prefix may verify.

This is a local SQLite transaction engine with a seller-owned authorization trust configuration, not a general-purpose sandbox. It requires caller-signed mandates binding subject/seller/action/target/full parameter hash/expiration/amount. Mandates and pinned roots are provisioned *outside* agent input. SQLite WAL with `synchronous=FULL` and `BEGIN IMMEDIATE` serializes the local effect and signed record. Replay identity is seller+action+nonce and request hash; a changed request is 409.

Paid operations must be explicitly registered with `payment_required=True`. Mock facilitator assertions use a separately pinned key and exact action/target/request digest/amount/expiry; unknown status is unresolved. The bridge does **not** invoke a facilitator; no settlement is retried automatically. After simulated settlement, crash recovery resumes a SQLite-local handler only. The status `SETTLED_UNFULFILLED_REFUND_DUE` is a signed assertion of failed local fulfillment, not a refund instruction or completed refund.

Signed `DENY` authenticates the receiver's refusal; `authenticated_subject=False` clearly indicates untrusted buyer proof. The detached verifier can additionally check the original buyer proof with independently pinned buyer keys. `prev_decision_hash` and `decision_seq` detect reorder, omissions in supplied history and suffix rollback **only when an externally stored expected head is supplied**. A compromised seller controlling DB and keys can forge a self-consistent new history otherwise. Historical keys are pinned out of band; key succession is signed by prior seller root but not an independent global witness. Durable revocations persist on restart.

**Known gaps**: no production key custody/HSM, remote secret management, host/DB compromise resistance, external webhook/ERP/chain atomicity, money settlement verification, compensation execution, client-visible independently anchored head receipts outside the response, multi-process distributed coordination, complete vulnerability audit, third-party product rights clearance, or official x402/MCP SDK wire conformance. The decorator wrapper provides no external side-effect atomicity; SQL-only example has the claimed boundary. The standalone plugin is not connected or approved in ChatGPT.

Earlier private research implementations are not shipped in this standalone source. Package tests include direct-route bypass assertions and signed outcome tamper checks; they are not a production penetration test.

Public export change: legacy no-grant policy override was removed from engine; no static demo signing keys are shipped. Exactly-once is SQLite-local only.
