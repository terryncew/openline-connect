# bounded_scope_v1 — experimental local receiver grant profile

`exact_parameters_v1` is unchanged and remains the default. Bounded scope is
an **additional opt-in receiver-signed** grant checked at SQLite effect entry.

Required receiver-signed scope: unique `id`/`jti`, receiver-held `seller`
authority (signed JWS), `subject` buyer, action and nonempty `allowed_actions`,
nonempty explicit `allowed_worker_subjects`, `permitted_keys`, `fixed_params`,
`target_restrictions`, `amount_key` (default `amount_cents`), positive integer
`max_amount_per_op`, `max_cumulative_amount`, `max_uses`, `expires_at`, active
flag. No wildcard. An action is granted only when its specific signed grant is
under that action's receiver policy key. Buyer delegation signed separately
with permitted same-or-narrower scope and expiration; its worker key/subject
are pinned. Every concrete worker request binds signed exact parameters and
nonce/task ID. Receiver policy and delegation conditions are intersected.

**Atomicity:** SQLite BEGIN IMMEDIATE prevents two guarded requests from
consuming the same capacity concurrently. Receiver grant and delegation JTI
budgets are charged in the same transaction as the trusted callback's local
SQLite effect. The signed budget row binds the exact authorization scope;
missing rows with previously signed bounded admissions fail closed. Failed
callbacks roll back capacity; authorized replay/recovery returns original
signed evidence without another charge. Revocation and expiry are checked
again before effect entry. `inspect_task` still requires current successor
credentials and never authorizes new work after grant revocation.

**Trust:** no guarantees against a compromised process, privileged direct SQL,
entire-ledger replacement by the host administrator, OS rollback, or effects
outside the guarded SQLite connection. Signed capacity records are a
self-contained tamper check under the receiver's key, **not** an independent
external witness. Receiver code controls handler behavior and table grants.
The code is not a payment, physical-safety, multi-host distributed ledger,
or universal wire interoperability system.

**Known performance cost:** successful effects still scan permitted local
application tables to sign a full-state hash; failed/pre-effect denials do not
recompute a snapshot and do not attest a new snapshot. The signed outcome's
`application_tables_snapshot_sha256` is absent on such denials. Tested local
1000/10000-row one-write transactions measured about 5.9/88.6 ms for allowed
and median 1.3/1.4 ms denied on one Python 3.13 runner. Not production p95,
not an external conventional benchmark; see saved benchmark receipts.

**Adoption:** author-written tests and this demo do not establish a faster
independent integration than competent conventional Ed25519/SQLite. Outsider's
original handwritten comparator is not available; no exploit is attributed
to it without running its actual source. No public publication or rights
clearance follows automatically from this private candidate.
