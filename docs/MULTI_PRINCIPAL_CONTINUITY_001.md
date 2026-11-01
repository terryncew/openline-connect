# OpenLine Connect: independent buyer / worker / receiver preview (experimental)

**Scope:** local SQLite receiver, receiver-owned trusted handlers, Ed25519 owner/worker keys, loopback HTTP integration. No real payments, remote key custody, OS security boundary between processes running as the same user, or cross-provider compatibility claim. This is an author-written first integration, not a cold-start outsider study.

## Five-minute first test

Python 3.11+ from the checked-out source root (FastAPI demo dependencies are optional to the base SDK):

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install '.[fastapi]' httpx
python examples/multiprincipal_http.py
python -m unittest tests.test_multiprincipal_001 -v
```

The executable launches **separate actual Python processes** for two buyers, four distinct workers and a FastAPI receiver. Buyer A's first response is dropped *after* its SQLite commit; a separate Worker B later recovers the exact original signed outcome after receiver restart and A-delegation revocation. Buyer B uses the same task/delegation/mandate IDs with a different pinned buyer key; its effect and counters are independent. Tampered cross-buyer recovery and mutation attempts are refused; the latter may be an HTTP 200 carrying a **signed DENY**, not necessarily an HTTP 403. The independent receipt check uses `cryptography` directly, not OpenLine's verification helpers. Read exact resulting stdout/SQLite rows; do not treat this narrative as evidence.

## Supported public APIs: no JWS construction by integrators

```python
from openline_connect.principals import ReceiverAuthority, BuyerAuthority, WorkerIdentity
from openline_connect.engine import ConnectEngine

# These objects live in different organizations/processes.
buyer = BuyerAuthority.generate(subject='my-company')          # buyer-only machine
worker = WorkerIdentity.generate(subject='my-worker')         # worker-only machine

# Receiver is given the public key only. Register *all current buyers before
# initializing an engine with a database containing live operations*.
policy = ReceiverAuthority.initial_policy(effect_tables=['invoices'])
policy = ReceiverAuthority.register_buyer(
    policy,buyer_subject='my-company',buyer_public=buyer.public_key)
# Add another unrelated buyer via register_buyer before engine construction.
# Receiver loads/persists its own seed, creates ConnectEngine and registers the
# trusted handler (params, restricted_db) for the named action.

# receiver_grant = ReceiverAuthority(engine).issue_bounded_grant(
#   buyer_subject='my-company',action='invoice.approve',grant_id='grant-1',
#   allowed_worker_subjects=['my-worker'], permitted_keys=['buyer','target','amount_cents'],
#   fixed_params={'buyer':'my-company'},target_restrictions={},
#   max_amount_per_op=100,max_cumulative_amount=300,max_uses=3,
#   expires_at=int(time.time())+300)
# Buyer, on its own machine:
# delegation = buyer.delegate(receiver_grant=receiver_grant,
#    receiver_public=PINNED_RECEIVER_PUBLIC,receiver_id='receiver',
#    worker_subject=worker.subject,worker_public=worker.public_key,
#    delegation_id='delegation-1')
# Worker, on its own machine:
# request = worker.request(delegation=delegation,buyer_subject='my-company',
#    buyer_public=buyer.public_key,action='invoice.approve',
#    params={'buyer':'my-company','target':'INV-1','amount_cents':50},task_id='task-1')
# Send `worker.http_payload(request)` to receiver's guarded FastAPI POST route.
# To recover: worker.recovery_request(task_id='task-1', ...same signed intent...)
```

See `examples/multiprincipal_http.py` for an **executable** workflow. All identity signing seeds in that demo are created within and stored in their respective processes/0600 files; the receiver reads only buyer *public keys*. The parent orchestration script can access all folders as the same OS user; this does not demonstrate production key custody or privileged-user isolation. A real deployment must arrange independent key storage and pinned trust roots.

## Security and migration

- Buyer namespace is the SHA-256 of **pinned receiver ID, buyer subject and pinned buyer public key**, recovered only after verifying the signed owner chain. Request fields do not select an operation/counter namespace. Scoped keys cover `operations` (including task recoveries and mock settlements), grant/delegation counters, mandate and grant revocations and used-JTI tracking. The receiver's operator-only `recover` and compensation path requires an explicit matching buyer scope in multi-buyer mode; do not expose raw operator endpoints to workers.
- `buyer_registry` durably pins subject/public keys under a `BEGIN IMMEDIATE` lock. Silent key replacement or buyer removal is rejected; buyer credential rollover requires a separately reviewed continuity mechanism.
- Existing single-buyer databases retain their original keys and behavior. If a legacy unscoped `operations`, `capacity_usage`, or `revocations` entry exists, attempting multi-buyer startup raises `legacy_unscoped_state_requires_explicit_migration`. **Do not clear it, overwrite it, or rename its keys to “fix” the error.** An operator must preserve old receipts/counters and explicitly migrate authority or start a separate new receiver. This is a safe compatibility hold, not an automated migration.
- Receiver key rotation is supported via `ConnectEngine.rotate(new_seed)` and does **not** change buyer namespace. Signed historical outcomes remain verifiable with the pinned receiver key-epoch chain; receiver seed/file rotation still is not cross-file crash-atomic.
- Receiver-signed bounded grants and separately buyer-signed narrower worker delegations require worker-signed exact concrete parameters/task ID. SQLite `BEGIN IMMEDIATE` serializes consumption and protected *local* effects. Revoked workers cannot get fresh work. A successor's valid, narrowed mandate may inspect a previously committed result without charging capacity again. No trusted handler may accept worker-chosen raw SQL or secret keys.
- `ConnectEngine.revoke(..., buyer_subject=...)` and `revoke_grant(...,buyer_subject=...)` are **receiver-operator APIs**, not self-revocation by an untrusted caller. In multi-buyer mode, calling without `buyer_subject` is rejected to avoid cross-buyer revocation.
- `Accept` (`accept.v1`) and its separately controlled seller gateway remain a **different profile**. Native conformance does not certify custom ConnectEngine tenant isolation. Robotics code is excluded from this rights-scoped source. No hosted identity, OAuth, new SQL engine, new security engine or production tenant boundary is introduced.

## Conservative comparison

FastAPI, Ed25519 and SQLite can implement the same per-buyer key derivation, transactional limits, distinct key custody and receipt signatures. OpenLine's historical competent conventional samples demonstrate local parity on their tested scopes; they are **not** a complete, independently benchmarked multi-principal comparator. DBOS and other durable execution frameworks may supply stronger workflow recovery interfaces in an appropriately configured deployment, but a direct equivalent measured security and integration comparison is **not established here**. Do not advertise a product advantage on the basis of this example or test count.

**Falsifiers:** B's same JTI blocks A, B can receive A's original receipt, a replay charges a grant twice, a changed buyer key silently restores capacity, an already-spent single-buyer ledger migrates automatically, a revoked worker performs new effects, or a signed output does not match the committed SQLite row. Any demonstrated case is a release blocker.
