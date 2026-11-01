# Primary developer path: ConnectEngine

**Experimental / fictional SQLite only.** Use `ConnectEngine` for the receiving
business's exact authority. It owns signed grant checks, transaction-scoped
capacity, permitted SQLite tables, durable task identity and receipts.

Run `python examples/bounded_agent_workflow.py` after installing from this
source tree. Inspect that file: it uses `allow_bounded(...)` to issue a
receiver-signed bounded grant, the buyer-signed delegation, worker-signed
mandates for every concrete request, and an owner-written effect handler.

Allowed actions require **receiver signed grant AND buyer delegation AND exact
worker-signed invocation**. `bounded_scope_v1` never implicitly permits new
actions, workers, keys or targets. `amount_key` is integer only. Counters for
receiver grant jti and buyer delegation jti advance in the same SQLite
`BEGIN IMMEDIATE` transaction as the permitted effect; original receipts are
returned on authorized retries. The default remains `exact_parameters_v1`.

Significant limits: normal Python callbacks run in a trusted receiver process,
not an OS sandbox. The SQLite C authorizer narrows database operations only;
direct privileged database connections can bypass a caller that does not use
the protected API. Local signed receipts do **not** prove outside shipment,
payment or physical safety. This source's demo co-locates fictional private
keys; production buyers, workers and receivers must hold separate keys. See
`docs/BOUNDED_SCOPE_V1.md`, `docs/SECURITY.md` and `docs/PROTOCOL_PROFILES_V1.md`.

Native `openline-connect conformance` tests its provided supplier fixtures,
not a developer's custom `ConnectEngine` callback. Accept remains a separate
wire profile; the robotics simulator is excluded from this rights-scoped cut.

---

# Mount one existing FastAPI action on the actual receiver-owned gate

This is a self-service, synthetic local demonstration. Run from the source root:

```sh
python -m pip install '.[fastapi]' httpx
python examples/fastapi_existing_service.py
```

The app has a pre-existing `GET /tickets/health` endpoint. The receiver defines a trusted local handler to write `support_tickets`, configures its own `effect_sql` permission, then mounts a single protected `POST /tickets/assign` route:

```python
from openline_connect.fastapi_route import mount_guarded_route
mount_guarded_route(app, engine,
    path='/tickets/assign', action='support.assign',
    handler=assign, max_amount_cents=0)
```

The receiver supplies `engine = read_engine(receiver_home)` and a trusted handler `assign(signed_params, authorized_db)`. The local example calls `initialize(receiver_home)` once, creates its SQLite business table as operator setup, configures `policy['effect_sql']['tables']`, and creates a **synthetic** buyer-signed mandate using `onboarding.allow(...)`. After provisioning, **explicitly call** `engine.reload_policy()` in the long-running process; creating a grant file alone does not change the live receiver's grants. In real deployments, the buyer key is provisioned and retained outside the seller process.

The HTTP client must send exactly `{"params":{...},"authorization":"<buyer JWS>","nonce":"..."}`. The route selects the action itself, rejects duplicate JSON keys and unexpected top-level fields, and calls the same `ConnectEngine.execute` implementation used by the local SDK. It never accepts a client-provided Python callback or raw SQL. A refusal can be an HTTP 200 response containing a signed decision of `DENY`; **check the decision**, not the HTTP status alone. `503` denotes an indeterminate failure: reconcile the original nonce; do not invent a new effect ID.

Verify with `onboarding.verify_local(home,seller_public=pinned_public,verify_records=True)` and read-only SQLite row count. This is a **local** transaction. Direct privileged Python I/O in the trusted handler bypasses the SQLite authorizer; don't put external API calls or arbitrary untrusted callbacks in it.

## What this does not automate

It does not provision independent keys, create business tables, infer seller policy, recover a separate company's original `accept.v1` receipt, or provide a production deploy. The separate-process seller and Worker B recovery path are exercised through `openline-connect unified-demo`. See `docs/PROTOCOL_PROFILES_V1.md` and `docs/UNIFIED_SECURITY.md`. A 10-line route binding must not be mistaken for a 10-line secure deployment.


## Signed task continuation through the same FastAPI endpoint

An optional `task_id` with `recover_only: true` invokes the unchanged `ConnectEngine.inspect_task` using currently authenticated worker delegation. See `docs/TASK_RECOVERY_HTTP.md`. The existing-service example now demonstrates Worker A revocation and Worker B retrieving the exact original signed outcome with no additional SQLite ticket insertion. Synthetic local administrator and keys only.
