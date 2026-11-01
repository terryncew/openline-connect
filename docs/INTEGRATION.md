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
