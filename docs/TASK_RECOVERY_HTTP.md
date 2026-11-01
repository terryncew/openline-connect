# OpenLine Connect HTTP Task Recovery — bounded developer preview

The receiver mounts a **literal server-selected action** through `mount_guarded_route`, with its own signed exact-scope grant and trusted SQLite handler. This route reuses the unchanged `ConnectEngine.execute_task` and `inspect_task` methods; it is not another authorization implementation or a universal cross-domain wire format.

## JSON contract

`POST /tickets/assign` (or operator-chosen literal path), `Content-Type: application/json`; maximum raw body 65,536 bytes. Required: `params` object, `authorization` nonblank string. Optional: `nonce` nonblank string, `task_id` nonblank string, `recover_only` boolean (default `false`). Unknown fields, duplicate keys anywhere, invalid field types, or omission of both `nonce` and `task_id` return HTTP 400. `task_id` may contain 1–96 chars after parsing; engine validates length. Non-task legacy actions require `nonce`. `recover_only=true` requires `task_id`.

* Legacy action: `execute(action, params, authorization, nonce)`.
* Task admission/replay: `execute_task(task_id, action, params, authorization, nonce)`.
* Read-only recovery: `inspect_task(task_id, action, params, authorization)`.

The signed *principal* delegation token is an `openline.connect.delegation.v1` compact JWS and binds `subject`, `seller`, `action`, `target`, `parameters_sha256`, `task_id`, `max_amount_cents`, `nbf`, `exp`, `jti`, `delegate_subject` and `delegate_public`. The separately worker-signed `openline.connect.mandate.v1` must match the principal's exact task intent, time and amount bounds and delegate subject. Wire form `<buyer JWS>:<worker JWS>`, Ed25519 signature per token, `kid` pinned to the appropriate configured subject or worker. Exact task ledger identity is receiver + principal + task ID + canonical intent. Revocation/expiry and current receiver grant are checked before any cached result disclosure. A successor with a current exact delegation can receive the original signed receipt and outcome; it creates no new SQLite effect.

`decision` and `state`, not HTTP status alone, indicate permission/outcome. A refusal can be signed in HTTP 200; invalid authentication or scope returns receiver status 403/404/409; 503 means indeterminate, so reconcile the same task ID before retrying. A valid signed outcome attests to the receiver's local SQLite effect, not external shipments, payments, or physical robot actuation.

Run:

```sh
python -m pip install '.[fastapi]' httpx
python examples/fastapi_existing_service.py
python -m unittest tests.test_fastapi_task_recovery tests.test_golden_protocol_vectors -v
```

`issue_fictional_delegated_task` is an **offline local-fixture helper**, with a demo buyer seed deliberately stored beside the receiver. Never deploy this key-custody pattern. The receiver's `allow` and `reload_policy` must still explicitly authorize new effects. See `GOLDEN_PROTOCOL_VECTORS.json` for independently verifiable pinned-seller Accept and signed Connect task envelopes. Connect, Accept, and simulated robotics wire formats remain distinct; independent outside developers and robot hardware have **not** been tested.
