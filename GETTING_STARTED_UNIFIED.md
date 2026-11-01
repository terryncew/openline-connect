# Ten-step local Connect and Accept walkthrough

Prerequisites: Python 3.11+, the built wheel and its cryptography dependency. This is a synthetic local evaluation; no payments, machines or external network services.

1. In a fresh virtual environment, install the wheel: `pip install .`.
2. Run `openline-connect unified-demo`. The command starts the real PR #90 Accept gateway in a second process on a random loopback port.
3. The synthetic Factory/Buyer creates Ed25519 buyer and AI Worker A keys; the seller independently pins the buyer, worker and two evidence-source public keys.
4. Connect's **public** `agent_order` API creates a bounded exact-PO mandate and two independent issuer evidence JWS tokens.
5. Connect's `AcceptClient.request()` posts it over actual HTTP `/v1/orders` to `openline_accept.Seller.submit()` and verifies the signed decision and outcome from the separately running seller.
6. The SDK submits the same signed order again: receiver returns `REPLAY_SAME`; local SQL business effect count remains 1.
7. A tampered unsigned order is refused with a seller-signed `REFUSED` receipt.
8. A simulated lost reply is recovered by Worker B using a buyer-signed delegation and Worker B's proof of possession through **`POST /v1/worker-recover`**, called using `AcceptClient.recover_worker(...)`. An operator-only status API exists separately, but is not needed by the worker.
9. The seller restarts with policy sequence 2 pinning Worker B; old Worker A is refused with a fresh request, Worker B is admitted for a different authorized PO.
10. The SDK independently verifies all returned seller-signed decision/outcome receipts, checks local SQLite count `2`, and prints `FICTIONAL_SQLITE_ONLY_NOT_EXTERNAL_DELIVERY`.

For code integration, copy the minimal Python snippet from `README.md` and use a receiver/operator-managed policy in your own process. The demonstration's all-in-one fixture key generator is **not** a model for controlling production independent issuers.

To test SQL capabilities in a **source checkout**: `python -m unittest tests.test_unified_sql`. To inspect the real HTTP source: `src/openline_accept/engine.py`, `src/openline_accept/gateway.py`. Native supplier conformance ships in this wheel as `openline-connect conformance --target "python -m openline_connect.conformance_sample"`; use `conformance_defective` as the must-fail control. The fuller PR #121 research gate is not part of the public release.

## SDK custom action without editing OpenLine

The app owner creates a SQLite table in its own provisioning step and explicitly
lists that table in receiver policy `effect_sql.tables`. The receiver loads its
policy, then registers a trusted application handler using `ConnectEngine.register`:

```python
from openline_connect.engine import ConnectEngine

engine = ConnectEngine('sqlite:///receiver.sqlite', policy, seller_seed=receiver_seed)
def commit_order(params, db):
    db.execute('INSERT INTO purchase_requests(order_id,approved) VALUES(?,1)', (params['order_id'],))
    return {'order_id': params['order_id'], 'approved': True}
engine.register('procurement.approve_order', commit_order, max_amount_cents=500, atomic=True)
```

Grant one exact action with `openline-connect allow --home .openline
--action procurement.approve_order --params-json
'{"target":"PO-1","order_id":"PO-1","amount_cents":100}'` in the *local fictional profile*.
The `allow` command signs an exact receiver grant and buyer mandate; it cannot
register or execute your application handler for you. The handler must operate
through the constrained DB proxy. It cannot claim external effects atomic.

## Worker B recovery (no admin credential)

See `src/openline_connect/accept_bridge.py` and `tests/test_worker_recovery.py`. From the installed SDK, use
`make_worker_recovery()` with the buyer and new worker's independently held
signing keys and the original signed order hash; pass its output into
`AcceptClient.recover_worker(**proof)`. The receiver checks its current
signed policy sequence and pinned worker public key and returns the **original**
receipt and outcome without adding a new business effect. `unified-demo`
executes this end to end with real separate Accept process.

## Supplier-native conformance (installed)

```sh
openline-connect conformance --target "python -m openline_connect.conformance_sample"
openline-connect conformance --target "python -m openline_connect.conformance_defective"
```

The first command must pass 12 local controller/journal checks; the second must
fail, including the false receipt/SQLite-row attack. The verifier does not trust
adapter-side effect claims, but cannot observe effects outside its fictional
controller. This does not prove protection against malicious system administrators.
