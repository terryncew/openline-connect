# OpenLine Connect — receiver-owned authorization for consequential local AI actions

**Start here as a skeptic.** Your AI agent asks a business to perform an action. Who can deny it? Who can replace the agent? What can an independent verifier actually check? This candidate gives a receiver-owned **local** authorization gate, a real separately running Accept seller example, signed receipts, successor recovery, and a behavioral conformance tool. It is not a payment, robot-safety, or external exactly-once system.

## Primary integration path: ConnectEngine

For a **fictional local-only** receiver-controlled bounded agent workflow, run:

```sh
python -m pip install .
python examples/bounded_agent_workflow.py
```

The example grants a named buyer and an explicit Worker A/Worker B list repeated
invoice authority within a receiver-signed scope: specified vendors, fixed
department, **300-cent per-call**, **600-cent cumulative** and **three successful
calls** maximum. Every invocation needs its own worker-signed exact parameters
and nonce/task ID. This uses the same SQLite transaction for the protected
invoice effect and grant/delegation capacity counters. Failed effects consume
no capacity. Cached task recovery does not execute again. The co-located fixture
buyer/worker keys are **never** a production topology. See
[bounded scope security model](docs/BOUNDED_SCOPE_V1.md) and
[the primary integration guide](docs/INTEGRATION.md).

`exact_parameters_v1` remains the default for one-off approvals. The existing
Accept seller and native conformance probe are separate from the ConnectEngine application profile; no universal interchangeable wire contract is claimed.
The native conformance fixtures **do not test your custom handler**.

Python 3.11+; run this from the source checkout containing this version:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install .
openline-connect unified-demo
openline-connect conformance --target "python -m openline_connect.conformance_sample"
openline-connect conformance --target "python -m openline_connect.conformance_defective"  # MUST exit nonzero and print FAIL
```

Windows PowerShell: activate the environment with `.venv/Scripts/Activate.ps1` rather than the Unix `.` command.

`unified-demo` launches a **real separate Accept process**, approves a synthetic SQLite order, rejects unauthorized work, recovers a previously committed receipt for Worker B without another effect, and verifies seller signatures. Conformance inspects a separately signed fictional controller journal: a supplier that merely fabricates receipts and business rows must fail. Inspect the command output and process exit code; don't trust this paragraph.

**Quick falsifiers.** A fabricated outcome passes conformance; a revoked worker gets new work; a recovered order inserts again; unauthorized application-table SQL is accepted; a signed receipt verifies against tampered local SQLite state. Any of these defeats the relevant claimed control. See [`docs/AI_EVALUATION.md`](docs/AI_EVALUATION.md) and [`AGENTS.md`](AGENTS.md) for an executable audit.

**Ask your coding agent (copy/paste):** "Inspect only this repository. Install it, run the real seller demo and both conformance targets, protect an example action using the installed SDK, verify one signed receipt, compare a competent Ed25519/SQLite alternative, and list failed commands, missing functionality, and unsupported claims with exact file paths. Do not assume my claims are true."

**Hard limits:** signed receipts attest to local digital decisions/committed SQLite effects under trust assumptions. They do not prove shipment, money settlement, physically safe robotics, independent production key custody, or one universal procurement/robotics protocol.

---

## Detailed technical walkthrough

**Developer preview: fictional local SQLite effects only.**

This package includes the Connect SDK and a separately runnable `openline_accept` seller gateway, connected by a narrow versioned `accept.v1` adapter. A separate seller process independently checks policy, signed buyer mandates and independent business evidence before a local SQLite order insert. Connect signs and verifies protocol messages. No real payments, deliveries or hardware actions.

## Clean install (Python 3.11+)

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install .
openline-connect unified-demo
openline-connect demo
```

The two packages are already bundled in the wheel. To run the **test suite**, use this proposed release source checkout and run `python -m unittest discover -s tests -q` from the source root; the tests are deliberately not bundled in wheel installations. `unified-demo` starts the genuine PR #90 Accept gateway in a separate subprocess, runs signed admission/refusal/replacement/recovery and prints a redacted summary. The original `demo` prints a local-only receipt; `test_real_accept_http` runs actual `openline_accept.engine.Seller` and `openline_accept.gateway.serve` in a separate process.

### Minimal Python integration (buyer-side)

```python
from openline_connect.accept_bridge import AcceptClient, agent_order
# Client receives the pinned seller public key through an independent trust channel.
client = AcceptClient('http://127.0.0.1:8765', seller_public='...64 hex...')
payload = agent_order(
    buyer='buyer-01', po='PO-101', sku='industrial-filter-17', units=2,
    unit_cents=250000, terms='NET30_SYNTHETIC_v1',
    buyer_seed='...', worker_seed='...',
    contract_seed='...', inventory_seed='...', now=...,)
receipt = client.request(payload)
assert receipt['decision'] == 'ACCEPTED'  # cryptographic signature validated
```

The two evidence signing seeds above belong to independent business evidence issuers **in production**; this synthetic example generates all fixture identities only to work offline. Never embed real private keys in source. The receiver controls its acceptance policy and its SQLite order state. Operator-only status (`client.status`) retains a separate admin token. `AcceptClient.recover_worker(...)` uses a buyer-signed, exact-PO, exact-original-request-hash and current-policy-sequence delegation plus the successor worker’s own signature; no admin token goes to an AI worker.

## What is actually interoperable

`openline-connect.accept_bridge` uses the bundled `accept.v1` HTTP contract and canonical Ed25519 JWS claims: `buyer_mandate`, `agent_purchase`, `business_evidence`, `seller_decision`, `seller_outcome`. This is a *documented versioned bridge*, **not** proof that Connect's `openline.connect.*`, Procurement's `openline.rights.*`, and robotics' `robotics.work_permit.*` are a single common wire protocol. Any shared `openline.core.*` release claim remains unsupported.

## Enforcement scope

`ConnectEngine` protects owner-defined SQLite handlers using SQLite's `set_authorizer` over explicitly configured tables and functions (`policy['effect_sql']`). By default, only `records` is allowed. The DB authorizer rejects unlisted tables even in SQL joins, aliases, CTEs and nested queries, and denies schema/transaction operations. **Trusted same-process Python handlers are not sandboxed**; they can still call `sqlite3.connect()` themselves or perform external I/O. The actual Accept seller validates signature, policy, issuer provenance, order bounds, and evidence before transactional local order insertion.

No cross-database atomicity, physical completion, real ERP reconciliation, or external exactly-once effect is claimed. MCP protocol handshake remains **EXPERIMENTAL / NOT VERIFIED with official SDK**. The separate PR #122 robotics simulator is **excluded from this rights-scoped preview** pending redistribution and attribution clearance. No robot driver or robotics conformance files are shipped.

Public SDK `accept.v1` HTTP interoperability is demonstrated only with the bundled local seller. An experimental **installed supplier-native conformance** command now exists:

```sh
openline-connect conformance --target "python -m openline_connect.conformance_sample"
# Must exit nonzero (fabricated receipts and local SQLite without controller admission):
openline-connect conformance --target "python -m openline_connect.conformance_defective"
```

The supplier executable independently checks owner/worker signatures, calls a separate fictional controller, records its own SQLite result, and the runner inspects the *controller* journal. It is not a real shipment observer or a substitute for separate operators; see `docs/NATIVE_CONFORMANCE.md`. It uses the **supplier-initiated** design, not the old masking wrapper. The public supplier-native conformance suite is runnable from the installed package. The controller/receiver processes currently share the host administrator.

A developer can protect an arbitrary local SQLite action using the public `ConnectEngine.register()`/`.protect()` APIs, and can grant its exact signed parameters with `openline-connect allow --action procurement.approve_order --params-json '{"target":"PO-1","order_id":"PO-1","amount_cents":100}'` after `init`. For a non-demo application, register the handler in your own service, and configure the explicit `policy["effect_sql"]={"tables":["purchase_requests"],"functions":[]}` receiver capability before initialization. No raw arbitrary SQL string from the AI worker is executed. See `GETTING_STARTED_UNIFIED.md`.

See `docs/UNIFIED_PROTOCOL.md`, `docs/UNIFIED_SECURITY.md` and `docs/UNIFIED_EVIDENCE.md` in the source distribution; they are not included as filesystem paths inside an installed wheel.
## Verify it yourself — coding agents and unfamiliar developers

Start with [`AGENTS.md`](AGENTS.md), which describes the exact source, build and test commands and includes falsifiers. A receiver-owned custom-action integration using **only installed SDK APIs** is at [`examples/support_ticket_receiver.py`](examples/support_ticket_receiver.py):

```sh
python examples/support_ticket_receiver.py
python examples/conventional_ticket_receiver.py
openline-connect conformance --target "python -m openline_connect.conformance_sample"
# Expected nonzero exit, JSON status FAIL; the conformance harness must catch this:
openline-connect conformance --target "python -m openline_connect.conformance_defective"
```

The application supplies an exact `tickets.assign` policy, explicitly permits its own `ticket_assignments` SQLite table, rejects a changed assignee, replays without a second insert, and verifies signed local SQLite state. The conventional example is an **author-written functional reference**, not a controlled integration-speed result. The same cryptographic and SQLite mechanisms are available without OpenLine.

For independent AI-agent testing use [`docs/AI_EVALUATION.md`](docs/AI_EVALUATION.md), including the exact evaluation prompt and evidence requirements. For machine-readable `PASS` / `FAIL` use [`docs/CONFORMANCE_RESULT.md`](docs/CONFORMANCE_RESULT.md) and its JSON schema; **command exit code matters**. The public evaluation prompt in `docs/AI_EVALUATION.md` may be given to an independent developer; no such blind evaluation is claimed complete.

**Evidence floor:** unfamiliar human and blind-AI integrations remain **unverified**; procurement and simulated robotics do not share one interoperable signed protocol. Signed local receipts prove bounded simulated admissions and local SQLite commitments; they do not establish third-party completion, physical safety, or external exactly-once effects.

## Additional public, repeatable evidence (author-side, not a blind adoption study)

To mount one **pre-existing FastAPI service route** through the same trusted
`ConnectEngine` decision/effect entry (no new security engine), install the optional
web dependencies and run:

```sh
python -m pip install '.[fastapi]' httpx
python examples/fastapi_existing_service.py
```

The example retains its original unprotected health route, adds a guarded
`POST /tickets/assign` endpoint, tests unsigned/tampered requests, exact replay,
duplicate-JSON keys, one persisted application row and pinned signed local state.
It demonstrates integration only with a synthetic local service using synthetic
buyer/receiver keys. Do **not** place the sample buyer seed in a deployed receiver.
`src/openline_connect/fastapi_route.py` is optional; actual authorization,
revocation and SQLite effect entry remain in `ConnectEngine`.

An **independently coded verifier** for the separate `accept.v1` signed receipt
profile is at `examples/independent_accept_verifier.py`. It does not import
OpenLine or use a public key supplied by an untrusted receipt. You must pin the
receiver public key out-of-band; cryptographic verification does not certify
external payment or shipment.

The separate robotics simulator is **not included in this cut**. Its earlier private CI and separate public source history are not verification of this reduced preview.

See [`docs/PROTOCOL_PROFILES_V1.md`](docs/PROTOCOL_PROFILES_V1.md) for versioned
wire boundaries, independently verifiable evidence, and exact limitations.
No independent developer onboarding-speed advantage or ecosystem moat is claimed.

For the complete receiver-owned route setup (including the explicit policy reload
and reason a 10-line snippet is not a complete secure integration), see
[`docs/INTEGRATION.md`](docs/INTEGRATION.md). For source-rights limitations,
contribution rules and private security reporting, see
[`docs/SOURCE_PROVENANCE.md`](docs/SOURCE_PROVENANCE.md),
[`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) and
[`docs/SECURITY_REPORTING.md`](docs/SECURITY_REPORTING.md).


### FastAPI task succession (local preview)

The optional route adapter supports signed `task_id` admission and `recover_only` result inspection by a differently delegated worker. Run `python examples/fastapi_existing_service.py` and see `docs/TASK_RECOVERY_HTTP.md` / `docs/GOLDEN_PROTOCOL_VECTORS.json`. This verifies one local SQLite transaction, not external effects or human integration effort.
