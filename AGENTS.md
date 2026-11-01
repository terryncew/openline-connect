# OpenLine Connect — coding-agent evaluation contract (candidate rc5.dev5)

This file describes this **versioned source tree**. Verify the installed package version and source paths; do not infer any capabilities from earlier tags. Founder-private test history is not evidence available to an external coding agent.

## Run the exact package

Python >=3.11, use an isolated venv. From the release **source root**:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install build
python -m build --wheel --sdist
python -m pip install dist/openline_connect-0.1.0rc5.dev5-py3-none-any.whl
openline-connect unified-demo
python examples/support_ticket_receiver.py
openline-connect conformance --target "python -m openline_connect.conformance_sample"
```

The defective receiver below **must exit nonzero**. A PASS would invalidate the conformance claim.

```sh
openline-connect conformance --target "python -m openline_connect.conformance_defective"
```

If the README commands fail, record the exact error. Don't repair source invisibly or invent private setup steps.

## Protection boundary

The receiving operator owns its signing key, grants, local SQLite policy and handler. Register an **owner-written** action via `ConnectEngine.register(...)` or `ConnectEngine.protect(...)`, grant a signed exact-parameter operation, and configure `policy["effect_sql"]` to expose only the application tables/functions it may touch. Do **not** pass raw SQL or callback code from the worker. `examples/support_ticket_receiver.py` uses only installed APIs. `tests/test_custom_action.py` additionally demonstrates tamper detection on the authorized table.

The `accept.v1` HTTP bridge reaches a **real separate-process** `openline_accept.Seller`. Worker recovery is `AcceptClient.recover_worker(...)` with signed buyer and successor credentials. It does not accept an agent-supplied seller admin token. `openline-connect unified-demo` exercises this with fictional local orders.

## Verification / falsifiers

- `python -m unittest discover -s tests -q` and `python -O -m unittest discover -s tests -q` from source checkout (tests are not in wheel-only installs).
- `python examples/support_ticket_receiver.py`: one authorized local row, unauthorized exact-parameter request refused, duplicate no new row, signed SQLite snapshot verifiable.
- `python examples/conventional_ticket_receiver.py`: a credible *authored reference*, not an independent developer benchmark. Security parity is possible with standard cryptography + SQLite.
- `openline-connect conformance --target "python -m openline_connect.conformance_sample"`: exit 0, JSON status `PASS`, every check true.
- Defective target: nonzero, JSON `FAIL`, **one false is sufficient** to fail. Check `docs/CONFORMANCE_RESULT.md` for machine-readable semantics.
- Controlled issue-to-agent research is not a requirement for this public package. Do not post issues or contact maintainers as part of a read-only audit.

## Trust and safety

Only local fictional SQLite effects and local controller-mediated digital admission are covered. Local signed receipts aren't evidence of delivered goods, external exactly-once APIs, physical safety, independent operator custody, or third-party deployment. Generic OpenLine cross-domain wire portability is **not established**: `accept.v1`, `openline.connect.*`, procurement rights and robotics permits remain distinct. No robotics simulator or ROS 2 integration is shipped. MCP official SDK handshake is unverified. Trusted receiver handlers are not isolated from arbitrary same-process Python I/O. Private keys in demo fixtures are not deployment credentials.

## Independent agent task

> Examine this repository and determine whether OpenLine is useful for an existing AI-agent application. Install the package, integrate it into an independently written receiving service, demonstrate authorization and refusal, test worker succession and recovery, verify the signed outcome, run conformance, and compare the engineering effort against competent conventional alternatives. Report security limitations and unsupported claims.

Use **only** this source tree and installed distribution. Do not read private handoffs, previous chats, other project branches or owner-only material. Record installation commands, timing, code changes, errors, and actual source paths. A favorable conclusion without execution is FAIL. An accurate negative conclusion is valuable. There is no known successful blind agent or human study of this candidate yet.

## Current extended public source inspection

Inspect `docs/PROTOCOL_PROFILES_V1.md`, the standalone independent Accept
verifier (`examples/independent_accept_verifier.py`) and the optional FastAPI
route example (`examples/fastapi_existing_service.py`). The latter requires
`python -m pip install '.[fastapi]' httpx` from this source checkout.
The separate robotics simulator and its conformance tests are **excluded** from this rights-scoped preview. Independently confirm the Accept receipt's pinned seller key and original SQLite rows. Do not count an author-side
rehearsal as a blind integrator evaluation; report parity or disadvantage openly.


## HTTP worker recovery and golden vectors

Run `python examples/fastapi_existing_service.py` and `python -m unittest tests.test_fastapi_task_recovery tests.test_golden_protocol_vectors -v`. Inspect `docs/TASK_RECOVERY_HTTP.md` and `docs/GOLDEN_PROTOCOL_VECTORS.json`. The demo buyer signer is co-located with the receiver for *local synthetic tests only*. No independently measured unfamiliar agent integration speed.
