# Claim-to-evidence — OpenLine Connect rc5.dev2 (developer preview)

Run these against the exact source checkout after `python -m pip install .`. Exits and signed receipt contents, not prose, determine the result.

| Claim | Shipped source / runnable proof | Evidence boundary |
| --- | --- | --- |
| Installable SDK and separate receiver | `pyproject.toml`, `src/openline_connect/`, `src/openline_accept/`; build wheel/sdist and import in clean venv | Python 3.11+ declared; dependencies may need installation |
| Receiver-owned exact authorization and refusal | `openline-connect unified-demo`; `tests/test_real_accept_http.py`, `tests/test_unified_sql.py` | fictional seller and local SQLite |
| Worker's credentials can be revoked/replaced | `tests/test_worker_recovery.py`, `src/openline_accept/engine.py` current policy epoch; `unified-demo` | bounded local seller; no global agent identity standard |
| Worker B recovers Worker A's original signed result | `AcceptClient.recover_worker(...)` in `src/openline_connect/accept_bridge.py`; HTTP `POST /v1/worker-recover` in `src/openline_accept/gateway.py`; `tests/test_worker_recovery.py` | exact buyer/PO/request hash, buyer delegation + B key, no second SQLite effect |
| Custom application table and signed state | `examples/support_ticket_receiver.py`, `tests/test_unified_sql.py` and `tests/test_receiver_exact.py` | trusted handler code, explicit SQLite table permissions; no arbitrary Python sandbox |
| Independently verifiable signed evidence | `src/openline_connect/signing.py`, `accept_bridge.py`, `verify.py`; verify trusted seller public key and canonical decision/outcome binding | cryptographic receipt of local state, not external completion |
| Native conformance catches fraudulent supplier evidence | `openline-connect conformance --target "python -m openline_connect.conformance_sample"` must PASS (0); `...conformance_defective` must FAIL (nonzero); `src/openline_connect/native_conformance.py` | fictional controller journal, shared evaluation host; not certification |
| All shipped public tests pass | `python -m unittest discover -s tests -q` and `python -O -m unittest discover -s tests -q` | 56 public tests, zero skips; private-only issue fixture omitted intentionally |
| Conventional reference has functional parity | `examples/conventional_ticket_receiver.py` beside `examples/support_ticket_receiver.py` | same-author examples, no independently measured developer-speed benefit |
| One universal robotics/procurement signed wire | **NOT ESTABLISHED**: see `docs/UNIFIED_PROTOCOL.md` | the simulated robotics conformance source is public in examples/robotics_sim/, but no hardware API exists |
| Official MCP SDK handshake | **NOT VERIFIED**: see `docs/PLATFORM-LIMITS.md` | do not claim production MCP interoperability |
| Independent human/AI adoption or external-effect finality | **NOT VERIFIED**: see `docs/AI_EVALUATION.md`, `docs/SECURITY.md` | no external fund transfer, shipment, robot or independently timed cohort |

A skeptical developer should run the positive and negative controls, inspect signed tokens and SQLite effects, and report falsifiers. The package makes no claim of unmatched cryptographic primitives or proven industry adoption.
