# OpenLine Connect 0.1.0rc5.dev3 — developer preview

This version ships the receiver-owned local Connect SDK and the separately runnable `openline_accept` seller implementation in a single installable package. The code uses standard pinned Ed25519/JWS signatures, receiver-configured authorization, a local transactional SQLite effect, and signed outcome evidence.

## Reproduce the shipped behavior

From the release source checkout after `python -m pip install .`:

```sh
openline-connect unified-demo
openline-connect demo
openline-connect conformance --target "python -m openline_connect.conformance_sample"
openline-connect conformance --target "python -m openline_connect.conformance_defective"
python -m unittest discover -s tests -q
python -O -m unittest discover -s tests -q
```

The deliberately defective conformance command **must exit nonzero** and print JSON status `FAIL`. A zero exit is a test failure, not an indication that the defective receiver works.

Worker B may recover Worker A's already-committed original seller-signed decision/outcome via `AcceptClient.recover_worker(...)` and seller `POST /v1/worker-recover`, requiring buyer-scoped delegation, successor proof, current policy sequence and original order identity. Recovering a result creates no additional fictional SQLite order effect.

The installed `openline-connect conformance` checks 12 cases against an independently signed fictional controller journal. Its passing result is a bounded local test, **not** external controller certification.

## License and evidence limits

The included project `LICENSE` declares **Apache License 2.0**; `pyproject.toml` also identifies `Apache-2.0`. See `NOTICE` and `docs/THIRD_PARTY_NOTICES.md` for copyright and separately installed dependency information. Package inclusion is **not** an independent chain-of-title or contributor-rights audit; the owner must clear any unresolved IP obligations before publishing.

No external payment or shipment settlement, robot safety, production-host isolation, official MCP SDK handshake, universal procurement/robotics wire, independent real-world adoption, or verified developer-speed superiority is claimed. The example and conventional comparison are author-written; the same controls are available with standard cryptography and SQLite. See `docs/UNIFIED_SECURITY.md` and `docs/COMPATIBILITY.md`.

## New public-source evidence in dev2

The optional FastAPI route helper mounts one local protected action in an existing ASGI service, using the same receiver-controlled `ConnectEngine`, and has an executable HTTP TestClient example. A standalone independently coded verifier can check `accept.v1` JWS receipt pairs with a pinned seller key. The previously separate separate fictional robotics simulation experiments now appear under `examples/robotics_sim/`, including receivers A/B, a conventional reference, 14-case adversarial conformance and deliberately dishonest negative control. These changes do not establish intercompany deployment, real robot hardware behavior, broad wire interoperability or a blind developer-speed advantage.


## Surgical task recovery extension

The FastAPI route accepts signed `task_id` and `recover_only`, delegating to the original ConnectEngine task APIs without changing the engine or the Accept seller. Adds a fictional local key-issuance helper, HTTP worker succession and single-effect tests, and frozen cryptographic golden vectors. No independent outsider integration test or human source-rights signoff; publication HOLD.
