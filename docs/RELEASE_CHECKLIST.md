# Exact public-export release checklist (developer preview)

Run these commands in the **actual exported release source checkout**, not the private research workspace. Python >=3.11 is declared in `pyproject.toml`; check exact runtime coverage in `docs/COMPATIBILITY.md`.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install .
python -m unittest discover -s tests -q
python -O -m unittest discover -s tests -q
openline-connect unified-demo
openline-connect demo
openline-connect conformance --target "python -m openline_connect.conformance_sample"
python examples/support_ticket_receiver.py
python examples/conventional_ticket_receiver.py
```

**Negative control:** run `openline-connect conformance --target "python -m openline_connect.conformance_defective"` separately. It must exit **nonzero** with JSON `"status": "FAIL"`; a positive result is a release blocker.

Also verify with receipts: installed wheel and sdist separately; signed seller decision and outcome; exact-scope refusal, revocation, replacement, Worker B recovery without a new SQLite order; independent pinned-key verification; `docs/UNIFIED_SECURITY.md` trust boundaries; and `LICENSE`, `NOTICE`, `docs/THIRD_PARTY_NOTICES.md` in the actual exported tree. Verify source archive and distribution SHA-256 against the manifest and the exact CI commit.

**Publication-specific owner gates:** confirm source/AI contribution chain-of-title, employer/contractor agreements and third-party license/notice obligations with a qualified reviewer where needed; approve the exact release tree and license. Do not infer ownership merely from a `LICENSE` file. Preserve existing public repository history and require a fresh public checkout and actual executed test results before announcing. Publication, hosting, PyPI, payments, robots and outreach require separate owner approvals.

The experimental optional MCP route has **not** passed an official SDK handshake and is not a mandatory launch test. No missing private script or unpublished research checkout is required by these commands.

## Reduced dev5 preview — optional FastAPI and explicit robotics exclusion

From the source root, after `python -m pip install '.[fastapi]' httpx`:

```sh
python examples/fastapi_existing_service.py
python examples/bounded_agent_workflow.py
```

The 16 `examples/robotics_sim/` files and their simulation controls are **not included** in this candidate; do not run the old robotics conformance commands. CI must assert the paths are absent from the public source and sdist.

Inspect independently verifiable receipts via the no-OpenLine-import reference `examples/independent_accept_verifier.py`. No independent developer study is claimed.
