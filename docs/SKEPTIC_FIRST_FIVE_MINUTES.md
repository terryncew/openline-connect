# Skeptic's first five minutes — reproducible source inspection

From this source root with Python 3.11+:

1. Create and activate a virtualenv (`python -m venv .venv; . .venv/bin/activate`, on Windows use `.venv\Scripts\activate`), then `python -m pip install .`; record errors.
2. `openline-connect unified-demo` — examine which seller process decided, which action was accepted/refused, and what was recovered; require signed output.
3. `openline-connect conformance --target "python -m openline_connect.conformance_sample"` — exit 0, machine-readable `status: PASS`; inspect the controller evidence, not just the status.
4. `openline-connect conformance --target "python -m openline_connect.conformance_defective"` — MUST exit nonzero and report `FAIL`. If it passes, stop and report a conformance defect.
5. Open `examples/support_ticket_receiver.py` and `examples/conventional_ticket_receiver.py`. Run both from the source root. Compare actual permissions, signed receipts, local SQLite effects, code/config and trust boundaries. This is a same-author example comparison, not an independent adoption benchmark.

**Read first:** `AGENTS.md`; **run independently:** `docs/AI_EVALUATION.md`; **verify semantics:** `docs/CONFORMANCE_RESULT.md`.

No production API, payment, real robot actuation, vendor interoperability guarantee, or measured human/AI onboarding advantage. No timed result is claimed until someone with a clean environment executes these commands.
