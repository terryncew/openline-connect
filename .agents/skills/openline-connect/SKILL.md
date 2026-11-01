---
name: openline-connect
description: Evaluate local receiver-owned AI-agent authorization, Accept v1 and installed native conformance using public APIs; report evidence and limits.
---

# OpenLine Connect rc5.dev5 — rights-scoped preview candidate (publication approval pending)

Read root `AGENTS.md` **before** touching integration code. Confirm the exact version from `pyproject.toml` or installed package metadata. The source in public GitHub is currently an older preview; do not claim this private candidate is live.

1. Create a clean Python >=3.11 venv, install the wheel built from this source. Run `openline-connect unified-demo` (actual separate Accept process with fictional SQLite order), and `python examples/support_ticket_receiver.py` for custom receiver policy/handler. No confidential key material is needed for this synthetic example.
2. Review `openline_connect.onboarding.initialize/allow/read_engine`, `ConnectEngine.register/protect`, `openline_connect.accept_bridge.AcceptClient.recover_worker`, and `tests/test_worker_recovery.py` / `GETTING_STARTED_UNIFIED.md`. Explicitly grant authorized application tables using `policy["effect_sql"]`; arbitrary worker SQL is unsupported.
3. Run `openline-connect conformance --target "python -m openline_connect.conformance_sample"` and repeat with `.conformance_defective`; parse stdout JSON and exit code per `docs/CONFORMANCE_RESULT.md`. The defective version **must fail**. Verify local controller journal, never trust a supplier's self-signed row as consequence proof.
4. Run normal and optimized Python inherited tests from the source tree. Compare to `examples/conventional_ticket_receiver.py` and record actual developer effort without treating authored LOC or demo speed as an independent adoption result.
5. Report: working use case, source paths, exact commands, test evidence, required configuration, and limits. State explicitly that Accept `accept.v1` is not a universal procurement+robotics wire standard; robotics simulator source is excluded from this rights-scoped candidate, external effects are not proven, official MCP handshake isn't verified, and the receiver's trusted Python handler is not sandboxed.

Independent AI evaluation protocol: `docs/AI_EVALUATION.md`. Local optional issue-to-agent test: `controlled_issue_repo/ISSUE-001.md`. Neither constitutes evidence of a blind evaluator until separately executed and measured.
