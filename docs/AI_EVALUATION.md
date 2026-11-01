# Independent AI evaluation protocol — precommitted, not yet executed with a distinct agent

**Evaluation scope:** use only this exact `openline-connect` rc5.dev5 source and its installed package. This protocol does not authorize recruitment or external contact.

## Exposure boundary

Give the evaluator a read-only checkout containing exactly the public source files in this version, plus the standard prompt in root `AGENTS.md`. Exclude all private GitHub history, nonpublic Argon analysis, prior chat context, instructor replies, hidden test implementations, parent PRs and founder-owned unpublished reports. The evaluator needs its *own* model session or independent tool instance. The author operating a new local venv is **not** an independent coding-agent evaluation.

## Required receipts

Record `git rev-parse HEAD`, Python and cryptography versions, initial access/installed package paths, wheel/sdist SHA-256, commands with timestamps, model identity/version and start/end, changed code diff, lines added, config edits, test logs, command exit codes, conformance JSON (both honest and defective), original and recovered signed-receipt equality, SQLite-effect counts, and the conventional implementation. Separate elapsed tool/runtime from developer reasoning time and from a human user's time. Pin source and dependencies. Do not infer time to integrate from demo runtime.

## Task (copy verbatim)

> Examine this repository and determine whether OpenLine is useful for an existing AI-agent application. Install the package, integrate it into an independently written receiving service, demonstrate authorization and refusal, test worker succession and recovery, verify the signed outcome, run conformance, and compare the engineering effort against competent conventional alternatives. Report security limitations and unsupported claims.

No hints after task delivery; an evaluator may give a negative conclusion. Record all interventions as loss of blindness.

## Pass / partial / fail precommit

**AI-INTEGRATABLE PASS** only when an unfamiliar isolated agent (1) installs with no human correction, (2) independently writes or adapts a receiving operation that obeys explicit policy/table permissions, (3) refuses an unauthorized request, (4) validates recovery and original signed outcome, (5) runs machine-readable native conformance and catches the deliberately defective receiver, and (6) reports local/effect and protocol limits correctly. **PARTIAL** for a complete scripted installation without independent agent integration; **FAIL** for exploitable authorization bypass or unreproducible ordinary installation.

**AI-INDEPENDENT-EVALUATION PASS** requires independent session identity and transcript, no private exposure, complete measured work and defensible analysis; **PARTIAL** for some isolated evaluation but incomplete tasks; **FAIL** for claims based only on the author's own testing or fabricated feedback. Here no separate coding agent was available. **Unperformed: no independent PASS**.

**HUMAN-INTEGRATABLE PASS** requires a developer unfamiliar with OpenLine installing and integrating without founder intervention, verified by a full session; **PARTIAL** for working docs and tested packet only. Human cohort work remains authorization-gated.

**GITHUB-ISSUE-TO-AGENT VERIFIED** requires an authorized controlled issue assigned to a different coding agent, its reproduction and patch tests, and independent conclusion. A local issue draft with failing→passing tests but no agent assignment is **PARTIAL**, not verified.

## Ask Your AI questions

What does the software accomplish? What does it do more conveniently than established libraries? Can I integrate it **from this exact candidate today**? What is genuinely new? What remains unsupported? Support each claim with actual paths, executed commands and paired conventional results. Treat local controller receipt verification as different from proof of external effect. The recommendation must name a specific use case and state a falsifier.
