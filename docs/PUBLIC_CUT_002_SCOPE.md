# Rights-scoped development preview — CUT 002

**DEVELOPMENT PREVIEW — NOT PRODUCTION READY.** Publication requires founder approval of this exact reduced source hash. The presence of this file does not authorize publication.

Founder rights affirmation (2026-11-01): to the best of their knowledge and based on authorship and applicable permissions, permission to distribute the OpenLine Connect and Accept core, included contributions/examples/documentation under Apache-2.0. This is the founder's statement, **not** legal certification.

The complete optional `examples/robotics_sim/` directory (16 files) was removed from the full `rc5.dev5` candidate because its redistribution rights and attribution remain unestablished. Source and sdist both omit it; there are no robot hardware drivers. Other documentation that points at omitted files was corrected; production safety, interoperable robotics, and external-effect guarantees are not claimed.

Runtime `cryptography` and optional `fastapi`, `uvicorn`, and `mcp` are installed separately and not vendored; see `THIRD_PARTY_NOTICES.md` for incomplete direct dependency license summary. No assurance is provided about arbitrary transitive versions chosen by installers. Synthetic test key fixtures are for offline tests only.

The private PR132 original source and public older evaluation branch remain unchanged. The next published evaluation branch, if separately approved, is an experimental source branch, not a tag or update to main.
