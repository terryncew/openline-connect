# Source and ownership provenance (human review required)

Earlier developer preview `0.1.0rc5.dev3` was built from a pinned previously verified private candidate plus a deliberately scoped set of public additions. The inherited `src/openline_connect` and `src/openline_accept` security engines and their existing tests are byte-preserved **except** optional `fastapi_route.py` and the FastAPI app version metadata. The new public profile documentation and independent verifier were written for this candidate. The fictional robotics simulator is a copy of the previously preserved Robot Work Permit research source with receiver A, separately implemented receiver B, conventional reference and dishonest negative control. Do not interpret "independently implemented receiver B" as an independent external developer study.

The project contains `LICENSE` marked Apache License 2.0 and `NOTICE` plus `docs/THIRD_PARTY_NOTICES.md`. Direct runtime `cryptography` and optional FastAPI/uvicorn/MCP dependencies install separately; no dependency source is intentionally vendored. **The founder has affirmed, to the best of their knowledge, rights to distribute included Connect/Accept core and contributions under Apache-2.0; this is not an independent legal chain-of-title audit. The robotics simulator is excluded due to unresolved redistribution and attribution rights. Separately installed third-party dependencies retain their upstream licenses.** Only the founder/legal rights holder can sign off. Absence of an obvious secret or license scan failure does not establish intellectual-property rights. No publication is authorized by this file.


The PR129 candidate starts from the pinned exact PR128 public source SHA256 `dea08cf79bc0eee527dc3ddd36dfdec064a47024b81a508b09ae09db6ea7c9b9`. It changes only the optional FastAPI adapter, the local-fictional onboarding helper, example/tests/docs and version metadata. ConnectEngine core, Accept seller and private robotics controllers were carried unchanged in that historical PR129 candidate. This reduced cut omits all robotics simulation files.


## New private bounded-scope candidate rc5.dev5

The post-PR130 `0.1.0rc5.dev5` source is reassembled from a source
SHA256-pinned PR130 archive, with a consciously enumerated overlay.
Unlike the prior dev3 candidate, this experimental preview **changes
`src/openline_connect/engine.py` and `onboarding.py`** to implement
`bounded_scope_v1` with signed budget state. Existing Accept/simulator
security sources are otherwise unchanged. The original outsider report
and its three program files were unavailable for source-preserving review.
A founder rights affirmation for the Connect/Accept core has been received. No independent legal certification is claimed, and the excluded robotics code is not cleared. This exact reduced source hash requires a separate explicit founder publication approval.
