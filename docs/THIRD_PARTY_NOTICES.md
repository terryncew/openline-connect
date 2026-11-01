# Third-party dependencies — no source vendored

The OpenLine Connect package declares runtime dependency `cryptography>=38,<51` (cryptography project distributes under Apache-2.0 **OR** BSD-3-Clause). Optional extras in this project's `pyproject.toml` declare `mcp>=2,<3` (MIT), `fastapi>=0.115` (MIT), and `uvicorn>=0.30` (BSD-3-Clause). These packages and their transitive dependencies are **installed separately** by the user's package manager; their source code is not copied into this release archive.

The original authors retain their own copyrights and license rights. Inspect the licenses and notices shipped by the *actual dependency versions installed* before redistribution, bundling, or deployment; this list is informational and is not a complete transitive third-party license inventory. No x402 package dependency is declared by the `x402` optional extra in this exact release.

This document does not confer the project's Apache-2.0 copyright grant on third-party libraries. See project `LICENSE` and `NOTICE` for the separately licensed OpenLine source. No third-party cryptographic primitive is claimed as proprietary OpenLine invention.
