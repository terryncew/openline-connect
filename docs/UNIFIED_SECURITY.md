# Trust boundaries and release HOLD

* **Authority:** buyer signs exact order mandate; supplier pins buyer, AI provider, independent evidence issuer keys and policy; supplier alone decides and commits its local SQLite order and local business_jobs row.
* **SQL security:** Connect's SQLite authorizer enforces receiver-configured resolved tables/functions against trusted callbacks, default denies DDL, PRAGMA, transaction management, attach, unlisted objects. Never accept caller-provided arbitrary Python or unreviewed SQLite connections. A Python callback can still bypass the authorizer by accessing filesystem/network or importing sqlite3: outside boundary.
* **Expiry/revocation:** H-01 local Connect effect-time checks; after an already-committed fictional settlement, exact signed-request reconciliation may proceed even after mandate expiry without invoking a new effect; PR #90 Accept policy `revoked` mandates and configured provider key replacement; no universal worker epoch protocol between the two engines. Revocation affects future *admissions*, not in-flight external work.
* **Recovery:** `AcceptClient.recover_worker(...)` calls `POST /v1/worker-recover`; the seller checks buyer-signed exact original-order delegation, Worker B signature, active policy sequence and pinned worker key before returning the original signed decision/outcome without another synthetic SQLite effect. Operator `reconcile` remains separately admin-scoped. A timeout without validated recovery remains UNKNOWN; recovery does not undo an external effect.
* **Digital effects:** only local transactional row insertion is atomic. Accept's signed outcome attests local DB work. Without separate independently controlled journal, it is NOT independent evidence of external delivery.
* **Installed native conformance:** `openline-connect conformance --target "python -m openline_connect.conformance_sample"` runs 12 local supplier-initiated admission checks against a separate fictional controller process and signed journal. `conformance_defective` is a must-fail negative control. This is a packaged bounded test, not third-party certification, universal interop or observed physical effects.
* **Robotics:** PR #122 research is excluded from this preview pending redistribution rights. No ROS 2, PLC, E-stop, robot-driver code or robot-safety claims are shipped.
* **Licensing:** Connect Apache-2.0 and Accept source from the private workspace; confirm chain of title, contributor/contractor obligations, declared dependency attribution and licensing consistency before public distribution. The included Apache-2.0 LICENSE does not itself prove those rights.
* **MCP:** optional module source retains an experimental stdio path. No independently verified official MCP SDK handshake for this candidate; do not advertise supported MCP.

## Finishing Gate 002 scope

`POST /v1/worker-recover` is **not** the seller operator's admin endpoint.
The successor sends a buyer-signed scoped delegation, a worker-signed proof
and the original PO hash; the real PR90 Accept seller checks current policy
sequence and active worker key before disclosing the original signed receipt.
Recovery executes no business handler. It applies only to **already committed**
synthetic SQLite orders, not external deliveries or settlements.

For custom `effect_sql.tables`, Connect signs both the original `records` digest
and `application_tables_snapshot_sha256` along with table names. Offline
verification with `verify_records=True` recomputes all explicitly listed
application table rows. This is a SQLite snapshot claim; it does not prove an
external side effect or defend against a privileged same-process Python callback.

`openline-connect conformance` starts an independent controller subprocess,
validates that the vendor explicitly calls its admission entrypoint and
compares the controller's signed receipt against its own journal. Both processes
still have the same host OS administrator. Noncontroller side effects remain
outside its observation. An attacker with the host admin or both private keys
is outside the demonstrated boundary. Conventional Ed25519/SQLite can match
these checks. No ROS 2 actual integration is claimed.
