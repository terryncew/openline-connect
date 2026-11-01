# Installed conformance result — machine-readable experimental profile

`openline-connect conformance --target 'python -m openline_connect.conformance_sample'`

The CLI prints one JSON object to stdout and exits **0 only if** all mandatory checks are true; otherwise it prints JSON `FAIL` and exits nonzero. The object has exactly these supported fields in this release candidate:

- `status`: string `PASS` or `FAIL`.
- `checks`: object with named Boolean properties describing a particular local simulator behavior. Every value must be `true` for PASS; the set is documented in `docs/NATIVE_CONFORMANCE.md`.
- `elapsed_seconds`: measured runtime of the conformance script (not installation or integration time).
- `limitations`: human-readable scope statement; do not scrape it as a security certificate.

Validation schema: [`conformance_result.schema.json`](conformance_result.schema.json). Machine-parse the JSON, require `status == 'PASS'`, `all(checks.values())`, and command exit code `0`. For a defective test target, require exit code **nonzero** and `status == 'FAIL'`. A failed probe does not identify physical effects outside the test controller; a malicious receiver may have unobserved side channels. Controller and supplier run under one host administrator. Nothing here certifies a third-party supplier, safety system, or production controller.

There is no ecosystem-standard certification protocol or signed external conformance badge in rc5.dev5.
