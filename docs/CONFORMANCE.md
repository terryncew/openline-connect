# Public release test and native-conformance contract

Run from the **exported source root** after `python -m pip install .`:

```sh
python -m unittest discover -s tests -q
python -O -m unittest discover -s tests -q
openline-connect conformance --target "python -m openline_connect.conformance_sample"
```

The exact export's GitHub private release CI #41259367261 executed **56/56** public tests in each mode with **zero skips**. Its inherited private gate #41259367271 executed **57/57** in each mode; the extra private-only test requires the deliberately unshipped controlled issue fixture. Run the commands yourself against the final exported commit; historical counts are not substitute proof.

**Negative control:** `openline-connect conformance --target "python -m openline_connect.conformance_defective"` must exit nonzero and emit JSON `"status": "FAIL"`. The honest native target must pass all **12** checks, exit 0, and emit `"status": "PASS"`. The receiver's signed SQLite rows alone are insufficient; the conformance controller's separately signed local journal is checked. This checks **fictional controller admissions** on one host, not independent security certification or external physical effects.

For scope, records, nonces, revocation, recovery and signed outcome evidence, see `docs/NATIVE_CONFORMANCE.md`, `docs/UNIFIED_EVIDENCE.md` and `docs/UNIFIED_SECURITY.md`. A competent conventional Ed25519/SQLite implementation can meet the same security properties; this suite does not establish a measured integration-speed advantage.
