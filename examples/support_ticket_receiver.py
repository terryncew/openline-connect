"""Public-API-only local ticket receiver. One fictional SQLite assignment, no external work.

Run: python examples/support_ticket_receiver.py
Assumption: single local operator owns the fixture keys and DB. No real workforce access.
"""
import json
import sqlite3
import tempfile
from pathlib import Path

from openline_connect.engine import ProtectionError
from openline_connect.onboarding import initialize, allow, read_engine, verify_local


def run():
    with tempfile.TemporaryDirectory(prefix="thirdparty-tickets-") as temporary:
        root = Path(temporary)
        trust = initialize(root)
        policy = json.loads((root / "policy.json").read_text())
        policy["effect_sql"] = {"tables": ["ticket_assignments"], "functions": []}
        (root / "policy.json").write_text(json.dumps(policy))
        with sqlite3.connect(root / "connect.sqlite") as connection:
            connection.execute("CREATE TABLE ticket_assignments(ticket TEXT PRIMARY KEY, assignee TEXT NOT NULL)")
        params = {"target": "CASE-17", "ticket": "CASE-17", "assignee": "queue-b", "amount_cents": 0}
        grant = allow(root, action="tickets.assign", params=params, ttl_seconds=300)
        engine = read_engine(root)

        def assign(signed_params, connection):
            connection.execute(
                "INSERT INTO ticket_assignments(ticket,assignee) VALUES (?,?)",
                (signed_params["ticket"], signed_params["assignee"]),
            )
            return {"ticket": signed_params["ticket"], "assignee": signed_params["assignee"]}

        engine.register("tickets.assign", assign, max_amount_cents=0, atomic=True)
        request = json.loads(Path(grant["fictional_agent_request"]).read_text())
        admitted = engine.execute(**request)
        assert admitted["decision"] == "ALLOW", admitted
        same = engine.execute(**request)
        assert same.get("replayed") is True, same
        unauthorized = dict(request)
        unauthorized["params"] = {**params, "assignee": "queue-evil"}
        try:
            wrong = engine.execute(**unauthorized)
            refused = wrong.get("decision") != "ALLOW"
        except ProtectionError:
            refused = True
        assert refused, "parameter tamper unexpectedly accepted"
        verified = verify_local(root, seller_public=trust["seller_public"], verify_records=True)
        with sqlite3.connect(root / "connect.sqlite") as connection:
            rows = connection.execute("SELECT ticket,assignee FROM ticket_assignments").fetchall()
        assert rows == [("CASE-17", "queue-b")], rows
        assert verified["verified"] and verified["application_tables_match_signed_outcome"]
        return {"status": "PASS", "action": "tickets.assign", "authorized": admitted["decision"],
                "unauthorized_refused": refused, "replayed": same["replayed"],
                "committed_rows": len(rows), "signed_local_sqlite_verified": verified["verified"],
                "limitations": "fictional local DB; colocated fixture buyer key; no external effects"}


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
