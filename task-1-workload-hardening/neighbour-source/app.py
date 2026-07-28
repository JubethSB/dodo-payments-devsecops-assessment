"""reporting — neighbour service for ledger-api.

Fetches transaction records from ledger-api and serves an aggregated summary.

Security note, and the reason this service exists in this shape:
ledger-api's GET /transactions returns full PANs in cleartext. This service
deliberately does NOT propagate them — it aggregates by currency/status and
exposes only counts and totals. That is data minimisation: the reporting
consumer has no business need for card numbers, so the PAN never leaves the
service that already holds it. It also keeps `reporting` out of PCI CDE scope,
which is the point Task 3 returns to when drawing the mesh boundary.
"""
import os

import requests
from flask import Flask, jsonify

app = Flask(__name__)

LEDGER_API_URL = os.environ.get("LEDGER_API_URL", "http://ledger-api:8080")
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT_SECONDS", "3"))


@app.route("/health")
def health():
    """Liveness/readiness endpoint.

    Intentionally does NOT check ledger-api reachability. A dependency being
    down must not make this pod fail its liveness probe and restart — that
    turns one service's outage into a cascading restart storm across the
    namespace. Dependency health belongs in /ready-style business checks or
    metrics, not in the probe that decides whether to kill the process.
    """
    return jsonify(status="ok")


@app.route("/summary")
def summary():
    """Aggregate ledger transactions without exposing PANs."""
    try:
        resp = requests.get(
            LEDGER_API_URL + "/transactions", timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        records = resp.json().get("transactions", [])
    except requests.RequestException as exc:
        # Fail closed with a generic message. The upstream error string could
        # carry internal hostnames or ports; surfacing it to a caller is a
        # small information-disclosure leak.
        app.logger.warning("upstream ledger-api call failed: %s", exc)
        return jsonify(error="upstream_unavailable"), 503

    summary_by_currency = {}
    for record in records:
        currency = record.get("currency", "UNKNOWN")
        bucket = summary_by_currency.setdefault(
            currency, {"count": 0, "total_amount": 0, "statuses": {}}
        )
        bucket["count"] += 1
        bucket["total_amount"] += record.get("amount", 0)
        status = record.get("status", "unknown")
        bucket["statuses"][status] = bucket["statuses"].get(status, 0) + 1

    # Note what is absent: no `pan`, no `id`. Only aggregates.
    return jsonify(currencies=summary_by_currency, record_count=len(records))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
