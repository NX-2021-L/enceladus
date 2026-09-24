#!/usr/bin/env python3
"""ENC-ISS-543: repair stale Neo4j node ``status`` vs canonical DynamoDB.

Scans tracker rows (read-only), compares canonical ``status`` to
graph_query_api keyword hits, and for mismatches issues a governed PATCH
touch (re-set ``updated_at`` note) so graph_sync re-projects the node.

Requires TRACKER_API_KEY (X-Coordination-Internal-Key) in the environment.

Usage:
    export TRACKER_API_KEY=...
    python3 tools/graph_status_drift_reconcile.py \\
        --tracker-table devops-project-tracker-gamma \\
        --base-url https://enceladus-gamma.jreese.net/api/v1 \\
        --apply
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Any, Dict, Optional

import boto3
import requests

REGION = "us-west-2"
PROJECTABLE_TYPES = ("task", "issue", "feature", "plan", "lesson")


def _make_session() -> requests.Session:
    key = os.environ.get("TRACKER_API_KEY", "")
    if not key:
        print("[ERROR] TRACKER_API_KEY not set", file=sys.stderr)
        sys.exit(1)
    session = requests.Session()
    session.headers.update({"X-Coordination-Internal-Key": key})
    return session


def _http(session: requests.Session, method: str, url: str, body: Optional[dict] = None):
    try:
        resp = session.request(method, url, json=body, timeout=30)
    except requests.RequestException as exc:
        return 0, {"error": str(exc)}
    try:
        return resp.status_code, resp.json()
    except ValueError:
        return resp.status_code, {}


def _bare_id(record_id: str) -> str:
    return record_id.split("#", 1)[-1] if "#" in record_id else record_id


def _graph_status(session: requests.Session, base_url: str, project_id: str, item_id: str) -> Optional[str]:
    code, body = _http(
        session,
        "GET",
        f"{base_url}/tracker/graphsearch",
        None,
    )
    # graphsearch is GET with query params
    try:
        resp = session.get(
            f"{base_url}/tracker/graphsearch",
            params={"project_id": project_id, "search_type": "keyword", "query": item_id, "limit": 5},
            timeout=30,
        )
        data = resp.json()
    except (requests.RequestException, ValueError):
        return None
    for node in data.get("nodes") or []:
        if node.get("record_id") == item_id:
            return str(node.get("status") or "").strip() or None
    return None


def _touch_record(session: requests.Session, base_url: str, project_id: str, record_type: str, item_id: str) -> bool:
    code, body = _http(
        session,
        "PATCH",
        f"{base_url}/tracker/{project_id}/{record_type}/{item_id}",
        {
            "field": "last_update_note",
            "value": "graph_status_drift_reconcile touch (ENC-ISS-543)",
            "write_source": {"provider": "graph_status_drift_reconcile", "channel": "tool"},
        },
    )
    return code in (200, 201) and body.get("success") is not False


def scan_table(table_name: str):
    ddb = boto3.resource("dynamodb", region_name=REGION)
    table = ddb.Table(table_name)
    kwargs: Dict[str, Any] = {}
    while True:
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            rid = str(item.get("record_id") or "")
            if rid.startswith("COUNTER-"):
                continue
            yield item
        last = resp.get("LastEvaluatedKey")
        if not last:
            break
        kwargs["ExclusiveStartKey"] = last


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconcile Neo4j status drift vs canonical DDB")
    parser.add_argument("--tracker-table", default="devops-project-tracker-gamma")
    parser.add_argument("--base-url", default="https://enceladus-gamma.jreese.net/api/v1")
    parser.add_argument("--project-id", default="enceladus")
    parser.add_argument("--apply", action="store_true", help="Issue PATCH touches for mismatches")
    parser.add_argument("--limit", type=int, default=0, help="Max mismatches to fix (0=all)")
    args = parser.parse_args()

    session = _make_session()
    mismatches = []
    scanned = 0

    for item in scan_table(args.tracker_table):
        record_type = str(item.get("record_type") or "").strip()
        if record_type not in PROJECTABLE_TYPES:
            continue
        item_id = _bare_id(str(item.get("record_id") or item.get("item_id") or ""))
        if not item_id:
            continue
        canonical_status = str(item.get("status") or "").strip()
        if not canonical_status:
            continue
        scanned += 1
        graph_st = _graph_status(session, args.base_url, args.project_id, item_id)
        if graph_st == canonical_status:
            continue
        mismatches.append((record_type, item_id, graph_st, canonical_status))
        print(f"[DRIFT] {item_id}: graph={graph_st!r} canonical={canonical_status!r}")

    print(f"[INFO] scanned={scanned} mismatches={len(mismatches)}")
    if not args.apply or not mismatches:
        return 0

    fixed = 0
    for record_type, item_id, _g, _c in mismatches:
        if args.limit and fixed >= args.limit:
            break
        if _touch_record(session, args.base_url, args.project_id, record_type, item_id):
            fixed += 1
            print(f"[FIX] touched {item_id}")
            time.sleep(0.2)
        else:
            print(f"[WARN] touch failed for {item_id}", file=sys.stderr)
    print(f"[INFO] touched={fixed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
