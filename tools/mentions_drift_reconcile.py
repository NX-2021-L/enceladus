#!/usr/bin/env python3
"""ENC-TSK-L87: reconcile MENTIONS drift without direct Neo4j access.

Mirrors deploy_parity_validator._run_mentions_drift_audit's expected/actual
comparison exactly (same mentions_extraction.py helpers, same graphsearch
neighbors query shape), but:
  - scans the FULL corpus via DynamoDB (read-only) instead of a 100-row
    recent-mutations sample, and
  - for every genuinely divergent record, issues a real PATCH "touch"
    (re-set an existing field to its own current value) through the
    tracker/document HTTP API. This is a legitimate governed write that
    generates a real DynamoDB Stream MODIFY event; the direct
    EventSourceMapping (ENC-TSK-L85, gamma) or EventBridge Pipe (prod)
    picks it up and graph_sync (whose own IAM role has Neo4j access,
    unlike an operator's CLI identity in most deployments) re-runs
    _reconcile_edges / _reconcile_mentions_edges for that record for real.

Requires TRACKER_API_KEY (a valid X-Coordination-Internal-Key value) in the
environment -- never hardcode this. AWS credentials must have DynamoDB
read access to the target tracker/documents tables (no Neo4j secret access
needed).

Usage:
    export TRACKER_API_KEY=...
    python3 tools/mentions_drift_reconcile.py \
        --tracker-table devops-project-tracker-gamma \
        --documents-table documents-gamma \
        --base-url https://enceladus-gamma.jreese.net/api/v1 \
        --apply   # scan + fix; omit --apply for scan-only
"""
import argparse
import os
import sys
import time
from pathlib import Path

import boto3
import requests

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "backend" / "lambda" / "graph_sync"))
from mentions_extraction import MENTIONS_PROSE_FIELDS, extract_id_tokens, strip_code_fences  # noqa: E402

REGION = "us-west-2"


def _make_session():
    key = os.environ.get("TRACKER_API_KEY", "")
    if not key:
        print("[ERROR] TRACKER_API_KEY not set in environment", file=sys.stderr)
        sys.exit(1)
    session = requests.Session()
    session.headers.update({"X-Coordination-Internal-Key": key})
    return session


def _http(session, method, url, body=None):
    try:
        resp = session.request(method, url, json=body, timeout=20)
    except requests.RequestException as e:
        print(f"[WARN] request failed: {e}", file=sys.stderr)
        return 0, {}
    try:
        return resp.status_code, resp.json()
    except ValueError:
        return resp.status_code, {}


def scan_table(table_name):
    ddb = boto3.resource("dynamodb", region_name=REGION)
    table = ddb.Table(table_name)
    kwargs = {}
    while True:
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            rid = item.get("record_id", "")
            if isinstance(rid, str) and rid.startswith("COUNTER-"):
                continue
            yield item
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key


def expected_mentions(record_type, record_id, record):
    fields = MENTIONS_PROSE_FIELDS.get(record_type, ())
    expected = set()
    for field_name in fields:
        value = record.get(field_name, "")
        if not isinstance(value, str) or not value:
            continue
        tokens = extract_id_tokens(strip_code_fences(value))
        tokens.discard(record_id)
        expected |= tokens
    return expected


def current_mentions(session, graphsearch_url, record_id, project_id="enceladus"):
    qs = (f"?project_id={project_id}&search_type=neighbors&record_id={record_id}"
          f"&edge_types=MENTIONS&direction=outgoing&depth=1")
    status, body = _http(session, "GET", graphsearch_url + qs)
    if status != 200 or not isinstance(body, dict):
        return None
    targets = set()
    for edge in body.get("edges", []) or []:
        t = edge.get("target") or edge.get("to") or edge.get("target_id")
        if isinstance(t, str) and t:
            targets.add(t)
    if not targets:
        for node in body.get("nodes", []) or []:
            nid = node.get("record_id") or node.get("id")
            if isinstance(nid, str) and nid and nid != record_id:
                targets.add(nid)
    return targets


def touch_record(session, tracker_api_base, document_api_base, record_type,
                  record_id, project_id, last_description):
    """Re-PATCH an existing field to its own value to force a real MODIFY
    stream event, without changing any actual content."""
    if record_type == "document":
        url = f"{document_api_base}/{record_id}"
        return _http(session, "PATCH", url, {"description": last_description.get(record_id, "")})
    url = f"{tracker_api_base}/{project_id}/{record_type}/{record_id}"
    return _http(session, "PATCH", url, {
        "field": "mentions_reconciled_at",
        "value": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "write_source": {"provider": "mentions-drift-reconcile", "channel": "manual_reconcile"},
    })


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tracker-table", default="devops-project-tracker-gamma")
    ap.add_argument("--documents-table", default="documents-gamma")
    ap.add_argument("--base-url", default="https://enceladus-gamma.jreese.net/api/v1")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--limit", type=int, default=0, help="cap number of records touched (0=no cap)")
    args = ap.parse_args()

    session = _make_session()
    graphsearch_url = f"{args.base_url}/tracker/graphsearch"
    tracker_api_base = f"{args.base_url}/tracker"
    document_api_base = f"{args.base_url}/documents"

    print(f"[START] scanning {args.tracker_table} + {args.documents_table}", file=sys.stderr)
    records = []
    for item in scan_table(args.tracker_table):
        rt = item.get("record_type", "")
        if rt not in MENTIONS_PROSE_FIELDS:
            continue
        rid = item.get("item_id") or item.get("record_id", "").split("#", 1)[-1]
        records.append((rt, rid, item.get("project_id", "enceladus"), dict(item)))
    doc_count = 0
    last_description = {}
    for item in scan_table(args.documents_table):
        rid = item.get("document_id", "")
        if not rid:
            continue
        records.append(("document", rid, item.get("project_id", "enceladus"), dict(item)))
        last_description[rid] = item.get("description", "")
        doc_count += 1
    print(f"[INFO] loaded {len(records)} records ({doc_count} documents)", file=sys.stderr)

    divergent = []
    checked = 0
    for rt, rid, project_id, record in records:
        exp = expected_mentions(rt, rid, record)
        if not exp:
            continue
        cur = current_mentions(session, graphsearch_url, rid, project_id)
        checked += 1
        if cur is None:
            print(f"[WARN] graphsearch failed for {rid}, skipping", file=sys.stderr)
            continue
        missing = exp - cur
        extra = cur - exp
        if missing or extra:
            divergent.append((rt, rid, project_id, sorted(missing), sorted(extra)))
        if checked % 200 == 0:
            print(f"[INFO] checked {checked}/{len(records)}, {len(divergent)} divergent so far", file=sys.stderr)

    print(f"[RESULT] {len(divergent)} divergent / {checked} checked (records with any expected mentions)", file=sys.stderr)
    for rt, rid, pid, missing, extra in divergent[:20]:
        print(f"  {rid} ({rt}): missing={missing[:5]} extra={extra[:5]}", file=sys.stderr)

    if not args.apply:
        print("[END] scan-only mode, no writes made", file=sys.stderr)
        return

    to_touch = divergent if not args.limit else divergent[:args.limit]
    print(f"[START] reconciling {len(to_touch)} divergent records via governed PATCH touch", file=sys.stderr)
    ok = 0
    fail = 0
    for rt, rid, pid, missing, extra in to_touch:
        status, body = touch_record(session, tracker_api_base, document_api_base,
                                     rt, rid, pid, last_description)
        if status == 200:
            ok += 1
        else:
            fail += 1
            print(f"[ERROR] touch failed for {rid}: HTTP {status} {body}", file=sys.stderr)
        time.sleep(0.15)
    print(f"[END] reconcile complete: ok={ok} fail={fail}", file=sys.stderr)


if __name__ == "__main__":
    main()
