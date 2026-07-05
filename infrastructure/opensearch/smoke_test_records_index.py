#!/usr/bin/env python3
"""ENC-TSK-L40 AC-3 smoke test: indexes one sample record via records_write and
queries it back via records_read for exact-term, prefix/autocomplete, fuzzy,
and faceted-aggregation. Prints a JSON evidence blob suitable for
live_validation_evidence.

    ADMIN_PASSWORD="$(tr -d '\\n' < /root/.opensearch-admin-password)" \\
      python3 smoke_test_records_index.py
"""
import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

SAMPLE_DOC = {
    "project_id": "enceladus",
    "record_type": "task",
    "status": "open",
    "priority": "P1",
    "tags": ["search", "opensearch"],
    "title": "B67 Search2.0 OpenSearch smoke test record",
    "description": "Synthetic record used to verify records_v1 mappings and analyzers.",
    "body": "Exact term, prefix autocomplete, and fuzzy matching should all resolve this document.",
    "created_at": "2026-07-05T00:00:00Z",
    "updated_at": "2026-07-05T00:00:00Z",
    "version_seq": 1751673600000,
}


def _request(host, method, path, admin_password, body=None):
    url = f"{host}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    auth = base64.b64encode(f"admin:{admin_password}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="https://127.0.0.1:9200")
    parser.add_argument("--admin-password", default=os.environ.get("ADMIN_PASSWORD"))
    args = parser.parse_args()
    if not args.admin_password:
        print("ADMIN_PASSWORD env var or --admin-password required", file=sys.stderr)
        sys.exit(1)

    host, pw = args.host, args.admin_password
    evidence = {}

    status, resp = _request(host, "POST", "/records_write/_doc/smoke-l40-1?refresh=true", pw, SAMPLE_DOC)
    evidence["index"] = {"status": status, "result": resp.get("result", resp)}
    if status not in (200, 201):
        sys.exit(f"Index failed: {resp}")

    time.sleep(1)

    status, resp = _request(host, "GET", "/records_read/_search", pw, {"query": {"term": {"record_type": "task"}}})
    evidence["exact_term"] = {"status": status, "hits": resp.get("hits", {}).get("total", {})}

    status, resp = _request(
        host, "GET", "/records_read/_search", pw,
        {"query": {"multi_match": {"query": "smok", "type": "bool_prefix", "fields": ["title", "title._2gram", "title._3gram"]}}},
    )
    evidence["prefix_autocomplete"] = {"status": status, "hits": resp.get("hits", {}).get("total", {})}

    status, resp = _request(
        host, "GET", "/records_read/_search", pw,
        {"query": {"match": {"title": {"query": "smoke tset", "fuzziness": "AUTO"}}}},
    )
    evidence["fuzzy"] = {"status": status, "hits": resp.get("hits", {}).get("total", {})}

    status, resp = _request(
        host, "GET", "/records_read/_search", pw,
        {"size": 0, "aggs": {"by_status": {"terms": {"field": "status"}}, "by_priority": {"terms": {"field": "priority"}}}},
    )
    evidence["faceted_aggregation"] = {"status": status, "aggregations": resp.get("aggregations", {})}

    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
