#!/usr/bin/env python3
"""ENC-TSK-L40 — apply the records_v{n} index template + read/write aliases.

Idempotent: safe to re-run. Creates the versioned physical index if absent,
applies the index template (composable, pattern records_v*), and points
records_read / records_write aliases at it. Never creates or writes to a
bare "records" index/alias -- OpenSearch forbids an alias sharing a name
with a physical index (see README.md).

Run on the OpenSearch node itself (VPC/SSM-only reachable -- no public
ingress, see infrastructure/cloudformation/10-opensearch-node.yaml):

    ADMIN_PASSWORD="$(tr -d '\\n' < /root/.opensearch-admin-password)" \\
      python3 apply_records_index.py --version 1

Or via SSM send-command from an operator machine with AWS creds -- see
README.md for the exact invocation.
"""
import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

TEMPLATE_PATH = Path(__file__).parent / "index-templates" / "records-v1.json"
TEMPLATE_NAME = "records-index-template"


def _request(host, method, path, admin_password, body=None):
    url = f"{host}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    import base64

    auth = base64.b64encode(f"admin:{admin_password}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    def _parse(raw):
        # HEAD responses (and some error responses) have no body.
        if not raw:
            return {}
        return json.loads(raw)

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return resp.status, _parse(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _parse(exc.read())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", type=int, required=True, help="Physical index version n (records_v{n})")
    parser.add_argument("--host", default="https://127.0.0.1:9200")
    parser.add_argument("--admin-password", default=os.environ.get("ADMIN_PASSWORD"))
    args = parser.parse_args()

    if not args.admin_password:
        print("ADMIN_PASSWORD env var or --admin-password required", file=sys.stderr)
        sys.exit(1)

    index_name = f"records_v{args.version}"
    template_body = json.loads(TEMPLATE_PATH.read_text())

    status, resp = _request(args.host, "PUT", f"/_index_template/{TEMPLATE_NAME}", args.admin_password, template_body)
    print(f"[template] PUT /_index_template/{TEMPLATE_NAME} -> {status} {resp}")
    if status not in (200, 201):
        sys.exit(f"Failed to apply index template: {resp}")

    status, resp = _request(args.host, "HEAD", f"/{index_name}", args.admin_password)
    if status == 200:
        print(f"[index] {index_name} already exists, skipping create")
    else:
        status, resp = _request(args.host, "PUT", f"/{index_name}", args.admin_password)
        print(f"[index] PUT /{index_name} -> {status} {resp}")
        if status not in (200, 201):
            sys.exit(f"Failed to create index {index_name}: {resp}")

    alias_actions = {
        "actions": [
            {"add": {"index": index_name, "alias": "records_read"}},
            {"add": {"index": index_name, "alias": "records_write", "is_write_index": True}},
        ]
    }
    status, resp = _request(args.host, "POST", "/_aliases", args.admin_password, alias_actions)
    print(f"[aliases] POST /_aliases -> {status} {resp}")
    if status not in (200, 201):
        sys.exit(f"Failed to apply aliases: {resp}")

    print(f"records_read / records_write now point at {index_name}. Done.")


if __name__ == "__main__":
    main()
