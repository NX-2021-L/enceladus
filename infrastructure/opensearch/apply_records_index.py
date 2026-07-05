#!/usr/bin/env python3
"""ENC-TSK-L40 / L42 — apply the records_v{n} index template + read/write aliases.

Idempotent: safe to re-run.

Modes:
  bootstrap (default): apply template, create physical index if absent, point
      records_read / records_write aliases at it (initial provisioning).
  create-only: apply template + create physical index; do not touch aliases
      (use before backfilling records_v{n+1} during zero-downtime reindex).
  swap: atomically repoint records_read + records_write to records_v{n},
      optionally delete superseded physical indices (--delete-old).

Run on the OpenSearch node (see README.md).
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
READ_ALIAS = "records_read"
WRITE_ALIAS = "records_write"


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
        if not raw:
            return {}
        return json.loads(raw)

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return resp.status, _parse(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _parse(exc.read())


def _apply_template(host, admin_password):
    template_body = json.loads(TEMPLATE_PATH.read_text())
    status, resp = _request(host, "PUT", f"/_index_template/{TEMPLATE_NAME}", admin_password, template_body)
    print(f"[template] PUT /_index_template/{TEMPLATE_NAME} -> {status} {resp}")
    if status not in (200, 201):
        sys.exit(f"Failed to apply index template: {resp}")


def _ensure_physical_index(host, admin_password, index_name):
    status, _resp = _request(host, "HEAD", f"/{index_name}", admin_password)
    if status == 200:
        print(f"[index] {index_name} already exists, skipping create")
        return
    status, resp = _request(host, "PUT", f"/{index_name}", admin_password)
    print(f"[index] PUT /{index_name} -> {status} {resp}")
    if status not in (200, 201):
        sys.exit(f"Failed to create index {index_name}: {resp}")


def _bootstrap_aliases(host, admin_password, index_name):
    alias_actions = {
        "actions": [
            {"add": {"index": index_name, "alias": READ_ALIAS}},
            {"add": {"index": index_name, "alias": WRITE_ALIAS, "is_write_index": True}},
        ]
    }
    status, resp = _request(host, "POST", "/_aliases", admin_password, alias_actions)
    print(f"[aliases] POST /_aliases bootstrap -> {status} {resp}")
    if status not in (200, 201):
        sys.exit(f"Failed to apply aliases: {resp}")
    print(f"{READ_ALIAS} / {WRITE_ALIAS} now point at {index_name}.")


def _alias_indices(host, admin_password, alias):
    status, resp = _request(host, "GET", f"/_alias/{alias}", admin_password)
    if status != 200:
        return set()
    return set(resp.keys())


def _swap_aliases(host, admin_password, index_name, delete_old=False):
    read_indices = _alias_indices(host, admin_password, READ_ALIAS)
    write_indices = _alias_indices(host, admin_password, WRITE_ALIAS)
    old_indices = (read_indices | write_indices) - {index_name}
    actions = []
    for old in sorted(old_indices):
        actions.append({"remove": {"index": old, "alias": READ_ALIAS}})
        actions.append({"remove": {"index": old, "alias": WRITE_ALIAS}})
    actions.append({"add": {"index": index_name, "alias": READ_ALIAS}})
    actions.append({"add": {"index": index_name, "alias": WRITE_ALIAS, "is_write_index": True}})
    status, resp = _request(host, "POST", "/_aliases", admin_password, {"actions": actions})
    print(f"[aliases] POST /_aliases swap -> {status} {resp}")
    if status not in (200, 201):
        sys.exit(f"Failed to swap aliases: {resp}")
    print(f"{READ_ALIAS} / {WRITE_ALIAS} now point at {index_name}.")
    if delete_old:
        for old in sorted(old_indices):
            del_status, del_resp = _request(host, "DELETE", f"/{old}", admin_password)
            print(f"[index] DELETE /{old} -> {del_status} {del_resp}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", type=int, required=True, help="Physical index version n (records_v{n})")
    parser.add_argument(
        "--mode",
        choices=("bootstrap", "create-only", "swap"),
        default="bootstrap",
        help="bootstrap=create+alias (default); create-only=physical index only; swap=atomic alias repoint",
    )
    parser.add_argument(
        "--delete-old",
        action="store_true",
        help="With --mode swap, delete superseded physical indices after alias swap",
    )
    parser.add_argument("--host", default="https://127.0.0.1:9200")
    parser.add_argument("--admin-password", default=os.environ.get("ADMIN_PASSWORD"))
    args = parser.parse_args()

    if not args.admin_password:
        print("ADMIN_PASSWORD env var or --admin-password required", file=sys.stderr)
        sys.exit(1)

    index_name = f"records_v{args.version}"
    _apply_template(args.host, args.admin_password)
    _ensure_physical_index(args.host, args.admin_password, index_name)

    if args.mode == "create-only":
        print(f"[done] {index_name} ready for backfill (aliases unchanged).")
        return
    if args.mode == "swap":
        _swap_aliases(args.host, args.admin_password, index_name, delete_old=args.delete_old)
        print("Alias swap complete.")
        return

    _bootstrap_aliases(args.host, args.admin_password, index_name)
    print("Done.")


if __name__ == "__main__":
    main()
