#!/usr/bin/env python3
"""ENC-TSK-P89 / AC-3: sweep for approved-or-failed-but-unapplied escalations
and re-drive them through the idempotent apply endpoint.

Finds every escalation with status in {approved, failed} AND applied_at unset
-- the ENC-ISS-759/ENC-ESC-105 stuck symptom: DynamoDB rejected the target
UpdateItem (either at approval time, leaving status=approved, or the applier
itself parked it at status=failed after the ValidationException), so the
decision landed but the target record never changed -- and, with --apply,
re-POSTs each one to the idempotent
POST /{project}/escalation/{id}/apply endpoint (which now accepts a retry
from status=failed as well as status=approved, per the failed->applying FSM
edge added in this same task).

Dry-run (default) only lists candidates; nothing is mutated until --apply
is passed. stdlib-only, no third-party deps.

Usage:
    python3 tools/escalation_redrive_sweep.py --base-url https://enceladus-gamma.jreese.net/api/v1/tracker
    python3 tools/escalation_redrive_sweep.py --base-url ... --apply
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

ENV_KEY_NAME = "ENCELADUS_COORDINATION_INTERNAL_API_KEY"


def _api_key() -> str:
    key = os.environ.get(ENV_KEY_NAME, "").strip()
    if not key:
        print(
            f"error: {ENV_KEY_NAME} is not set. Export it (without printing it) "
            "before running this sweep.",
            file=sys.stderr,
        )
        sys.exit(2)
    return key


def _request(url: str, api_key: str, method: str = "GET", body: bytes = None) -> tuple:
    """Returns (status_code, parsed_json_or_none, raw_text)."""
    req = urllib.request.Request(url, method=method, data=body)
    req.add_header("X-Coordination-Internal-Key", api_key)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            status = resp.getcode()
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        status = exc.code
    except urllib.error.URLError as exc:
        print(f"error: request to {url} failed: {exc}", file=sys.stderr)
        sys.exit(1)
    try:
        parsed = json.loads(raw) if raw else None
    except (ValueError, TypeError):
        parsed = None
    return status, parsed, raw


_REDRIVE_STATUSES = {"approved", "failed"}


def _candidates(base_url: str, project: str, api_key: str) -> list:
    """GET .../{project}/escalation/list?page_size=200 WITHOUT a status filter,
    walking next_cursor (bounded), then filter client-side to status in
    {approved, failed} AND applied_at empty/missing. Fetching unfiltered (one
    call) rather than one call per status keeps this a single pass over the
    list; either approach is fine, this just avoids paginating twice."""
    out = []
    cursor = None
    max_pages = 50
    for _ in range(max_pages):
        query = "page_size=200"
        if cursor:
            query += f"&next_cursor={urllib.parse.quote(cursor)}"
        url = f"{base_url}/{project}/escalation/list?{query}"
        status, parsed, raw = _request(url, api_key)
        if status != 200 or not isinstance(parsed, dict):
            print(f"error: list call failed (status={status}): {raw[:300]}", file=sys.stderr)
            sys.exit(1)
        for item in parsed.get("escalations", []):
            if item.get("status") in _REDRIVE_STATUSES and not item.get("applied_at"):
                out.append(item)
        cursor = parsed.get("next_cursor")
        if not cursor:
            break
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True,
                        help="e.g. https://enceladus-gamma.jreese.net/api/v1/tracker")
    parser.add_argument("--project", default="enceladus")
    parser.add_argument("--apply", action="store_true",
                        help="Actually POST the apply call. Default is dry-run.")
    args = parser.parse_args()

    api_key = _api_key()
    base_url = args.base_url.rstrip("/")

    candidates = _candidates(base_url, args.project, api_key)
    if not candidates:
        print("No approved-or-failed escalations with unset applied_at found.")
        return 0

    print(f"Found {len(candidates)} approved-or-failed escalation(s) with applied_at unset:")
    for item in candidates:
        esc_id = item.get("item_id", "?")
        target = item.get("target_record_id", "?")
        mutation_type = item.get("mutation_type", "?")
        esc_status = item.get("status", "?")
        decided_at = item.get("decided_at") or item.get("updated_at", "?")
        print(f"  {esc_id}  status={esc_status}  target={target}  "
              f"mutation_type={mutation_type}  decided_at={decided_at}")

        if args.apply:
            url = f"{base_url}/{args.project}/escalation/{esc_id}/apply"
            status, parsed, raw = _request(url, api_key, method="POST", body=b"{}")
            summary = json.dumps(parsed, default=str)[:300] if parsed is not None else raw[:300]
            print(f"    -> POST apply: HTTP {status}: {summary}")

    if not args.apply:
        print("\nDry-run only. Re-run with --apply to POST the apply call for each id above.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
