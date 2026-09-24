#!/usr/bin/env python3
"""tools/docstore_race_harness.py — ENC-TSK-P70 AC-5 race harness (FR-B1-9..12).

Launches N concurrent PATCH writers against a document_api base URL, all
carrying the SAME If-Match content-hash precondition against a freshly-created
scratch document, and asserts that exactly one writer gets HTTP 200 and the
rest get HTTP 412 CONTENT_HASH_MISMATCH — proving the AC-3 atomic conditional
write (single DynamoDB UpdateItem with ConditionExpression content_hash =
:expected) is race-safe under real concurrency, not just in a mocked unit
test. Repeats for --trials consecutive trials (default 100), each against a
brand-new scratch document so trials don't interfere with each other.

stdlib-only: urllib, threading, json, argparse (plus os/sys/time for glue) —
no requests/boto3 dependency, so it runs from any Python 3.x without the
Lambda's own deps installed.

The internal API key is read from env ENCELADUS_COORDINATION_INTERNAL_API_KEY
and is never printed, logged, or included in the JSON summary.

Usage:
    export ENCELADUS_COORDINATION_INTERNAL_API_KEY=<key>
    python3 tools/docstore_race_harness.py \\
        --base-url https://enceladus-gamma.jreese.net/api/v1/documents \\
        --project-id enceladus --trials 100

    python3 tools/docstore_race_harness.py --base-url ... --writers 3 --trials 100

Prints a single compact JSON summary line to stdout and exits 0 if every
trial matched the expected (1 success, writers-1 failures) split, else 1.

Note (ENC-TSK-P70 brief): this script is not run against gamma from this
session — the code it exercises is not deployed yet. The coordinator runs it
post-deploy.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

ENV_KEY_NAME = "ENCELADUS_COORDINATION_INTERNAL_API_KEY"
SCRATCH_TITLE_PREFIX = "SCRATCH ENC-TSK-P70"


def _request(
    method: str,
    url: str,
    api_key: str,
    body: Optional[Dict[str, Any]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
    timeout: float = 15.0,
) -> Tuple[int, Dict[str, Any]]:
    """Minimal urllib JSON request helper. Returns (status_code, parsed_json).

    status_code is 0 on a transport-level failure (DNS, connection refused,
    timeout) — the caller treats that as "not 200 and not 412" (i.e. a trial
    failure), never as a silent pass.
    """
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-Coordination-Internal-Key", api_key)
    req.add_header("Content-Type", "application/json")
    for key, value in (extra_headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.getcode()
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    except urllib.error.URLError as exc:
        return 0, {"_transport_error": str(exc.reason)}
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except (ValueError, UnicodeDecodeError):
        parsed = {"_unparseable_body": True}
    return status, parsed


def create_scratch_document(base_url: str, api_key: str, project_id: str) -> Tuple[str, str]:
    """Creates a fresh scratch document (title prefix 'SCRATCH ENC-TSK-P70') and
    returns (document_id, content_hash) read from the create response."""
    title = f"{SCRATCH_TITLE_PREFIX} {int(time.time() * 1000)}"
    status, body = _request(
        "PUT",
        base_url,
        api_key,
        body={
            "project_id": project_id,
            "title": title,
            "content": "# Scratch\n\nENC-TSK-P70 race harness seed content.",
            "document_subtype": "doc",
        },
    )
    if status not in (200, 201):
        raise RuntimeError(f"scratch document create failed: status={status} body={body}")
    document_id = body.get("document_id")
    content_hash = body.get("content_hash")
    if not document_id or not content_hash:
        raise RuntimeError(f"scratch document create response missing fields: {body}")
    return str(document_id), str(content_hash)


def run_trial(
    base_url: str, api_key: str, document_id: str, if_match: str, writers: int,
) -> List[int]:
    """Fires `writers` concurrent PATCH requests carrying the same If-Match value
    at a single scratch document, released together via a Barrier to maximize
    race pressure. Returns the list of HTTP status codes observed (index-aligned
    to writer number, not completion order)."""
    url = f"{base_url.rstrip('/')}/{document_id}"
    results: List[int] = [0] * writers
    barrier = threading.Barrier(writers)

    def _writer(idx: int) -> None:
        barrier.wait()
        status, _body = _request(
            "PATCH",
            url,
            api_key,
            body={"content": f"# Scratch\n\nWriter {idx} @ {time.time()!r}."},
            extra_headers={"If-Match": if_match},
        )
        results[idx] = status

    threads = [threading.Thread(target=_writer, args=(i,)) for i in range(writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return results


def evaluate_trial(statuses: List[int], writers: int) -> bool:
    """AC-5: exactly one 200 and (writers - 1) 412s, nothing else."""
    success_count = sum(1 for s in statuses if s == 200)
    failure_count = sum(1 for s in statuses if s == 412)
    other_count = len(statuses) - success_count - failure_count
    return success_count == 1 and failure_count == (writers - 1) and other_count == 0


def run_harness(base_url: str, project_id: str, trials: int, writers: int, api_key: str) -> Dict[str, Any]:
    trial_records: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    for trial_idx in range(trials):
        try:
            document_id, content_hash = create_scratch_document(base_url, api_key, project_id)
        except Exception as exc:  # noqa: BLE001
            failures.append({"trial": trial_idx, "error": f"setup failed: {exc}"})
            continue
        statuses = run_trial(base_url, api_key, document_id, content_hash, writers)
        ok = evaluate_trial(statuses, writers)
        trial_records.append({"trial": trial_idx, "statuses": statuses, "ok": ok})
        if not ok:
            failures.append({"trial": trial_idx, "statuses": statuses, "document_id": document_id})

    return {
        "base_url": base_url,
        "writers": writers,
        "trials_requested": trials,
        "trials_run": len(trial_records),
        "trials_passed": sum(1 for t in trial_records if t["ok"]),
        "trials_failed": len(failures),
        "expected_per_trial": {"success": 1, "failure_412": writers - 1},
        "all_passed": len(failures) == 0 and len(trial_records) == trials,
        "failures": failures[:10],
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ENC-TSK-P70 docstore If-Match race harness")
    parser.add_argument(
        "--base-url", required=True,
        help="documents API base URL, e.g. https://enceladus-gamma.jreese.net/api/v1/documents",
    )
    parser.add_argument("--project-id", default="enceladus")
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--writers", type=int, default=2)
    args = parser.parse_args(argv)

    if args.writers < 2:
        print(json.dumps({"error": "--writers must be >= 2", "trials_run": 0}))
        return 1

    api_key = os.environ.get(ENV_KEY_NAME, "")
    if not api_key:
        print(json.dumps({"error": f"{ENV_KEY_NAME} not set", "trials_run": 0}))
        return 1

    summary = run_harness(args.base_url, args.project_id, args.trials, args.writers, api_key)
    print(json.dumps(summary))
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
