#!/usr/bin/env python3
"""Backfill first_checked_out_at / closed_at / closed_at_unknown onto historical tasks.

ENC-TSK-S96-0D (ENC-PLN-108 W1.4), DOC-5E1E205FA664 section 5.2 as amended by
ruling D-21, contract DOC-B8285D689DAC.

WHAT IT DOES
  1. Reads every task of a project through the governed tracker_mutation LIST route
     (GET /api/v1/tracker/{project}?type=task&fields=...). Read-only.
  2. Runs the history extractor (backend/lambda/tracker_mutation/lifecycle_backfill.py)
     over each task and prints a report:
       * proven and unknown close times, split by checked-out and never-checked-out
         tasks;
       * tasks with checkout_count = 0;
       * every discrepancy it refuses to paper over.
  3. With --apply (and only then) POSTs one request per task that needs a write to
     the governed route
       POST /api/v1/tracker/{project}/task/{id}/lifecycle-backfill
     which stamps the values as a MARKER write (write_kind = marker, no version_seq),
     set-if-absent. The request carries NO timestamp: the Lambda derives the value
     from the record's own history, so this script cannot invent or choose a date.

CREDENTIALS
  This script holds NO table credentials. It never builds a boto3 client, names a
  table, or reads an AWS key; the agent IAM user denies tracker-table access anyway
  (ENC-TSK-564). Its only secret is the tracker API's internal key, read from the
  environment, which is an HTTP credential for the governed route, not a table
  credential. The Lambda's own role performs the write.

DRY RUN IS THE DEFAULT. Nothing is written unless --apply is passed.

USAGE
    # Dry run (no writes) -- the report goes to io before any prod run (ruling D-21):
    ENCELADUS_COORDINATION_INTERNAL_API_KEY=... \\
      python3 tools/backfill_task_lifecycle_stamps.py --env gamma --project enceladus --dry-run

    # Apply (gamma first, then prod):
    python3 tools/backfill_task_lifecycle_stamps.py --env gamma --project enceladus --apply \\
      --run-id lbf-2026-11-19-gamma

KILL CRITERION 2 (DOC-5E1E205FA664 section 9)
  "If the backfill cannot be made consumer-neutral ... do not run it as ordinary
  writes." Consumer-neutrality has two halves, and this script can verify neither
  against a deployed environment: the W1.3 guards must be DEPLOYED in
  opensearch_indexer, governance_audit and convergence_telemetry, and the route
  must be deployed. --apply therefore refuses to run against prod without
  --confirm-preconditions, which is the operator asserting both.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

REPO = Path(__file__).resolve().parents[1]
_EXTRACTOR_PATH = REPO / "backend" / "lambda" / "tracker_mutation" / "lifecycle_backfill.py"


def _load_extractor():
    """Load the extractor by path, under a private name, without touching sys.path."""
    spec = importlib.util.spec_from_file_location("_lifecycle_backfill_tool", _EXTRACTOR_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


lb = _load_extractor()

BASE_URLS = {
    "prod": "https://enceladus.jreese.net/api/v1/tracker",
    "gamma": "https://enceladus-gamma.jreese.net/api/v1/tracker",
}
KEY_ENV_VARS = ("ENCELADUS_COORDINATION_INTERNAL_API_KEY", "COORDINATION_INTERNAL_API_KEY")
USER_AGENT = "enceladus-lifecycle-backfill/1"  # a bare urllib UA is blocked at the edge (Cloudflare 1010)

# Everything the extractor and the report need; nothing heavier is fetched.
LIST_FIELDS = (
    "record_id", "status", "history", "checkout_count", "closed_count",
    "first_checked_out_at", "closed_at", "closed_at_unknown",
)


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

class Client:
    """Thin HTTP client for the governed tracker route. Injectable for tests."""

    def __init__(self, base_url: str, api_key: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None,
                query: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, Any]]:
        url = f"{self.base_url}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            "X-Coordination-Internal-Key": self.api_key,
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw)
            except Exception:  # noqa: BLE001
                return exc.code, {"raw": raw.decode(errors="replace")}


def fetch_tasks(client: Any, project: str, page_size: int = 50,
                limit: int = 0) -> Iterator[Dict[str, Any]]:
    """Yield every task of ``project`` via the paginated list route. Fails loudly on any error page.

    A page that fails ends the run: a partial scan would make every count in the report a
    silent undercount (the ENC-ISS-558 class), so there is no skip-and-continue.
    """
    cursor = ""
    seen = 0
    while True:
        query = {"type": "task", "fields": ",".join(LIST_FIELDS), "page_size": str(page_size)}
        if cursor:
            query["next_cursor"] = cursor
        status, body = client.request("GET", f"/{project}", query=query)
        if status != 200 or not isinstance(body, dict) or not body.get("success", True):
            raise RuntimeError(f"list page failed for {project}: HTTP {status} {str(body)[:300]}")
        for rec in body.get("records") or []:
            rid = str(rec.get("record_id") or "")
            rec = dict(rec, record_id=rid.split("#", 1)[1] if rid.startswith("task#") else rid)
            yield rec
            seen += 1
            if limit and seen >= limit:
                return
        cursor = str(body.get("next_cursor") or "")
        if not cursor:
            return


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------

def _inc(d: Dict[str, int], k: str, n: int = 1) -> None:
    d[k] = d.get(k, 0) + n


def summarise(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Run the extractor over every record and bucket the outcome. Pure."""
    r: Dict[str, Any] = {
        "tasks_scanned": 0,
        "checked_out": 0,                 # checkout_count >= 1
        "never_checked_out": 0,           # checkout_count = 0 (or absent)
        "checkout_count_zero": 0,         # same population, named for AC-3 / criterion 17
        "first_checked_out_at": {"to_stamp": 0, "already_set": 0, "unprovable": 0,
                                 "never_checked_out_no_stamp": 0},
        "closed_tasks": 0,
        "close": {
            "checked_out": {"proven": 0, "unknown": 0, "already_set": 0, "already_unknown": 0,
                            "proven_but_unknown_marker_present": 0},
            "never_checked_out": {"proven": 0, "unknown": 0, "already_set": 0, "already_unknown": 0,
                                  "proven_but_unknown_marker_present": 0},
        },
        "unknown_reasons": {"checked_out": {}, "never_checked_out": {}},
        "proven_by_writer": {},
        "flags": {},
        "writes_planned": 0,
        "write_ids": [],
        "unprovable_checkout_ids": [],
        # D-31 audit sets, enumerated by id because a count cannot be checked:
        "count_zero_with_checkout_note_ids": [],   # stamped from history despite checkout_count 0
        "note_present_but_unstamped_ids": [],      # the ONLY exception to the restated criterion 17
    }
    for rec in records:
        plan = lb.plan_lifecycle_stamps(rec)
        r["tasks_scanned"] += 1
        side = "checked_out" if plan["checked_out"] else "never_checked_out"
        r[side] += 1
        if not plan["checked_out"]:
            r["checkout_count_zero"] += 1
        cc = plan["checkout_class"]
        fco = r["first_checked_out_at"]
        if cc == "stamped":
            fco["to_stamp"] += 1
        elif cc == "already_set":
            fco["already_set"] += 1
        elif cc == "never_checked_out":
            fco["never_checked_out_no_stamp"] += 1
        else:
            fco["unprovable"] += 1
            r["unprovable_checkout_ids"].append(str(rec.get("record_id")))
        if plan["close_class"] != "not_closed":
            r["closed_tasks"] += 1
            _inc(r["close"][side], plan["close_class"])
            if plan["close_class"] == "unknown":
                _inc(r["unknown_reasons"][side], plan["unknown_reason"])
            if plan["close_class"] == "proven":
                _inc(r["proven_by_writer"], plan["close_writer"])
        for f in plan["flags"]:
            _inc(r["flags"], f)
            if f == "checkout_note_but_count_zero":
                r["count_zero_with_checkout_note_ids"].append(str(rec.get("record_id")))
            elif f == "first_checkout_timestamp_unparsable":
                r["note_present_but_unstamped_ids"].append(str(rec.get("record_id")))
        if plan["set"]:
            r["writes_planned"] += 1
            r["write_ids"].append(str(rec.get("record_id")))
    return r


def criterion_17(report: Dict[str, Any]) -> Dict[str, Any]:
    """Would criterion 17's equality hold if every planned write landed?

    RESTATED by io's ruling D-31 (2026-11-19, "history wins"). The original form --
    "the tasks without first_checked_out_at are exactly the tasks with checkout_count
    of 0" -- was not testable against real history, because checkout_count arrived with
    ENC-TSK-F41 and was never backfilled: the first gamma dry run found 782 tasks with a
    recognisable checkout note and a zero count. The equality now reads:

        the tasks without first_checked_out_at are exactly the tasks whose history
        carries no recognisable first-checkout note.

    Under D-31 a task is stamped whenever history proves a first checkout, so the only
    way a task can carry a note and still lack the stamp is an unparsable timestamp on
    that note. That set is the exception, and it is enumerated by id rather than counted,
    so it can never be absorbed silently.
    """
    unparsable = report["flags"].get("first_checkout_timestamp_unparsable", 0)
    return {
        "holds": unparsable == 0,
        "basis": "D-31 history-wins restatement",
        "note_present_but_unstamped": unparsable,
        "note_present_but_unstamped_ids": list(report["note_present_but_unstamped_ids"]),
        # Audit figures, not exceptions: these ARE stamped under D-31.
        "count_zero_but_stamped_from_history": report["flags"].get("checkout_note_but_count_zero", 0),
        "count_positive_without_note": report["flags"].get("checkout_count_positive_but_no_checkout_note", 0),
    }


def render_report(report: Dict[str, Any], *, header: str = "DRY RUN") -> str:
    c = report["close"]
    both = lambda k: c["checked_out"][k] + c["never_checked_out"][k]  # noqa: E731
    f = report["first_checked_out_at"]
    lines = [
        f"Task lifecycle stamp backfill -- {header}",
        f"  extractor version {lb.EXTRACTOR_VERSION}; basis: {lb.BACKFILL_BASIS}",
        "",
        f"Tasks scanned: {report['tasks_scanned']}",
        f"  checked out (checkout_count >= 1):        {report['checked_out']}",
        f"  never checked out (checkout_count = 0):   {report['never_checked_out']}",
        f"  tasks with checkout_count = 0:            {report['checkout_count_zero']}  (stamped anyway when history proves it, D-31)",
        "",
        "first_checked_out_at",
        f"  to stamp (first checkout note proven):    {f['to_stamp']}",
        f"  already set (left as is):                 {f['already_set']}",
        f"  checked out but NOT provable (no stamp):  {f['unprovable']}",
        f"  no checkout note in history (no stamp):   {f['never_checked_out_no_stamp']}",
        f"  stamped from history despite count 0:     {report['flags'].get('checkout_note_but_count_zero', 0)}  (D-31)",
        "",
        f"Closed tasks: {report['closed_tasks']}",
        "                                   checked-out   never-checked-out   total",
    ]
    for label, key in (("close time PROVEN (closed_at)", "proven"),
                       ("close time UNKNOWN (marker)", "unknown"),
                       ("closed_at already set", "already_set"),
                       ("closed_at_unknown already set", "already_unknown"),
                       ("proven, but unknown-marker present", "proven_but_unknown_marker_present")):
        lines.append(f"  {label:<33}{c['checked_out'][key]:>8}{c['never_checked_out'][key]:>18}{both(key):>10}")
    for side in ("checked_out", "never_checked_out"):
        reasons = report["unknown_reasons"][side]
        if reasons:
            lines.append(f"  unknown reasons, {side.replace('_', '-')}: " +
                         ", ".join(f"{k}={v}" for k, v in sorted(reasons.items())))
    if report["proven_by_writer"]:
        lines.append("  proven by writer: " + ", ".join(
            f"{k}={v}" for k, v in sorted(report["proven_by_writer"].items())))
    if report["flags"]:
        lines += ["", "Discrepancies reported, not written over:"]
        lines += [f"  {k}: {v}" for k, v in sorted(report["flags"].items())]
    c17 = criterion_17(report)
    lines += [
        "",
        f"Criterion 17 equality after the run ({c17['basis']}): "
        f"{'HOLDS' if c17['holds'] else 'DOES NOT HOLD'} "
        f"(tasks with a checkout note left unstamped: {c17['note_present_but_unstamped']})",
        f"  stamped from history despite checkout_count 0: {c17['count_zero_but_stamped_from_history']} (D-31; audit, not an exception)",
        f"  positive count with no checkout note:          {c17['count_positive_without_note']} (left unstamped, D-21)",
        f"Writes planned: {report['writes_planned']} marker writes (write_kind=marker, no version_seq, set-if-absent)",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def apply_writes(client: Any, project: str, ids: List[str], run_id: str, *,
                 max_rps: float = 10.0, max_consecutive_errors: int = 5,
                 sleep: Callable[[float], None] = time.sleep) -> Dict[str, Any]:
    """POST one governed marker-write request per id. The body carries no timestamp.

    Throttled (``max_rps``): every write still invokes the three stream consumers whose guards
    drop it in code, so the invocations are spread rather than fired in one burst.
    """
    out: Dict[str, Any] = {"written": 0, "noop": 0, "failed": 0, "outcomes": {}, "failures": []}
    consecutive = 0
    gap = 1.0 / max_rps if max_rps > 0 else 0.0
    for rid in ids:
        status, body = 0, {}
        for attempt in range(3):
            status, body = client.request(
                "POST", f"/{project}/task/{rid}/lifecycle-backfill", {"backfill_run_id": run_id})
            retryable = status >= 500 or status == 429 or (
                status == 409 and (body.get("error_envelope") or {}).get("code") == "RECORD_CHANGED")
            if not retryable:
                break
            sleep(1.0 * (attempt + 1))
        if status == 200 and body.get("success"):
            consecutive = 0
            outcome = str(body.get("outcome"))
            _inc(out["outcomes"], outcome)
            out["written" if outcome == "written" else "noop"] += 1
        else:
            consecutive += 1
            out["failed"] += 1
            out["failures"].append({"record_id": rid, "status": status, "body": str(body)[:200]})
            if consecutive >= max_consecutive_errors:
                out["aborted"] = f"{consecutive} consecutive failures"
                break
        if gap:
            sleep(gap)
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None, client: Optional[Any] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--env", choices=sorted(BASE_URLS), required=True)
    ap.add_argument("--project", action="append", required=True,
                    help="project id; repeat for several (e.g. --project enceladus)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="report only (the default)")
    mode.add_argument("--apply", action="store_true", help="perform the marker writes")
    ap.add_argument("--run-id", default="", help="backfill_run_id stamped into closed_at_unknown markers")
    ap.add_argument("--base-url", default="", help="override the tracker API base URL")
    ap.add_argument("--page-size", type=int, default=50)
    ap.add_argument("--limit", type=int, default=0, help="stop after N tasks per project (testing)")
    ap.add_argument("--max-rps", type=float, default=10.0)
    ap.add_argument("--report-json", default="", help="also write the report as JSON to this path")
    ap.add_argument("--confirm-preconditions", action="store_true",
                    help="required for --apply on prod: the operator asserts that io reviewed the dry-run "
                         "report (ruling D-21) AND that the W1.3 projection-only guards are deployed in "
                         "opensearch_indexer, governance_audit and convergence_telemetry (kill criterion 2)")
    args = ap.parse_args(argv)

    if client is None:
        key = next((os.environ[v] for v in KEY_ENV_VARS if os.environ.get(v)), "")
        if not key:
            print(f"ERROR: set one of {', '.join(KEY_ENV_VARS)} (the tracker API internal key).", file=sys.stderr)
            return 2
        client = Client(args.base_url or BASE_URLS[args.env], key)

    if args.apply and args.env == "prod" and not args.confirm_preconditions:
        print("ERROR: --apply on prod needs --confirm-preconditions (see --help; kill criterion 2).",
              file=sys.stderr)
        return 2
    run_id = args.run_id or time.strftime("lbf-%Y%m%dT%H%M%SZ", time.gmtime())

    exit_code = 0
    for project in args.project:
        report = summarise(fetch_tasks(client, project, page_size=args.page_size, limit=args.limit))
        report["project"] = project
        report["env"] = args.env
        print(render_report(report, header=("APPLY" if args.apply else "DRY RUN") + f" [{args.env}/{project}]"))
        if args.apply:
            result = apply_writes(client, project, report["write_ids"], run_id, max_rps=args.max_rps)
            report["apply"] = result
            print(f"\nApply: written={result['written']} noop={result['noop']} failed={result['failed']}"
                  + (f" ABORTED: {result['aborted']}" if result.get("aborted") else ""))
            if result["failed"]:
                exit_code = 1
        if args.report_json:
            path = Path(args.report_json if len(args.project) == 1 else f"{args.report_json}.{project}")
            path.write_text(json.dumps({k: v for k, v in report.items() if k != "write_ids"}, indent=2,
                                       sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
