#!/usr/bin/env python3
"""elr_batch_get.py -- ELR batch reads over an EXPLICIT ID list.

Spec: DOC-F2CF625B7556 AC-6 (ENC-TSK-O52). Mitigates the ENC-ISS-558
undercount class, where a caller mistook a paginated/limited LIST
response for a complete answer. elr_batch_get NEVER calls a list, scan,
search, or query route -- it only ever issues one entity-specific
per-record GET per ID, so there is no server-side page/limit that can
silently drop rows. What each caller gets back is therefore an honest
LOWER BOUND on what exists (an ID that 404s might still exist under a
different type/project than guessed -- it is reported failed, never
silently skipped), not a "complete" answer the way a list call implies.

Two entity families are supported, dispatched purely from ID shape:

  ENC-TSK-*, ENC-ISS-*, ENC-FTR-*, ENC-PLN-*, ENC-LSN-*
      -> tracker per-record GET: GET /{project_id}/{record_type}/{id}
         on the tracker API (mirrors server.py's _tracker_get, which
         calls _tracker_api_request("GET", f"/{project_id}/{record_type}/{rid}")
         after resolving project_id/record_type from the ID via
         _parse_record_id / _ID_SEGMENT_TO_TYPE).

  DOC-*
      -> document GET *metadata only* (include_content=false): GET
         /{document_id}?include_content=false on the document API
         (mirrors server.py's _documents_get, which builds
         query={"include_content": "false"} and never unwraps the
         response -- the document record IS the response body).

Anything else (unknown project prefix, unknown type segment, malformed
shape) is never guessed at -- it is reported as "unclassified" in the
digest and no network call is made for it.

Usage:
    python3 tools/elr/elr_batch_get.py --ids "ENC-TSK-1,DOC-ABCDEF123456"
    python3 tools/elr/elr_batch_get.py --ids-file ids.txt --timeout 10
    python3 tools/elr/elr_batch_get.py --ids "ENC-TSK-1" --json

Exit code is 0 only when every requested ID was classified AND fetched
successfully; 1 otherwise (any failure or unclassified ID).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Allow running this file directly (python3 tools/elr/elr_batch_get.py)
# without requiring tools/elr to already be on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from elr_lib.config import get_profile  # noqa: E402
from elr_lib.digest import build_digest  # noqa: E402
from elr_lib.transport import InternalClient, classify_internal_posture  # noqa: E402

# --- ID classification ------------------------------------------------------
# Record-ID -> DynamoDB-key mapping mirrored from server.py's
# _ID_SEGMENT_TO_TYPE (server.py line ~709). Kept as a local literal (not
# imported from server.py) because ELR must run standalone, stdlib-only,
# on any workstation -- it never imports the Lambda handler module.
_TRACKER_TYPE_BY_SEGMENT: Dict[str, str] = {
    "TSK": "task",
    "ISS": "issue",
    "FTR": "feature",
    "PLN": "plan",
    "LSN": "lesson",
}

# Project-prefix -> project_id. server.py resolves this dynamically via
# the projects LIST API (_resolve_prefix -> _get_prefix_map, which calls
# _projects_api_request("GET") with no id -- a list route). elr_batch_get
# deliberately does NOT do that: the HARD RULE for this tool is that it
# never constructs a list/scan/query route, only entity-specific per-ID
# GETs. So the one prefix this tool currently classifies as tracker-kind
# (ENC) is a static literal, not a live lookup. Any other prefix -- even
# one that *would* resolve via the projects API -- falls through to
# "unclassified" rather than triggering a list call to find out.
_PREFIX_TO_PROJECT_ID: Dict[str, str] = {
    "ENC": "enceladus",
}

_TRACKER_ID_RE = re.compile(
    r"^(?P<prefix>[A-Z]{2,8})-(?P<type_seg>TSK|ISS|FTR|PLN|LSN)-(?P<suffix>[A-Z0-9]+(?:-[A-Z0-9]{1,4})?)$"
)
_DOCUMENT_ID_RE = re.compile(r"^DOC-[A-Z0-9]+$")

KIND_TRACKER = "tracker"
KIND_DOCUMENT = "document"
KIND_UNCLASSIFIED = "unclassified"


@dataclass(frozen=True)
class ClassifiedId:
    raw: str
    normalized: str
    kind: str
    project_id: Optional[str] = None
    record_type: Optional[str] = None


def classify_id(raw_id: str) -> ClassifiedId:
    """Classify one ID by prefix/shape. Never guesses: an ID whose prefix
    or type segment isn't recognized comes back KIND_UNCLASSIFIED and is
    never sent over the network.
    """
    normalized = str(raw_id).strip().upper()

    if _DOCUMENT_ID_RE.match(normalized):
        return ClassifiedId(raw=raw_id, normalized=normalized, kind=KIND_DOCUMENT)

    match = _TRACKER_ID_RE.match(normalized)
    if match:
        type_seg = match.group("type_seg")
        prefix = match.group("prefix")
        record_type = _TRACKER_TYPE_BY_SEGMENT.get(type_seg)
        project_id = _PREFIX_TO_PROJECT_ID.get(prefix)
        if record_type and project_id:
            return ClassifiedId(
                raw=raw_id,
                normalized=normalized,
                kind=KIND_TRACKER,
                project_id=project_id,
                record_type=record_type,
            )

    return ClassifiedId(raw=raw_id, normalized=normalized, kind=KIND_UNCLASSIFIED)


# --- Route builders (entity-specific GET only -- see HARD RULE) ------------

_FORBIDDEN_ROUTE_TOKENS = ("list", "scan", "query", "search")


def _assert_not_a_list_route(path: str) -> str:
    """Defense in depth for the HARD RULE: never call any list/scan/query
    endpoint, only entity-specific per-record GETs. Every path this module
    builds is asserted here before it is ever handed to the transport.
    """
    lowered = path.lower()
    for token in _FORBIDDEN_ROUTE_TOKENS:
        if token in lowered:
            raise AssertionError(
                f"elr_batch_get built a route containing forbidden token {token!r}: {path!r}. "
                "elr_batch_get.py must ONLY construct entity-specific per-record GET paths."
            )
    return path


def tracker_path(project_id: str, record_type: str, record_id: str) -> str:
    """GET /{project_id}/{record_type}/{record_id} -- one specific record.
    Never a bare "/{project_id}/{record_type}" (that would be a list route).
    """
    if not project_id or not record_type or not record_id:
        raise ValueError("project_id, record_type, and record_id are all required")
    path = f"/{project_id}/{record_type}/{record_id}"
    return _assert_not_a_list_route(path)


def document_path(document_id: str) -> str:
    """GET /{document_id} -- one specific document (metadata query is
    attached separately via include_content=false, not via this path).
    """
    if not document_id:
        raise ValueError("document_id is required")
    path = f"/{urllib.parse.quote(document_id, safe='')}"
    return _assert_not_a_list_route(path)


# --- Digest row shaping ------------------------------------------------------

_TITLE_TRUNCATE_LIMIT = 60


def truncate_title(value: Any, limit: int = _TITLE_TRUNCATE_LIMIT) -> str:
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 0)] + "..."


@dataclass
class FetchOutcome:
    row: Dict[str, Any]
    anomalies: List[str]
    posture: str
    http_status: int
    ok: bool
    # False only for unclassified_row(), where no network call was ever
    # attempted -- distinct from a network call that reached status 0
    # (unreachable), which DID attempt the network and so still counts
    # toward identity-posture aggregation below.
    attempted: bool = True


def fetch_tracker_row(client: InternalClient, classified: ClassifiedId) -> FetchOutcome:
    path = tracker_path(classified.project_id, classified.record_type, classified.normalized)
    status, body = client.request("GET", "tracker", path)
    key_sent = bool(client.config.key_for("tracker"))
    posture, posture_anomalies = classify_internal_posture(key_sent=key_sent, status_code=status)

    ok = 200 <= status < 300
    record: Dict[str, Any] = body.get("record", body) if isinstance(body, dict) else {}
    anomalies = [f"{classified.normalized}: {a}" for a in posture_anomalies]

    if isinstance(body, dict) and body.get("error"):
        ok = False

    if not ok:
        err = (body.get("error") if isinstance(body, dict) else None) or (
            record.get("error") if isinstance(record, dict) else None
        )
        detail = f" ({err})" if err else ""
        anomalies.append(f"{classified.normalized}: tracker_get_failed_http_{status}{detail}")

    row = {
        "id": classified.normalized,
        "kind": KIND_TRACKER,
        "ok": ok,
        "status_or_version": record.get("status") if ok else None,
        "title": truncate_title(record.get("title")) if ok else "",
    }
    return FetchOutcome(row=row, anomalies=anomalies, posture=posture, http_status=status, ok=ok)


def fetch_document_row(client: InternalClient, classified: ClassifiedId) -> FetchOutcome:
    path = document_path(classified.normalized)
    status, body = client.request("GET", "document", path, query={"include_content": "false"})
    key_sent = bool(client.config.key_for("document"))
    posture, posture_anomalies = classify_internal_posture(key_sent=key_sent, status_code=status)

    ok = 200 <= status < 300
    record: Dict[str, Any] = body if isinstance(body, dict) else {}
    anomalies = [f"{classified.normalized}: {a}" for a in posture_anomalies]

    if isinstance(body, dict) and body.get("error"):
        ok = False

    if not ok:
        err = record.get("error") if isinstance(record, dict) else None
        detail = f" ({err})" if err else ""
        anomalies.append(f"{classified.normalized}: document_get_failed_http_{status}{detail}")

    row = {
        "id": classified.normalized,
        "kind": KIND_DOCUMENT,
        "ok": ok,
        "status_or_version": record.get("version") if ok else None,
        "title": truncate_title(record.get("title")) if ok else "",
    }
    return FetchOutcome(row=row, anomalies=anomalies, posture=posture, http_status=status, ok=ok)


def unclassified_row(classified: ClassifiedId) -> FetchOutcome:
    row = {
        "id": classified.normalized,
        "kind": KIND_UNCLASSIFIED,
        "ok": False,
        "status_or_version": None,
        "title": "",
    }
    anomalies = [f"{classified.normalized}: unclassified_id_prefix"]
    # No network call was made, so there is no auth posture to report.
    return FetchOutcome(
        row=row, anomalies=anomalies, posture="unknown", http_status=0, ok=False, attempted=False
    )


# --- ID list loading ---------------------------------------------------------


def parse_ids_arg(value: str) -> List[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def load_ids_file(path: str) -> List[str]:
    text = Path(path).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


def collect_ids(ids_arg: Optional[str], ids_file_arg: Optional[str]) -> List[str]:
    ids: List[str] = []
    if ids_arg:
        ids.extend(parse_ids_arg(ids_arg))
    if ids_file_arg:
        ids.extend(load_ids_file(ids_file_arg))
    # De-dupe while preserving first-seen order -- a repeated ID should
    # only be fetched (and counted) once.
    seen = set()
    deduped: List[str] = []
    for raw_id in ids:
        key = raw_id.strip().upper()
        if key not in seen:
            seen.add(key)
            deduped.append(raw_id)
    return deduped


# --- Batch runner -------------------------------------------------------------


def _aggregate_posture(outcomes: List[FetchOutcome]) -> Tuple[str, List[str]]:
    """Roll up per-call identity postures into one digest-level posture.

    Any call that reported an unknown posture from an auth-shaped
    anomaly (401/403/unreachable/5xx) forces the whole batch to
    "unknown" -- an ambiguous identity signal on even one call means the
    batch as a whole cannot vouch for a single consistent posture.
    Otherwise, if every call that DID reach the network agrees on one
    posture, that posture is reported; a genuine split (e.g. tracker
    calls authenticated but document calls didn't) is also "unknown",
    flagged explicitly rather than papered over.
    """
    network_postures = [o.posture for o in outcomes if o.attempted]
    distinct = sorted(set(p for p in network_postures if p != "unknown"))
    saw_unknown = any(p == "unknown" for p in network_postures)

    if not network_postures:
        return "unknown", []
    if saw_unknown and not distinct:
        return "unknown", []
    if len(distinct) == 1 and not saw_unknown:
        return distinct[0], []
    if len(distinct) > 1:
        return "unknown", [f"mixed_identity_posture:{','.join(distinct)}"]
    # saw_unknown mixed with a single known posture
    return "unknown", [f"mixed_identity_posture:{','.join(distinct or ['unknown'])}"]


def run_batch_get(ids: List[str], profile_name: str, timeout: int) -> Dict[str, Any]:
    config = get_profile(profile_name)
    client = InternalClient(config, timeout=timeout)

    rows: List[Dict[str, Any]] = []
    anomalies: List[str] = []
    outcomes: List[FetchOutcome] = []

    fetched = 0
    failed = 0
    unclassified = 0

    for raw_id in ids:
        classified = classify_id(raw_id)

        if classified.kind == KIND_TRACKER:
            outcome = fetch_tracker_row(client, classified)
        elif classified.kind == KIND_DOCUMENT:
            outcome = fetch_document_row(client, classified)
        else:
            outcome = unclassified_row(classified)

        # Failures are partitioned per-ID: one bad ID never aborts the
        # loop or prevents the rest of the batch from being attempted.
        outcomes.append(outcome)
        rows.append(outcome.row)
        anomalies.extend(outcome.anomalies)

        if classified.kind == KIND_UNCLASSIFIED:
            unclassified += 1
        elif outcome.ok:
            fetched += 1
        else:
            failed += 1

    requested = len(ids)
    overall_ok = requested > 0 and failed == 0 and unclassified == 0 and fetched == requested

    totals = {
        "requested": requested,
        "fetched": fetched,
        "failed": failed,
        "unclassified": unclassified,
        # This tool only ever issues entity-specific per-ID GETs (never a
        # list/scan/query call), so these totals can only ever describe
        # the IDs the caller explicitly supplied -- they are a LOWER
        # BOUND on what exists, never a claim of completeness over the
        # full record space (that is precisely the ENC-ISS-558 class of
        # bug this tool exists to avoid).
        "lower_bound": True,
    }

    if requested == 0:
        overall_status: Any = 400
        anomalies.append("no_ids_supplied")
    elif overall_ok:
        overall_status = 200
    elif fetched == 0:
        overall_status = 502
    else:
        overall_status = 207  # partial success (Multi-Status)

    posture, posture_anomalies = _aggregate_posture(outcomes)
    anomalies.extend(posture_anomalies)

    return build_digest(
        "elr_batch_get.batch",
        overall_ok,
        overall_status,
        identity_posture=posture,
        anomalies=anomalies,
        counts=totals,
        rows=rows,
    )


# --- CLI ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    # ALL ELR CLIs must set allow_abbrev=False so partial/ambiguous flags
    # are never silently accepted (matches elr_smoke.py's contract).
    parser = argparse.ArgumentParser(
        prog="elr_batch_get",
        description=(
            "ELR batch reads over an explicit ID list -- one entity-specific "
            "per-record GET per ID (never list/scan/query), digest-only output."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--ids",
        default=None,
        help="Comma-separated list of record/document IDs, e.g. 'ENC-TSK-1,DOC-ABCDEF123456'.",
    )
    parser.add_argument(
        "--ids-file",
        default=None,
        help="Path to a file with one ID per line (blank lines and '#' comments ignored).",
    )
    parser.add_argument(
        "--profile",
        default="internal",
        choices=["internal"],
        help="ELR profile to use (only 'internal' supports batch reads).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Per-request timeout in seconds (default: 15).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the digest as a single compact JSON line (default: pretty-printed JSON).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    ids = collect_ids(args.ids, args.ids_file)

    digest = run_batch_get(ids, args.profile, args.timeout)

    if args.json:
        print(json.dumps(digest, sort_keys=True))
    else:
        print(json.dumps(digest, sort_keys=True, indent=2))

    return 0 if digest.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
