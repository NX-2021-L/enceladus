#!/usr/bin/env python3
"""elr_batch_get.py -- ELR batch reads over an EXPLICIT ID list.

Spec: DOC-F2CF625B7556 AC-6 (ENC-TSK-O52). Mitigates the ENC-ISS-558
undercount class, where a caller mistook a paginated/limited LIST
response for a complete answer. elr_batch_get NEVER calls a list, scan,
search, or query route -- it only ever issues one entity-specific
per-record GET per ID, so there is no server-side page/limit that can
silently drop rows. What each caller gets back is therefore an honest
LOWER BOUND on what exists (an ID that 404s is reported not_found,
never silently skipped), not a "complete" answer the way a list call
implies.

Two entity families are supported, dispatched purely from ID shape:

  <PREFIX>-TSK-*, <PREFIX>-ISS-*, <PREFIX>-FTR-*, <PREFIX>-PLN-*, <PREFIX>-LSN-*
      -> tracker per-record GET on the project-agnostic SENTINEL route
         (ENC-TSK-Q10 / ENC-ISS-791): GET /_/{record_type}/{id} on the
         tracker API. The reserved project segment "_" (PROJECT_SENTINEL)
         tells the server to derive the owning project from the record
         id's prefix via the projects table. ELR holds ZERO prefix ->
         project knowledge: any prefix is sent as-is and the server is
         the only authority on whether it resolves. The TYPE segment
         (TSK/ISS/FTR/PLN/LSN -> task/issue/...) is still mapped locally
         (_TRACKER_TYPE_BY_SEGMENT) -- that is type knowledge, not
         project knowledge.

  DOC-*
      -> document GET *metadata only* (include_content=false): GET
         /{document_id}?include_content=false on the document API
         (mirrors server.py's _documents_get, which builds
         query={"include_content": "false"} and never unwraps the
         response -- the document record IS the response body).

Anything else (unknown type segment, malformed shape) is reported as
kind "unsupported" (outcome "error", anomaly unsupported_id_shape) and
no network call is made for it.

Per-id outcome contract (every row carries ``outcome`` and ``http_status``):

  found      2xx with a record body                          (ok=True)
  not_found  HTTP 404 -- the id does not resolve on this plane (unknown
             prefix or unknown record). Reported, never an anomaly.
  forbidden  HTTP 401/403 (auth posture anomalies attached)
  error      everything else: 5xx (after the transport's one GET retry),
             transport failure (status 0), an unexpected status, a 2xx
             body carrying "error", an unsupported id shape, or a 404
             from a plane that predates the sentinel route ("Project '_'
             is not registered" -> anomaly
             sentinel_route_unsupported_by_server).

Usage:
    python3 tools/elr/elr_batch_get.py --ids "ENC-TSK-1,INT-TSK-4,DOC-ABCDEF123456"
    python3 tools/elr/elr_batch_get.py --ids-file ids.txt --timeout 10
    python3 tools/elr/elr_batch_get.py --ids "ENC-TSK-1" --json

Exit code is 0 only when every requested ID came back "found"; 1
otherwise (any not_found / forbidden / error / unsupported id).
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

from elr_lib import profiles as elr_profiles  # noqa: E402
from elr_lib.config import get_profile  # noqa: E402
from elr_lib.digest import build_digest  # noqa: E402
from elr_lib.transport import InternalClient, classify_internal_posture  # noqa: E402

# --- Sentinel project segment ------------------------------------------------

# Reserved project segment of the tracker API (ENC-TSK-Q10 / ENC-ISS-791).
# GET-only: GET /{PROJECT_SENTINEL}/{record_type}/{record_id} asks the
# server to derive the owning project from the record id itself (its
# prefix, looked up in the projects table server-side). A batch read
# never sends a real project id -- ELR has none to send.
PROJECT_SENTINEL = "_"

# A plane that predates the sentinel route treats "_" as an ordinary
# (unregistered) project name and answers 404 with this text. ELR must
# distinguish that from a genuine not_found -- it is a client/server
# version skew, reported as outcome "error" with its own anomaly.
_SENTINEL_UNSUPPORTED_MARKER = "project '_'"
ANOMALY_SENTINEL_UNSUPPORTED = "sentinel_route_unsupported_by_server"

# --- ID classification ------------------------------------------------------
# Record-ID type segment -> tracker record_type, mirrored from server.py's
# _ID_SEGMENT_TO_TYPE. Kept as a local literal (not imported from
# server.py) because ELR must run standalone, stdlib-only, on any
# workstation -- it never imports the Lambda handler module. This is TYPE
# knowledge (which table a TSK/ISS/... id lives in), not PROJECT knowledge.
_TRACKER_TYPE_BY_SEGMENT: Dict[str, str] = {
    "TSK": "task",
    "ISS": "issue",
    "FTR": "feature",
    "PLN": "plan",
    "LSN": "lesson",
}

# Project resolution history: pre-ENC-TSK-P90 this module carried a static
# prefix->project literal ({"ENC": "enceladus"}); ENC-TSK-P90 replaced it
# with a live resolver class in elr_lib/prefix.py (network -> local file
# cache -> built-in seed), which ENC-ISS-791 ruled a design defect because it
# silently degraded to ENC-only. ENC-TSK-Q10 removed prefix->project
# resolution from ELR entirely: the server resolves the project from the
# record id via the sentinel route (PROJECT_SENTINEL above), and ELR holds
# zero prefix/project knowledge. Any [A-Z]{2,8} prefix is accepted here
# and sent as-is; the server alone decides whether it resolves.
_TRACKER_ID_RE = re.compile(
    r"^(?P<prefix>[A-Z]{2,8})-(?P<type_seg>TSK|ISS|FTR|PLN|LSN)-(?P<suffix>[A-Z0-9]+(?:-[A-Z0-9]{1,4})?)$"
)
_DOCUMENT_ID_RE = re.compile(r"^DOC-[A-Z0-9]+$")

KIND_TRACKER = "tracker"
KIND_DOCUMENT = "document"
KIND_UNSUPPORTED = "unsupported"

OUTCOME_FOUND = "found"
OUTCOME_NOT_FOUND = "not_found"
OUTCOME_FORBIDDEN = "forbidden"
OUTCOME_ERROR = "error"
VALID_OUTCOMES: Tuple[str, ...] = (OUTCOME_FOUND, OUTCOME_NOT_FOUND, OUTCOME_FORBIDDEN, OUTCOME_ERROR)


@dataclass(frozen=True)
class ClassifiedId:
    raw: str
    normalized: str
    kind: str
    # Always None: ELR never knows (or guesses) a record's project. It is
    # kept on the dataclass so callers can see, explicitly, that nothing
    # client-side ever fills it in -- the digest row's project_id is the
    # SERVER-reported value from a found record, never this field.
    project_id: Optional[str] = None
    record_type: Optional[str] = None


def classify_id(raw_id: str) -> ClassifiedId:
    """Classify one ID purely by SHAPE. Never guesses a project: an id
    that matches the tracker shape (PREFIX-TSK|ISS|FTR|PLN|LSN-suffix)
    is KIND_TRACKER for ANY prefix, with project_id=None -- the server
    resolves the project on the sentinel route. A DOC-* id is
    KIND_DOCUMENT. Anything else (unknown type segment, garbage, empty)
    is KIND_UNSUPPORTED and is never sent over the network.
    """
    normalized = str(raw_id).strip().upper()

    if _DOCUMENT_ID_RE.match(normalized):
        return ClassifiedId(raw=raw_id, normalized=normalized, kind=KIND_DOCUMENT)

    match = _TRACKER_ID_RE.match(normalized)
    if match:
        record_type = _TRACKER_TYPE_BY_SEGMENT.get(match.group("type_seg"))
        if record_type:
            return ClassifiedId(
                raw=raw_id,
                normalized=normalized,
                kind=KIND_TRACKER,
                project_id=None,
                record_type=record_type,
            )

    return ClassifiedId(raw=raw_id, normalized=normalized, kind=KIND_UNSUPPORTED)


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


def tracker_path(record_type: str, record_id: str) -> str:
    """GET /_/{record_type}/{record_id} -- one specific record on the
    project-agnostic sentinel route (ENC-TSK-Q10). The project segment is
    always the literal PROJECT_SENTINEL; the record id is sent verbatim
    and the server derives the owning project from it. Never a bare
    "/_/{record_type}" (that would be a list route).
    """
    if not record_type or not record_id:
        raise ValueError("record_type and record_id are both required")
    path = f"/{PROJECT_SENTINEL}/{record_type}/{record_id}"
    return _assert_not_a_list_route(path)


def document_path(document_id: str) -> str:
    """GET /{document_id} -- one specific document (metadata query is
    attached separately via include_content=false, not via this path).
    """
    if not document_id:
        raise ValueError("document_id is required")
    path = f"/{urllib.parse.quote(document_id, safe='')}"
    return _assert_not_a_list_route(path)


# --- Per-id outcome classification -----------------------------------------


def _error_detail(body: Any, record: Any) -> str:
    """The short error string a failed response carried (for the anomaly
    detail suffix). Never the whole body."""
    err = None
    if isinstance(body, dict):
        err = body.get("error")
    if not err and isinstance(record, dict):
        err = record.get("error")
    return str(err) if err else ""


def _sentinel_error_text(body: Any) -> str:
    """Every place a server might put the 'Project '_' is not registered'
    text: the top-level error string and the error_envelope message."""
    if not isinstance(body, dict):
        return ""
    parts: List[str] = []
    if body.get("error"):
        parts.append(str(body["error"]))
    envelope = body.get("error_envelope")
    if isinstance(envelope, dict):
        for key in ("message", "detail"):
            if envelope.get(key):
                parts.append(str(envelope[key]))
    return " | ".join(parts)


def is_sentinel_unsupported(status: int, body: Any) -> bool:
    """True when a 404 is really 'this plane does not know the sentinel
    route' (its error text names Project '_'), which is a version skew
    between ELR and the server, not a missing record."""
    if status != 404:
        return False
    return _SENTINEL_UNSUPPORTED_MARKER in _sentinel_error_text(body).lower()


def classify_outcome(status: int, body: Any) -> str:
    """Map one per-record GET result onto the four-valued outcome contract
    (see module docstring). A 2xx whose body carries "error" is an error,
    not a find; a 404 that names Project '_' is an error, not a miss.
    """
    if 200 <= status < 300:
        if isinstance(body, dict) and body.get("error"):
            return OUTCOME_ERROR
        return OUTCOME_FOUND
    if status == 404:
        return OUTCOME_ERROR if is_sentinel_unsupported(status, body) else OUTCOME_NOT_FOUND
    if status in (401, 403):
        return OUTCOME_FORBIDDEN
    return OUTCOME_ERROR


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
    outcome: str = OUTCOME_ERROR
    # False only for unsupported_row(), where no network call was ever
    # attempted -- distinct from a network call that reached status 0
    # (unreachable), which DID attempt the network and so still counts
    # toward identity-posture aggregation below.
    attempted: bool = True


def _build_outcome(
    classified: ClassifiedId,
    kind: str,
    *,
    key_sent: bool,
    status: Any,
    body: Any,
    record: Dict[str, Any],
    version_key: str,
    failure_label: str,
) -> FetchOutcome:
    """Shared tail of fetch_tracker_row / fetch_document_row: classify the
    outcome, attach exactly the anomalies the contract calls for, and
    project the compact row."""
    # The transport reports a non-int sentinel status (elr_lib.tls
    # TLS_UNRESOLVED_STATUS) when it refused to attempt the handshake at
    # all; for the outcome contract that is a transport failure (0) whose
    # body already carries the remediation text as "error".
    http_status = status if isinstance(status, int) else 0
    posture, posture_anomalies = classify_internal_posture(key_sent=key_sent, status_code=http_status)
    outcome = classify_outcome(http_status, body)
    ok = outcome == OUTCOME_FOUND

    anomalies: List[str] = []
    if outcome == OUTCOME_NOT_FOUND:
        # A 404 is a plain, reportable answer ("this id does not resolve
        # on this plane") -- it counts against overall ok via the
        # not_found total, but it is never an anomaly. It also came back
        # through the same authenticated, routed path a 2xx would have
        # (an auth failure is 401/403, not 404), so it carries the same
        # identity posture as a find rather than the transport's generic
        # "unknown" for an unexpected status -- otherwise one missing
        # record would poison the whole batch's posture.
        posture = "internal-key" if key_sent else "server-held-keys"
    elif outcome == OUTCOME_ERROR and is_sentinel_unsupported(http_status, body):
        # Version skew, not a missing record: one specific anomaly, and
        # not the generic failed-http-404 one.
        anomalies.append(f"{classified.normalized}: {ANOMALY_SENTINEL_UNSUPPORTED}")
    elif not ok:
        anomalies.extend(f"{classified.normalized}: {a}" for a in posture_anomalies)
        err = _error_detail(body, record)
        detail = f" ({err})" if err else ""
        anomalies.append(f"{classified.normalized}: {failure_label}_http_{http_status}{detail}")

    row = {
        "id": classified.normalized,
        "kind": kind,
        "ok": ok,
        "outcome": outcome,
        "http_status": http_status,
        # SERVER-reported owning project of a found record -- the only
        # place a project id ever appears in this module's output.
        "project_id": record.get("project_id") if ok else None,
        "status_or_version": record.get(version_key) if ok else None,
        "title": truncate_title(record.get("title")) if ok else "",
    }
    return FetchOutcome(
        row=row, anomalies=anomalies, posture=posture, http_status=http_status, ok=ok, outcome=outcome
    )


def fetch_tracker_row(client: InternalClient, classified: ClassifiedId) -> FetchOutcome:
    path = tracker_path(classified.record_type, classified.normalized)
    status, body = client.request("GET", "tracker", path)
    key_sent = bool(client.config.key_for("tracker"))
    record: Dict[str, Any] = body.get("record", body) if isinstance(body, dict) else {}
    if not isinstance(record, dict):
        record = {}
    return _build_outcome(
        classified,
        KIND_TRACKER,
        key_sent=key_sent,
        status=status,
        body=body,
        record=record,
        version_key="status",
        failure_label="tracker_get_failed",
    )


def fetch_document_row(client: InternalClient, classified: ClassifiedId) -> FetchOutcome:
    path = document_path(classified.normalized)
    status, body = client.request("GET", "document", path, query={"include_content": "false"})
    key_sent = bool(client.config.key_for("document"))
    record: Dict[str, Any] = body if isinstance(body, dict) else {}
    return _build_outcome(
        classified,
        KIND_DOCUMENT,
        key_sent=key_sent,
        status=status,
        body=body,
        record=record,
        version_key="version",
        failure_label="document_get_failed",
    )


def unsupported_row(classified: ClassifiedId) -> FetchOutcome:
    row = {
        "id": classified.normalized,
        "kind": KIND_UNSUPPORTED,
        "ok": False,
        "outcome": OUTCOME_ERROR,
        "http_status": 0,
        "project_id": None,
        "status_or_version": None,
        "title": "",
    }
    anomalies = [f"{classified.normalized}: unsupported_id_shape"]
    # No network call was made, so there is no auth posture to report.
    return FetchOutcome(
        row=row,
        anomalies=anomalies,
        posture="unknown",
        http_status=0,
        ok=False,
        outcome=OUTCOME_ERROR,
        attempted=False,
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


def run_batch_get(ids: List[str], environment_profile_name: str, timeout: int) -> Dict[str, Any]:
    # ENC-TSK-P77: `environment_profile_name` is the "prod"/"v4-gamma"
    # ENVIRONMENT profile (elr_lib.profiles) coming from --profile; the
    # TRANSPORT profile is always "internal" here (the only one batch
    # reads support), so it's passed through as the literal string.
    config = get_profile("internal", environment_profile_name=environment_profile_name)
    client = InternalClient(config, timeout=timeout)

    rows: List[Dict[str, Any]] = []
    anomalies: List[str] = []
    outcomes: List[FetchOutcome] = []

    fetched = 0
    not_found = 0
    failed = 0

    for raw_id in ids:
        classified = classify_id(raw_id)

        if classified.kind == KIND_TRACKER:
            outcome = fetch_tracker_row(client, classified)
        elif classified.kind == KIND_DOCUMENT:
            outcome = fetch_document_row(client, classified)
        else:
            outcome = unsupported_row(classified)

        # Failures are partitioned per-ID: one bad ID never aborts the
        # loop or prevents the rest of the batch from being attempted.
        outcomes.append(outcome)
        rows.append(outcome.row)
        anomalies.extend(outcome.anomalies)

        if outcome.outcome == OUTCOME_FOUND:
            fetched += 1
        elif outcome.outcome == OUTCOME_NOT_FOUND:
            not_found += 1
        else:
            # forbidden + error (including unsupported ids)
            failed += 1

    requested = len(ids)
    overall_ok = requested > 0 and fetched == requested

    totals = {
        "requested": requested,
        "fetched": fetched,
        "failed": failed,
        "not_found": not_found,
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
        default=elr_profiles.PROFILE_PROD,
        choices=list(elr_profiles.VALID_ENVIRONMENT_PROFILES),
        help=(
            "ELR ENVIRONMENT profile (ENC-TSK-P77) -- which deployed "
            "Enceladus environment to read from (default: prod; "
            "ENCELADUS_PROFILE env var also selects this). Batch reads "
            "always use the 'internal' transport."
        ),
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
