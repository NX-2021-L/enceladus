"""Pre-cutover baseline capture (ENC-TSK-N26 / BRD DOC-44230223DD1C Wave 3,
parent objective ENC-TSK-N08).

On-demand event mode for the rhythm_cycle Lambda -- invoked with
``{"tier": "baseline_capture"}`` and routed through the same TIER_HANDLERS
table as the scheduled beats (see lambda_function.py). Unlike the scheduled
tiers it has no TIER_PREDECESSOR entry and is never added to config.TIER_ORDER:
it is not part of the harmonic scheduling chain, it is a standalone,
independently-invocable capture. No EventBridge schedule resource is created
for it (code path only, per BRD Wave 3 -- schedulable later during the actual
baseline week).

Produces four artifact classes as a single Sense-adjacent artifact, written
via artifact_store's existing S3 conventions under artifact key class
"baseline" (timestamped + latest pointer, same shape as every other tier):

  1. percolation_export   -- copy of comp-percolation-monitor's latest
                              DynamoDB telemetry row (read-only; this Lambda
                              never writes to that table).
  2. retrieval_quality     -- a small fixed canonical query set (record-id
                              lookups + topic-string list-filters) run against
                              the tracker HTTP API, recording result ids and
                              per-query latency.
  3. lesson_citation_rate  -- lesson-record counts and a documented proxy
                              citation-rate formula from the same tracker API.
  4. corpus_invariants     -- N / M / mean degree / second moment / modularity
                              Q / hot-tier fraction, each either derived from
                              what's cheaply reachable or explicitly marked
                              "not computable from this surface".

Every step is independently guarded: a failure or an unreachable dependency
in any one of the four classes degrades to an honest "unavailable + reason"
sub-object rather than failing the whole run. Partial capture with honest
gaps beats a failed run -- BRD Wave 3: "the only v3 pre-cutover baseline that
will ever exist."

Invocation (on-demand; io/terminal-invoked only -- the enceladus-agent-cli
IAM role cannot invoke Lambdas, this is deliberately outside the agent CLI's
permission boundary):

    aws lambda invoke \\
        --function-name <rhythm-cycle-function-name> \\
        --payload '{"tier": "baseline_capture"}' \\
        --cli-binary-format raw-in-base64-out \\
        /tmp/baseline_capture_out.json

See README.md "Baseline capture (on-demand)" for the full runbook note.

Design note on the tracker HTTP read shape: this module uses
``{TRACKER_API_BASE}/records`` with ``project_id`` (and ``record_type``,
``status``, ``page_size``) as query params -- the shape ENC-TSK-N28 (#1016,
merged into v4/main just ahead of this branch) live-probed against gamma and
confirmed returns 200; the ``/{project}/records`` shape 404s there. An
earlier draft of this module used a path-based ``{TRACKER_API_BASE}/{project}``
shape inferred from reading tracker_mutation's route regexes statically --
that inference turned out to not match gamma's actual live routing (per
N28's probe), so it was replaced with the live-confirmed shape before this
PR was opened. There is no confirmed single-record GET-by-id endpoint, so
record-id queries in the retrieval-quality fixed-query run also go through
this same ``/records`` list-and-filter path rather than guessing at an
unverified single-record route.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List

import boto3

from artifact_store import write_artifact
from config import (
    GRAPH_QUERY_API_BASE,
    PERCOLATION_TABLE,
    PROJECT_ID,
    TRACKER_API_BASE,
)
from http_client import get_json

logger = logging.getLogger(__name__)

# Small fixed canonical query set for the retrieval-quality run (task AC-1 /
# artifact class 2). Deliberately cheap: a handful of record-id lookups plus
# topic-string list-filters, mixed across record types. Kept as module-level
# data (not derived at call time) so the same queries run every baseline
# capture -- comparability across captures is the point of "fixed".
FIXED_QUERY_SET: List[Dict[str, str]] = [
    {"kind": "record_id", "record_type": "plan", "value": "ENC-PLN-078"},
    {"kind": "record_id", "record_type": "task", "value": "ENC-TSK-N26"},
    {"kind": "record_id", "record_type": "task", "value": "ENC-TSK-N08"},
    {"kind": "topic", "record_type": "task", "value": "baseline capture"},
    {"kind": "topic", "record_type": "task", "value": "percolation"},
    {"kind": "topic", "record_type": "issue", "value": "gamma deploy"},
    {"kind": "topic", "record_type": "feature", "value": "governance"},
    {"kind": "topic", "record_type": "task", "value": "cutover"},
]

# Tracker record types scanned for the corpus-invariants N estimate, the
# lesson citation rate, and the retrieval-quality run. task|issue|feature|
# plan|lesson mirrors the vocabulary used elsewhere in this Lambda
# (tiers/sense.py, tiers/decide.py).
_RECORD_TYPES_FOR_CENSUS = ("task", "issue", "feature", "plan", "lesson")

_LIST_PAGE_SIZE = 200  # generous cap; tracker reads elsewhere in this Lambda use 1-100


def _decimalize_clean(value: Any) -> Any:
    """Recursively convert DynamoDB Decimal values to plain int/float for JSON."""
    if isinstance(value, Decimal):
        as_int = int(value)
        return as_int if as_int == value else float(value)
    if isinstance(value, dict):
        return {k: _decimalize_clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decimalize_clean(v) for v in value]
    return value


def _tracker_list(record_type: str, page_size: int = _LIST_PAGE_SIZE) -> Dict[str, Any]:
    """GET /records?project_id=&record_type=&page_size= -- the shape ENC-TSK-N28
    (#1016) live-probed against gamma and confirmed at 200 (see module
    docstring). Used for both list-filter queries and record-id lookups
    (client-side filtered from the returned page) since no single-record
    GET-by-id route has been confirmed live.
    """
    url = f"{TRACKER_API_BASE}/records"
    return get_json(url, {"project_id": PROJECT_ID, "record_type": record_type, "page_size": page_size})


# ---------------------------------------------------------------------------
# Artifact class 1: percolation telemetry export
# ---------------------------------------------------------------------------

def capture_percolation_export() -> Dict[str, Any]:
    """Copy comp-percolation-monitor's latest DynamoDB telemetry row.

    Read-only against PERCOLATION_TABLE (this Lambda never writes to it).
    A handful-of-rows table (one row per calendar day, pk=``date#YYYY-MM-DD``),
    so an unfiltered scan is cheap; we take the lexicographically-latest pk.
    """
    try:
        table = boto3.resource("dynamodb").Table(PERCOLATION_TABLE)
        resp = table.scan(Limit=100)
        items = resp.get("Items", [])
    except Exception as exc:
        return {
            "status": "unavailable",
            "reason": f"percolation telemetry table read failed: {exc}",
            "source_table": PERCOLATION_TABLE,
        }

    if not items:
        return {
            "status": "unavailable",
            "reason": f"no rows found in {PERCOLATION_TABLE}",
            "source_table": PERCOLATION_TABLE,
        }

    latest_raw = max(items, key=lambda r: str(r.get("pk", "")))
    latest = _decimalize_clean(latest_raw)
    return {
        "status": "ok",
        "source_table": PERCOLATION_TABLE,
        "row_pk": latest.get("pk"),
        "computed_at": latest.get("computed_at"),
        "exported_row": latest,
    }


# ---------------------------------------------------------------------------
# Artifact class 2: retrieval-quality fixed-query run
# ---------------------------------------------------------------------------

def _run_one_query(q: Dict[str, str]) -> Dict[str, Any]:
    """Both query kinds go through the same confirmed-live /records list
    endpoint: 'record_id' filters the returned page for an exact id match,
    'topic' does a substring match over title/description. Neither kind
    guesses at an unverified single-record GET route.
    """
    entry: Dict[str, Any] = {
        "kind": q["kind"],
        "query": q["value"],
        "record_type": q.get("record_type", ""),
    }
    started = time.perf_counter()
    try:
        body = _tracker_list(q.get("record_type", ""))
        records = body.get("records") or []
        entry["candidates_scanned"] = len(records)
        if q["kind"] == "record_id":
            target = q["value"].strip().upper()
            matches = [
                r.get("item_id") or r.get("record_id")
                for r in records
                if str(r.get("item_id") or r.get("record_id") or "").upper() == target
            ]
        else:  # topic
            needle = q["value"].lower()
            matches = [
                r.get("item_id") or r.get("record_id")
                for r in records
                if needle in f"{r.get('title', '')} {r.get('description', '')}".lower()
            ]
        entry["result_ids"] = [m for m in matches if m][:10]
        entry["found"] = bool(entry["result_ids"])
    except Exception as exc:
        entry["found"] = False
        entry["result_ids"] = []
        entry["error"] = str(exc)
    entry["latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
    return entry


def capture_retrieval_quality() -> Dict[str, Any]:
    """Run the fixed canonical query set against the tracker HTTP API."""
    if not TRACKER_API_BASE:
        return {
            "status": "unavailable",
            "reason": "TRACKER_API_BASE not configured in this Lambda's environment",
            "query_count": 0,
            "queries": [],
        }

    results = [_run_one_query(q) for q in FIXED_QUERY_SET]
    hit_count = sum(1 for r in results if r.get("found"))
    return {
        "status": "ok",
        "query_surface": (
            f"{TRACKER_API_BASE}/records?project_id=&record_type=&page_size= "
            "-- tracker HTTP API (both record-id and topic queries list-and-filter "
            "this same confirmed-live endpoint; ENC-TSK-N28 #1016)"
        ),
        "query_count": len(results),
        "hit_count": hit_count,
        "queries": results,
    }


# ---------------------------------------------------------------------------
# Artifact class 3: lesson citation rate
# ---------------------------------------------------------------------------

def capture_lesson_citation_rate() -> Dict[str, Any]:
    """Lesson counts + a documented proxy citation-rate formula.

    True inbound-citation counting (how often OTHER records cite a given
    lesson) would require a project-wide edge/relationship scan that isn't
    cheaply available from this Lambda's read surface. The proxy computed
    here instead counts, per lesson record, whether the lesson ITSELF carries
    any outbound related_task_ids/related_issue_ids/related_feature_ids cross
    references -- a lower-bound signal on lesson connectedness, not a true
    citation rate. The formula is recorded verbatim below so a later,
    graph-capable pass can replace it without ambiguity about what the number
    means.
    """
    if not TRACKER_API_BASE:
        return {
            "status": "unavailable",
            "reason": "TRACKER_API_BASE not configured in this Lambda's environment",
            "lesson_count": 0,
        }

    try:
        body = _tracker_list("lesson")
    except Exception as exc:
        return {"status": "unavailable", "reason": str(exc), "lesson_count": 0}

    lessons = body.get("records") or []
    lesson_count = len(lessons)
    cited = 0
    total_refs = 0
    for rec in lessons:
        refs: List[str] = []
        for field in ("related_task_ids", "related_issue_ids", "related_feature_ids"):
            refs.extend(rec.get(field) or [])
        if refs:
            cited += 1
            total_refs += len(refs)

    result: Dict[str, Any] = {
        "status": "ok",
        "lesson_count": lesson_count,
        "lessons_with_outbound_refs": cited,
        "proxy_citation_rate": round(cited / lesson_count, 4) if lesson_count else 0.0,
        "total_outbound_refs": total_refs,
        "formula": (
            "proxy_citation_rate = count(lesson records with >=1 outbound "
            "related_task_ids/related_issue_ids/related_feature_ids entry) / lesson_count. "
            "This is an outbound-reference proxy, NOT true inbound-citation rate "
            "(how often other records cite the lesson) -- that requires a "
            "project-wide relationship scan not cheaply available here."
        ),
    }
    if lesson_count >= _LIST_PAGE_SIZE:
        result["note"] = (
            f"lesson_count hit the {_LIST_PAGE_SIZE}-row page cap; true count may be higher "
            "(no next_cursor is followed by this cheap capture pass)"
        )
    return result


# ---------------------------------------------------------------------------
# Artifact class 4: corpus invariants
# ---------------------------------------------------------------------------

def capture_corpus_invariants(percolation_export: Dict[str, Any]) -> Dict[str, Any]:
    """N, M, mean degree, second moment, modularity Q, hot-tier fraction.

    M / mean degree / second moment are sourced from the SAME percolation
    telemetry row already captured as artifact class 1 (comp-percolation-monitor
    computes exactly these graph quantities nightly via graph_query_api
    adjacency reads) rather than re-paginating the whole graph a second time
    in this same run -- cheaper, and keeps the two artifact classes
    self-consistent by construction. N (governed record count) is a separate,
    independent read against the tracker API since it counts tracker records,
    not graph nodes.
    """
    invariants: Dict[str, Any] = {}

    # N: best-effort governed-record census via the tracker API. There is no
    # total-count field on this endpoint, so per-type page_size=200 result
    # lengths are an honest LOWER BOUND, not a true corpus census.
    if TRACKER_API_BASE:
        per_type: Dict[str, Any] = {}
        capped_types: List[str] = []
        try:
            for rtype in _RECORD_TYPES_FOR_CENSUS:
                body = _tracker_list(rtype)
                count = len(body.get("records") or [])
                per_type[rtype] = count
                if count >= _LIST_PAGE_SIZE:
                    capped_types.append(rtype)
            invariants["N_lower_bound_by_type"] = per_type
            invariants["N_lower_bound_total"] = sum(per_type.values())
            note = (
                "tracker HTTP API exposes no total-count field; figures are "
                f"page_size={_LIST_PAGE_SIZE} lower bounds, not a true census"
            )
            if capped_types:
                note += f"; types at the page cap (undercounted): {capped_types}"
            invariants["N_note"] = note
        except Exception as exc:
            invariants["N_lower_bound_by_type"] = None
            invariants["N_lower_bound_total"] = None
            invariants["N_note"] = f"tracker read failed: {exc}"
    else:
        invariants["N_lower_bound_by_type"] = None
        invariants["N_lower_bound_total"] = None
        invariants["N_note"] = "TRACKER_API_BASE not configured"

    # M, mean degree, second moment: reuse this run's percolation export.
    exported_row = (percolation_export or {}).get("exported_row") or {}
    if percolation_export.get("status") == "ok" and exported_row:
        invariants["M_edges"] = exported_row.get("edge_count")
        invariants["mean_degree"] = exported_row.get("mean_degree")
        invariants["second_moment_mean_degree_sq"] = exported_row.get("mean_degree_sq")
        invariants["graph_node_count"] = exported_row.get("node_count")
        invariants["graph_metrics_source"] = (
            f"comp-percolation-monitor row {percolation_export.get('row_pk')} "
            "(this same baseline run's artifact class 1, not re-fetched)"
        )
    else:
        invariants["M_edges"] = None
        invariants["mean_degree"] = None
        invariants["second_moment_mean_degree_sq"] = None
        invariants["graph_node_count"] = None
        invariants["graph_metrics_source"] = (
            "unavailable -- percolation telemetry export (artifact class 1) was itself "
            f"unavailable in this run: {percolation_export.get('reason', 'unknown')}"
        )

    invariants["modularity_Q"] = None
    invariants["modularity_Q_note"] = (
        "not computable from this surface -- modularity requires a community "
        "assignment (e.g. Louvain/Leiden) over the full adjacency, which this "
        "cheap baseline-capture pass does not run; graph_query_api has no "
        "search_type that returns one today"
    )

    invariants["hot_tier_fraction"] = None
    invariants["hot_tier_fraction_note"] = (
        "not computable from this surface -- 'hot-tier' (H record set) as used "
        "in graph_query_api/drift_telemetry.py is a wave-relative, "
        "embedding-derived concept requiring a wave-close event and Titan V2 "
        "embeddings; no such classification field is exposed on the tracker "
        "or graph read surfaces this Lambda can reach cheaply"
    )

    invariants["graph_query_api_configured"] = bool(GRAPH_QUERY_API_BASE)
    return invariants


# ---------------------------------------------------------------------------
# Entry point (routed as tier="baseline_capture" in lambda_function.py)
# ---------------------------------------------------------------------------

def run_baseline_capture() -> Dict[str, Any]:
    """Capture all four artifact classes and write one Sense-adjacent artifact.

    Returns the same shape as every other tier handler (dict merged with
    write_artifact's key info) so it flows through lambda_function.run_beat's
    existing timing/metrics/error-handling path unmodified.
    """
    logger.info("[START] baseline_capture: project=%s", PROJECT_ID)

    percolation_export = capture_percolation_export()
    retrieval_quality = capture_retrieval_quality()
    lesson_citation_rate = capture_lesson_citation_rate()
    corpus_invariants = capture_corpus_invariants(percolation_export)

    classes_ok = sum(
        1
        for c in (percolation_export, retrieval_quality, lesson_citation_rate)
        if c.get("status") == "ok"
    )

    snapshot: Dict[str, Any] = {
        "beat_type": "baseline_capture",
        "brd_ref": "DOC-44230223DD1C Wave 3 / ENC-TSK-N08 AC-3",
        "percolation_export": percolation_export,
        "retrieval_quality": retrieval_quality,
        "lesson_citation_rate": lesson_citation_rate,
        "corpus_invariants": corpus_invariants,
        "artifact_classes_ok": classes_ok,
        "artifact_classes_total": 3,  # corpus_invariants has no single ok/unavailable status
    }

    keys = write_artifact("baseline", snapshot, datetime.now(timezone.utc))
    snapshot.update(keys)
    logger.info(
        "[SUCCESS] baseline_capture wrote artifact key=%s classes_ok=%d/3",
        keys.get("latest_key"),
        classes_ok,
    )
    logger.info("[END] baseline_capture complete")
    return snapshot
