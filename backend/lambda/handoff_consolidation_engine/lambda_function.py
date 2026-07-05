"""Handoff Consolidation Engine (HCE) — ENC-TSK-C08 / ENC-FTR-064 / ENC-FTR-096.

Closes the gap between Enceladus's short-term memory (Handoff documents, the
episodic / hippocampal buffer) and its long-term knowledge (Lesson records, the
semantic store). A scheduled, adaptive-triggered Lambda that runs a full
scan-cluster-propose cycle against the Handoff document corpus and proposes
Lesson candidates for coordination-lead review.

Design lineage: DOC-450CE70D7BAC (Memory Consolidation Lambda design spec). This
implementation operationalizes that design and adds, per ENC-TSK-C08:

  * an adaptive trigger (run only when enough new episodic material has
    accumulated since the last cycle, so the schedule is a ceiling not a floor),
  * FSRS-6 stability initialization from Handoff recurrence count
    (higher recurrence => higher initial stability S on the promoted Lesson),
  * GDMP Stage 2 provenance annotation (compliant documents receive ancestral
    session context via HCE semantic clustering and advance to `contextualized`),
  * OGTM-traversable provenance edges CONSOLIDATED_FROM (candidate -> source
    Handoffs) and PROPOSED_BY (candidate -> proposer) emitted as first-class
    document fields that graph_sync projects to Neo4j.

Governance model (mirrors the enceladus-agent-cli IAM posture):
  * READS go straight to DynamoDB (the execution role is granted Query/Scan on
    the documents table only).
  * WRITES never touch DynamoDB/S3 directly — the engine invokes the governed
    Document API Lambda with a synthetic API Gateway event and the internal
    service key, exactly as coordination_api does for service-to-service writes.
  * The engine NEVER promotes a candidate to a governed Lesson — that is an
    io-only `tracker.create_lesson` action (DOC-450CE70D7BAC §6).

The pure-function core (extractors, FSRS init, clustering, the adaptive-trigger
decision, candidate assembly) is import-safe and side-effect-free so it can be
unit-tested without AWS. The handler wires those functions to DynamoDB reads and
Document API writes.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import boto3
from boto3.dynamodb.conditions import Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- Configuration ---------------------------------------------------------

PROJECT_ID = os.environ.get("PROJECT_ID", "enceladus")
DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "documents")
REGION = os.environ.get("AWS_REGION", "us-west-2")
DOCUMENT_API_LAMBDA_NAME = os.environ.get("DOCUMENT_API_LAMBDA_NAME", "")

# Adaptive trigger: a scheduled invoke runs a full cycle only when at least this
# many Handoff documents were created since the lookback floor. The schedule is
# therefore an upper bound on cadence; quiet periods are skipped cheaply.
ADAPTIVE_TRIGGER_MIN_HANDOFFS = int(os.environ.get("ADAPTIVE_TRIGGER_MIN_HANDOFFS", "3"))
LOOKBACK_DAYS = int(os.environ.get("HCE_LOOKBACK_DAYS", "90"))

# Pattern-matching thresholds (DOC-450CE70D7BAC §4).
COCITATION_MIN_PAIR_COUNT = int(os.environ.get("HCE_COCITATION_MIN_PAIR_COUNT", "3"))
COCITATION_MIN_DISTINCT_WAVES = int(os.environ.get("HCE_COCITATION_MIN_WAVES", "2"))
ERROR_MIN_DISTINCT_WAVES = int(os.environ.get("HCE_ERROR_MIN_WAVES", "2"))

# GDMP Stage 2 provenance annotation budget per cycle.
GDMP_PROVENANCE_ENABLED = os.environ.get("HCE_GDMP_PROVENANCE_ENABLED", "true").lower() == "true"
GDMP_MAX_ANNOTATIONS = int(os.environ.get("HCE_GDMP_MAX_ANNOTATIONS", "10"))
GDMP_MIN_SHARED_REFS = int(os.environ.get("HCE_GDMP_MIN_SHARED_REFS", "1"))

# Proposer for the PROPOSED_BY edge. Defaults to the HCE feature record so the
# edge lands on a real, traversable node.
PROPOSER_ID = os.environ.get("HCE_PROPOSER_ID", "ENC-FTR-064")

# AC-5 (ENC-TSK-L15): block candidate dispatch when the lesson primitive is disabled.
_ENABLE_LESSON_RAW = os.environ.get("ENABLE_LESSON_PRIMITIVE", "true")


def _lesson_primitive_enabled() -> bool:
    return str(_ENABLE_LESSON_RAW).strip().lower() in ("1", "true", "yes", "on")

# FSRS-6 initial-stability mapping bounds (see initial_stability_from_recurrence).
FSRS_S0_FLOOR = float(os.environ.get("HCE_FSRS_S0_FLOOR", "2.0"))
FSRS_S0_CEIL = float(os.environ.get("HCE_FSRS_S0_CEIL", "15.0"))
FSRS_S0_GROWTH = float(os.environ.get("HCE_FSRS_S0_GROWTH", "0.35"))

DOC_SUBTYPES_IN_SCOPE = ("handoff", "wave")
DOC_STATUSES_IN_SCOPE = ("active", "completed", "stale")

CANDIDATE_KEYWORD = "lesson-candidate"

_RATE_LIMIT_SLEEP_S = float(os.environ.get("HCE_RATE_LIMIT_SLEEP_S", "0.1"))

# Enceladus record-id token (used for co-citation and error-class extraction).
_ID_TOKEN_RE = re.compile(r"\b([A-Z]{2,5}-(?:TSK|ISS|FTR|PLN|LSN)-[0-9A-Z]+)\b")
_ISS_TOKEN_RE = re.compile(r"\b([A-Z]{2,5}-ISS-[0-9A-Z]+)\b")
_ERROR_TAG_RE = re.compile(r"\[(ERROR|WARN)\]", re.IGNORECASE)
_SEV_RE = re.compile(r"\bSev([0-3])\b", re.IGNORECASE)

_ddb_resource = None
_lambda_client = None


def _get_table():
    global _ddb_resource
    if _ddb_resource is None:
        _ddb_resource = boto3.resource("dynamodb", region_name=REGION)
    return _ddb_resource.Table(DOCUMENTS_TABLE)


def _get_lambda_client():
    global _lambda_client
    if _lambda_client is None:
        _lambda_client = boto3.client("lambda", region_name=REGION)
    return _lambda_client


def _internal_api_key() -> str:
    for name in (
        "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
        "ENCELADUS_COORDINATION_INTERNAL_API_KEY",
        "COORDINATION_INTERNAL_API_KEY",
    ):
        val = (os.environ.get(name) or "").strip()
        if val:
            return val
    return ""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# FSRS-6 stability initialization (ENC-TSK-C08 AC-5)
# ---------------------------------------------------------------------------

def initial_stability_from_recurrence(
    recurrence: int,
    *,
    floor: float = FSRS_S0_FLOOR,
    ceil: float = FSRS_S0_CEIL,
    growth: float = FSRS_S0_GROWTH,
) -> float:
    """Map a Handoff recurrence count to an initial FSRS-6 stability S_0.

    Contract (ENC-TSK-C08 AC-5): the function is STRICTLY increasing in
    `recurrence` for any growth > 0 — a pattern that recurred across more
    sessions earns a higher initial stability, so the promoted Lesson decays
    more slowly and surfaces longer in retrieval. The mapping saturates toward
    `ceil` so a runaway recurrence count cannot mint an unbounded stability.

    S_0(r) = floor + (ceil - floor) * (1 - exp(-growth * (r - 1)))

    At r = 1 (a single occurrence) S_0 == floor — a normal new-Lesson stability.
    As r -> inf, S_0 -> ceil. The curve is concave (diminishing returns), which
    matches the FSRS-6 intuition that the first few corroborations matter most.
    """
    r = max(1, int(recurrence))
    if ceil <= floor or growth <= 0:
        return round(floor, 4)
    span = ceil - floor
    s0 = floor + span * (1.0 - math.exp(-growth * (r - 1)))
    return round(s0, 4)


# ---------------------------------------------------------------------------
# Handoff corpus helpers
# ---------------------------------------------------------------------------

def wave_anchor(doc: Dict[str, Any]) -> str:
    """Group key for a Handoff into a wave (DOC-450CE70D7BAC §7.3).

    Prefer the explicit plan_anchor_id; otherwise the document is treated as its
    own standalone wave (conservative grouping that never over-merges).
    """
    anchor = str(doc.get("plan_anchor_id") or "").strip()
    return anchor or str(doc.get("document_id") or "").strip()


def _doc_related_ids(doc: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for rid in doc.get("related_items", []) or []:
        rid = str(rid).strip().upper()
        if _ID_TOKEN_RE.fullmatch(rid):
            out.append(rid)
    return out


def normalize_error_tokens(text: str) -> List[str]:
    """Extract a normalized set of error-class tokens from Handoff prose.

    ISS-NNN references are the preferred (structured) signal; [ERROR]/[WARN] log
    tags and SevN markers are kept as coarse fallbacks for unstructured text.
    """
    text = text or ""
    tokens = set(m.group(1).upper() for m in _ISS_TOKEN_RE.finditer(text))
    for m in _ERROR_TAG_RE.finditer(text):
        tokens.add(f"TAG:{m.group(1).upper()}")
    for m in _SEV_RE.finditer(text):
        tokens.add(f"SEV{m.group(1)}")
    return sorted(tokens)


def source_hash(ids: Sequence[str]) -> str:
    """Stable content hash over a candidate's source set (dedup guard, §3.3)."""
    norm = sorted({str(i).strip().upper() for i in ids if str(i).strip()})
    return hashlib.sha256("|".join(norm).encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Pattern extractors (DOC-450CE70D7BAC §4) — pure functions
# ---------------------------------------------------------------------------

def extract_co_citation_candidates(
    handoffs: Sequence[Dict[str, Any]],
    *,
    min_pair_count: int = COCITATION_MIN_PAIR_COUNT,
    min_distinct_waves: int = COCITATION_MIN_DISTINCT_WAVES,
) -> List[Dict[str, Any]]:
    """Co-citation frequency extractor (§4.1, primary).

    A record pair that is co-cited in the related_items of >= min_distinct_waves
    distinct wave anchors AND reaches >= min_pair_count total co-citations within
    the corpus becomes a candidate. Returns one candidate per qualifying pair.
    """
    pair_waves: Dict[Tuple[str, str], set] = defaultdict(set)
    pair_docs: Dict[Tuple[str, str], set] = defaultdict(set)
    for doc in handoffs:
        anchor = wave_anchor(doc)
        doc_id = str(doc.get("document_id") or "").strip()
        ids = sorted(set(_doc_related_ids(doc)))
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                pair = (ids[i], ids[j])
                pair_waves[pair].add(anchor)
                pair_docs[pair].add(doc_id)

    candidates: List[Dict[str, Any]] = []
    for pair, waves in pair_waves.items():
        docs = pair_docs[pair]
        if len(waves) >= min_distinct_waves and len(docs) >= min_pair_count:
            candidates.append({
                "extractor": "co-citation",
                "pattern_token": f"{pair[0]}+{pair[1]}",
                "record_pair": list(pair),
                "recurrence_count": len(docs),
                "distinct_waves": sorted(waves),
                "source_doc_ids": sorted(docs),
            })
    candidates.sort(key=lambda c: (-c["recurrence_count"], c["pattern_token"]))
    return candidates


def extract_error_recurrence_candidates(
    handoffs: Sequence[Dict[str, Any]],
    *,
    min_distinct_waves: int = ERROR_MIN_DISTINCT_WAVES,
) -> List[Dict[str, Any]]:
    """Error-class recurrence extractor (§4.2, primary).

    An error class recurring across >= min_distinct_waves distinct wave anchors
    becomes a candidate.
    """
    class_waves: Dict[str, set] = defaultdict(set)
    class_docs: Dict[str, set] = defaultdict(set)
    class_first: Dict[str, str] = {}
    class_last: Dict[str, str] = {}
    for doc in handoffs:
        anchor = wave_anchor(doc)
        doc_id = str(doc.get("document_id") or "").strip()
        created = str(doc.get("created_at") or "")
        text = " ".join(str(doc.get(f) or "") for f in ("title", "description", "content"))
        for token in normalize_error_tokens(text):
            class_waves[token].add(anchor)
            class_docs[token].add(doc_id)
            if token not in class_first or created < class_first[token]:
                class_first[token] = created
            if token not in class_last or created > class_last[token]:
                class_last[token] = created

    candidates: List[Dict[str, Any]] = []
    for token, waves in class_waves.items():
        if len(waves) >= min_distinct_waves:
            docs = class_docs[token]
            candidates.append({
                "extractor": "error-recurrence",
                "pattern_token": token,
                "error_class": token,
                "recurrence_count": len(docs),
                "distinct_waves": sorted(waves),
                "source_doc_ids": sorted(docs),
                "first_seen": class_first.get(token, ""),
                "last_seen": class_last.get(token, ""),
            })
    candidates.sort(key=lambda c: (-c["recurrence_count"], c["pattern_token"]))
    return candidates


def run_extractors(handoffs: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run all primary extractors and return the merged candidate list."""
    out: List[Dict[str, Any]] = []
    out.extend(extract_co_citation_candidates(handoffs))
    out.extend(extract_error_recurrence_candidates(handoffs))
    return out


# ---------------------------------------------------------------------------
# Adaptive trigger (ENC-TSK-C08 AC-1)
# ---------------------------------------------------------------------------

def count_new_handoffs(handoffs: Sequence[Dict[str, Any]], since_iso: Optional[str]) -> int:
    if not since_iso:
        return len(handoffs)
    return sum(1 for d in handoffs if str(d.get("created_at") or "") > since_iso)


def should_run_cycle(
    handoffs: Sequence[Dict[str, Any]],
    *,
    since_iso: Optional[str],
    min_new_handoffs: int = ADAPTIVE_TRIGGER_MIN_HANDOFFS,
    force: bool = False,
) -> Tuple[bool, str]:
    """Adaptive-trigger decision.

    Returns (run, reason). A forced invoke always runs. Otherwise a full cycle
    runs only when enough new episodic material accumulated since the last cycle,
    making the schedule a ceiling on cadence rather than an unconditional floor.
    """
    if force:
        return True, "forced"
    if not handoffs:
        return False, "no handoffs in scope"
    new_count = count_new_handoffs(handoffs, since_iso)
    if new_count >= min_new_handoffs:
        return True, f"{new_count} new handoffs >= threshold {min_new_handoffs}"
    return False, f"{new_count} new handoffs < threshold {min_new_handoffs}"


# ---------------------------------------------------------------------------
# GDMP Stage 2 provenance clustering (ENC-TSK-C08 AC-3)
# ---------------------------------------------------------------------------

def cluster_provenance_context(
    compliant_docs: Sequence[Dict[str, Any]],
    *,
    min_shared_refs: int = GDMP_MIN_SHARED_REFS,
) -> Dict[str, List[str]]:
    """Semantic-clustering proxy for GDMP Stage 2 ancestral provenance.

    For each compliant document, find sibling documents that share at least
    `min_shared_refs` related-item references (the lightweight co-citation
    proxy for semantic adjacency that needs no embedding round-trip). The shared
    siblings become the document's ancestral session context (`informed_by`),
    which graph_sync projects as INFORMED_BY edges, advancing the document from
    `compliant` to `contextualized`.
    """
    ref_sets: Dict[str, set] = {}
    for doc in compliant_docs:
        doc_id = str(doc.get("document_id") or "").strip()
        if doc_id:
            ref_sets[doc_id] = set(_doc_related_ids(doc))

    result: Dict[str, List[str]] = {}
    for doc_id, refs in ref_sets.items():
        if not refs:
            continue
        siblings: List[str] = []
        for other_id, other_refs in ref_sets.items():
            if other_id == doc_id:
                continue
            if len(refs & other_refs) >= min_shared_refs:
                siblings.append(other_id)
        if siblings:
            result[doc_id] = sorted(siblings)
    return result


# ---------------------------------------------------------------------------
# Candidate document assembly (DOC-450CE70D7BAC §5)
# ---------------------------------------------------------------------------

def build_candidate_document(
    candidate: Dict[str, Any],
    *,
    lookback_start: str,
    lookback_end: str,
    proposer_id: str = PROPOSER_ID,
) -> Dict[str, Any]:
    """Assemble the Document API PUT body for a Lesson candidate.

    The body carries the OGTM provenance fields the graph layer projects:
      * consolidated_from -> the source Handoff document IDs (CONSOLIDATED_FROM)
      * proposed_by       -> the proposer record (PROPOSED_BY)
      * fsrs_initial_stability -> S_0 derived from recurrence (AC-5)
    """
    extractor = candidate["extractor"]
    recurrence = int(candidate["recurrence_count"])
    pattern_token = candidate["pattern_token"]
    source_ids = list(candidate["source_doc_ids"])
    distinct_waves = candidate.get("distinct_waves", [])
    s0 = initial_stability_from_recurrence(recurrence)

    if extractor == "co-citation":
        pair = candidate["record_pair"]
        short = f"co-citation of {pair[0]} & {pair[1]}"
        observed = (
            f"Records {pair[0]} and {pair[1]} were co-cited across "
            f"{len(distinct_waves)} distinct waves ({recurrence} handoffs), "
            "suggesting a recurring structural coupling worth a governed Lesson."
        )
    else:
        short = f"recurring error class {candidate.get('error_class', pattern_token)}"
        observed = (
            f"Error class {candidate.get('error_class', pattern_token)} recurred "
            f"across {len(distinct_waves)} distinct waves ({recurrence} handoffs)."
        )

    evidence_lines = "\n".join(f"- [{d}] source handoff" for d in source_ids)
    content = f"""# LESSON CANDIDATE — {short}

**Extractor**: {extractor}
**Source Handoffs**: {', '.join(source_ids)} ({len(distinct_waves)} distinct waves)
**Recurrence Count**: {recurrence}
**FSRS-6 Initial Stability (S_0)**: {s0}
**Lookback Window**: {lookback_start} to {lookback_end}
**Generated**: {_iso(_now())}
**Status**: DRAFT — awaiting coordination-lead review

## Observed Pattern
{observed}

## Supporting Evidence
{evidence_lines}

## Proposed Lesson Statement
<Draft — what should be learned and applied going forward, based on the
recurring pattern above. Coordination lead refines before promotion.>

## Suggested Tags
{CANDIDATE_KEYWORD}, {pattern_token}

---
_Generated by the Handoff Consolidation Engine (ENC-TSK-C08). Not yet reviewed._
_To promote: io calls tracker.create_lesson with this DOC as evidence_
_(initial FSRS-6 stability S_0 = {s0}, derived from recurrence={recurrence})._
_To discard: set document status to archived._
"""

    keywords = [CANDIDATE_KEYWORD, extractor, pattern_token.lower()]
    return {
        "title": f"LESSON CANDIDATE — {short}",
        "document_subtype": "doc",
        "document_maturity_state": "raw",
        "content": content,
        "related_items": source_ids,
        "keywords": keywords[:10],
        "consolidated_from": source_ids,
        "proposed_by": proposer_id,
        "fsrs_initial_stability": s0,
        "_source_hash": source_hash(source_ids),
        "_recurrence": recurrence,
    }


# ---------------------------------------------------------------------------
# AWS-facing I/O
# ---------------------------------------------------------------------------

def _scan_documents(
    subtypes: Sequence[str],
    *,
    statuses: Sequence[str],
    cutoff_iso: str,
) -> List[Dict[str, Any]]:
    """Read documents in scope directly from DynamoDB (read-only IAM)."""
    table = _get_table()
    filt = (
        Attr("record_type").eq("document")
        & Attr("project_id").eq(PROJECT_ID)
        & Attr("document_subtype").is_in(list(subtypes))
        & Attr("created_at").gte(cutoff_iso)
    )
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {"FilterExpression": filt}
    while True:
        resp = table.scan(**kwargs)
        for it in resp.get("Items", []):
            if str(it.get("document_maturity_state") or "") == "archived":
                continue
            if statuses and str(it.get("status") or "active") not in statuses:
                continue
            items.append(it)
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def _scan_existing_candidate_hashes() -> set:
    """Source hashes of already-proposed candidates (dedup guard, §3.3)."""
    table = _get_table()
    filt = (
        Attr("record_type").eq("document")
        & Attr("project_id").eq(PROJECT_ID)
        & Attr("keywords").contains(CANDIDATE_KEYWORD)
    )
    hashes: set = set()
    kwargs: Dict[str, Any] = {"FilterExpression": filt}
    while True:
        resp = table.scan(**kwargs)
        for it in resp.get("Items", []):
            consolidated = it.get("consolidated_from") or it.get("related_items") or []
            hashes.add(source_hash(consolidated))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return hashes


def _invoke_document_api(method: str, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """Invoke the governed Document API Lambda with a synthetic API GW event."""
    if not DOCUMENT_API_LAMBDA_NAME:
        raise RuntimeError("DOCUMENT_API_LAMBDA_NAME not configured")
    headers = {"Content-Type": "application/json"}
    key = _internal_api_key()
    if key:
        headers["X-Coordination-Internal-Key"] = key
    payload = {"project_id": PROJECT_ID, **body}
    event = {
        "version": "2.0",
        "routeKey": f"{method} {path}",
        "rawPath": path,
        "requestContext": {"http": {"method": method, "path": path}},
        "httpMethod": method,
        "headers": headers,
        "isBase64Encoded": False,
        "body": json.dumps(payload),
    }
    resp = _get_lambda_client().invoke(
        FunctionName=DOCUMENT_API_LAMBDA_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps(event).encode("utf-8"),
    )
    raw = resp.get("Payload")
    text = raw.read().decode("utf-8") if raw is not None else ""
    envelope = json.loads(text) if text else {}
    if resp.get("FunctionError"):
        raise RuntimeError(f"document API invoke error: {envelope}")
    status = int(envelope.get("statusCode") or 0)
    inner_raw = envelope.get("body")
    inner: Dict[str, Any] = {}
    if isinstance(inner_raw, str) and inner_raw:
        try:
            inner = json.loads(inner_raw)
        except json.JSONDecodeError:
            inner = {}
    elif isinstance(inner_raw, dict):
        inner = inner_raw
    return {"status": status, "body": inner}


def _create_candidate(spec: Dict[str, Any]) -> Optional[str]:
    put_body = {k: v for k, v in spec.items() if not k.startswith("_")}
    res = _invoke_document_api("PUT", "/api/v1/documents", put_body)
    if res["status"] in (200, 201):
        return res["body"].get("document_id")
    logger.error("[ERROR] candidate create failed status=%s body=%s", res["status"], res["body"])
    return None


def _annotate_provenance(doc_id: str, informed_by: List[str]) -> bool:
    body = {
        "informed_by": informed_by,
        "document_maturity_state": "contextualized",
    }
    res = _invoke_document_api("PATCH", f"/api/v1/documents/{doc_id}", body)
    if res["status"] == 200:
        return True
    logger.error("[ERROR] provenance patch failed for %s status=%s body=%s",
                 doc_id, res["status"], res["body"])
    return False


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Run one HCE scan-cluster-propose cycle.

    Event knobs (all optional):
      force      — bypass the adaptive trigger and always run.
      dry_run    — run the full cycle but make no Document API writes.
      since      — ISO timestamp for the adaptive new-handoff comparison.
    """
    event = event or {}
    force = bool(event.get("force"))
    dry_run = bool(event.get("dry_run"))
    since_iso = event.get("since")
    run_id = f"hce-{int(time.time())}"
    logger.info("[START] HCE cycle %s (force=%s dry_run=%s)", run_id, force, dry_run)

    if not _lesson_primitive_enabled():
        logger.info("[INFO] HCE cycle %s skipped: ENABLE_LESSON_PRIMITIVE disabled", run_id)
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "run_id": run_id,
                    "skipped": True,
                    "reason": "ENABLE_LESSON_PRIMITIVE disabled",
                }
            ),
        }

    now = _now()
    cutoff = now - timedelta(days=LOOKBACK_DAYS)
    cutoff_iso = _iso(cutoff)

    summary: Dict[str, Any] = {
        "run_id": run_id,
        "lookback_start": cutoff_iso,
        "lookback_end": _iso(now),
        "handoffs_scanned": 0,
        "candidates_detected": 0,
        "candidates_proposed": 0,
        "candidates_skipped_duplicate": 0,
        "provenance_annotated": 0,
        "dry_run": dry_run,
        "errors": [],
    }

    try:
        handoffs = _scan_documents(
            DOC_SUBTYPES_IN_SCOPE, statuses=DOC_STATUSES_IN_SCOPE, cutoff_iso=cutoff_iso
        )
        summary["handoffs_scanned"] = len(handoffs)

        run, reason = should_run_cycle(handoffs, since_iso=since_iso, force=force)
        summary["adaptive_trigger"] = reason
        if not run:
            logger.info("[INFO] HCE cycle %s skipped by adaptive trigger: %s", run_id, reason)
            summary["skipped"] = True
            return {"statusCode": 200, "body": json.dumps(summary)}

        candidates = run_extractors(handoffs)
        summary["candidates_detected"] = len(candidates)

        existing_hashes = set() if dry_run else _scan_existing_candidate_hashes()
        proposed_ids: List[str] = []
        for cand in candidates:
            spec = build_candidate_document(
                cand, lookback_start=cutoff_iso, lookback_end=_iso(now)
            )
            if spec["_source_hash"] in existing_hashes:
                summary["candidates_skipped_duplicate"] += 1
                continue
            existing_hashes.add(spec["_source_hash"])
            if dry_run:
                proposed_ids.append(f"DRY-RUN:{spec['_source_hash']}")
                continue
            doc_id = _create_candidate(spec)
            if doc_id:
                proposed_ids.append(doc_id)
            else:
                summary["errors"].append(f"create failed: {spec['_source_hash']}")
            time.sleep(_RATE_LIMIT_SLEEP_S)
        summary["candidates_proposed"] = len(proposed_ids)
        summary["proposed_document_ids"] = proposed_ids

        # GDMP Stage 2 — provenance annotation of compliant documents.
        if GDMP_PROVENANCE_ENABLED:
            compliant = [
                d for d in _scan_documents(
                    ("doc", "handoff", "wave", "coe"),
                    statuses=("active",),
                    cutoff_iso=cutoff_iso,
                )
                if str(d.get("document_maturity_state") or "") == "compliant"
            ]
            provenance = cluster_provenance_context(compliant)
            annotated = 0
            for doc_id, informed_by in provenance.items():
                if annotated >= GDMP_MAX_ANNOTATIONS:
                    break
                if dry_run:
                    annotated += 1
                    continue
                if _annotate_provenance(doc_id, informed_by):
                    annotated += 1
                time.sleep(_RATE_LIMIT_SLEEP_S)
            summary["provenance_annotated"] = annotated

        logger.info("[SUCCESS] HCE cycle %s: %s", run_id, json.dumps(summary))
        return {"statusCode": 200, "body": json.dumps(summary)}

    except Exception as exc:  # noqa: BLE001 — surface as structured error
        logger.error("[ERROR] HCE cycle %s failed: %s", run_id, exc, exc_info=True)
        summary["errors"].append(str(exc))
        return {"statusCode": 500, "body": json.dumps(summary)}


# Alias for environments that expect lambda_handler.
lambda_handler = handler
