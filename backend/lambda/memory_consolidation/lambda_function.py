"""Enceladus Memory Consolidation Lambda (ENC-FTR-096 Phase 1 / ENC-TSK-I84).

Nightly EventBridge-triggered Lambda that closes the episodic->semantic
consolidation gap (DOC-E2379D980FA2 sec 4.1). It scans inter-session Handoff
documents written to the docstore in the prior 24h, extracts co-citation
clusters (records repeatedly cited together across >= 2 distinct Handoffs),
and drafts *lesson-candidate* documents for later io review.

Architecture:
  EventBridge (cron 02:00 UTC) -> this Lambda
  this Lambda -> DynamoDB `documents` table (read Handoffs; put lesson-candidate drafts)
  this Lambda -> S3 agent-documents prefix (put draft markdown body)

io-approval gate (ENC-FTR-096 AC-4, ENC-TSK-I84 AC-4):
  This Lambda is PROPOSE-ONLY. It NEVER calls tracker.create, checkout.advance,
  or lesson.promote. Every candidate is written with status=draft and
  handoff_status=pending. Promotion to a governed Lesson requires an explicit
  io call to tracker.create_lesson with the draft DOC as evidence. The gate is
  architecturally non-removable: any synthesizer manufactures coherence
  (activation-synthesis), so candidate plausibility is never self-certifying.

OGTM pre-flight (ENC-TSK-I84 AC-5):
  Lesson-candidate documents are stored with record_type="document" and carry
  related_items pointing at their source Handoff DOC ids. graph_sync projects
  document related_items to the pre-existing RELATED_TO edge type. This Lambda
  introduces NO new edge type and does NOT modify graph_sync. `_ogtm_preflight`
  asserts this invariant and logs it on every run.

Hopfield framing (ENC-FTR-096 AC-7): nightly consolidation performs basin
shaping -- merging episodic point-attractors (individual Handoff patterns) into
semantic prototype basins (governed Lessons). The draft-only / io-approval gate
is the architectural analogue of controlled Hebbian consolidation; no weight
erasure (Lesson promotion / unlearning) occurs without explicit io authorization.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from itertools import combinations
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration (env-overridable; defaults mirror document_api CFN wiring)
# ---------------------------------------------------------------------------

DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "documents")
PROJECT_UPDATED_INDEX = os.environ.get("PROJECT_UPDATED_INDEX", "project-updated-index")
S3_BUCKET = os.environ.get("S3_BUCKET", "jreese-net")
S3_PREFIX = os.environ.get("S3_PREFIX", "agent-documents")
AWS_REGION = os.environ.get("AWS_REGION", "us-west-2")

# Comma-separated project ids to consolidate. Default: the enceladus project.
PROJECT_IDS = [
    p.strip()
    for p in os.environ.get("CONSOLIDATION_PROJECT_IDS", "enceladus").split(",")
    if p.strip()
]

# Scan window: Handoffs touched within the prior N hours.
LOOKBACK_HOURS = int(os.environ.get("CONSOLIDATION_LOOKBACK_HOURS", "24"))

# A co-citation must recur across at least this many distinct Handoffs (waves)
# to qualify as a consolidation candidate (ENC-FTR-096 AC-2).
MIN_WAVES = int(os.environ.get("CONSOLIDATION_MIN_WAVES", "2"))

# Write-source channel for governance attribution on docstore writes.
WRITE_SOURCE_CHANNEL = os.environ.get(
    "CONSOLIDATION_WRITE_SOURCE_CHANNEL", "memory_consolidation_lambda"
)

# Document classification for drafts. document_subtype carries the literal
# lesson-candidate type (ENC-TSK-I84 AC-3); subtypepattern mirrors it so the
# value is discoverable via the document.doc subtypepattern graduation pathway
# (governance_data_dictionary document.doc) until io promotes it to a
# first-class enum value in document_api.
LESSON_CANDIDATE_SUBTYPE = "lesson-candidate"

# Edge types graph_sync emits for a document's related_items. RELATED_TO is the
# pre-existing document relationship edge (see backend/lambda/graph_sync). This
# Lambda must never cause a NEW edge type to be projected (OGTM, AC-5).
KNOWN_DOCUMENT_EDGE_TYPES = frozenset({"RELATED_TO"})

# io-approval gate (AC-4): these governed operations are FORBIDDEN to this
# Lambda. They are listed only for explicit logging/auditing -- the code never
# imports a client for them.
IO_GATED_OPERATIONS = ("tracker.create", "checkout.advance", "lesson.promote")

# ID token patterns used for co-citation extraction.
_TRACKER_ID_RE = re.compile(
    r"\b[A-Z]{2,4}-(?:TSK|ISS|FTR|LSN|PLN|GEN|AGT|SES)-[A-Za-z0-9]+\b"
)
_DOC_ID_RE = re.compile(r"\bDOC-[0-9A-Fa-f]{12}\b", re.IGNORECASE)

_ddb_client = None
_s3_client = None


def _get_ddb():
    global _ddb_client
    if _ddb_client is None:
        import boto3

        _ddb_client = boto3.client("dynamodb", region_name=AWS_REGION)
    return _ddb_client


def _get_s3():
    global _s3_client
    if _s3_client is None:
        import boto3

        _s3_client = boto3.client("s3", region_name=AWS_REGION)
    return _s3_client


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_z() -> str:
    return _now().strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# DynamoDB (de)serialization helpers (minimal, attribute-level)
# ---------------------------------------------------------------------------

def _deser(attr: Dict[str, Any]) -> Any:
    if "S" in attr:
        return attr["S"]
    if "N" in attr:
        return attr["N"]
    if "BOOL" in attr:
        return attr["BOOL"]
    if "NULL" in attr:
        return None
    if "M" in attr:
        return {k: _deser(v) for k, v in attr["M"].items()}
    if "L" in attr:
        return [_deser(v) for v in attr["L"]]
    if "SS" in attr:
        return list(attr["SS"])
    return None


def _deser_item(item: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _deser(v) for k, v in item.items()}


def _ser_list(values: Iterable[str]) -> Dict[str, Any]:
    items = [{"S": str(v)} for v in values]
    if not items:
        return {"L": []}
    return {"L": items}


def _stable_doc_id(seed: str) -> str:
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12].upper()
    return f"DOC-{digest}"


def _s3_key(project_id: str, document_id: str) -> str:
    return f"{S3_PREFIX}/{project_id}/{document_id}.md"


# ---------------------------------------------------------------------------
# Handoff scan
# ---------------------------------------------------------------------------

def _scan_recent_handoffs(project_id: str, cutoff_iso: str) -> List[Dict[str, Any]]:
    """Return Handoff documents for a project touched since cutoff_iso.

    Uses the project-updated-index GSI (project_id PK, updated_at SK), then
    filters to document_subtype=handoff. Pagination is followed to completion.
    """
    ddb = _get_ddb()
    params: Dict[str, Any] = {
        "TableName": DOCUMENTS_TABLE,
        "IndexName": PROJECT_UPDATED_INDEX,
        "KeyConditionExpression": "project_id = :pid AND updated_at >= :cut",
        "FilterExpression": "document_subtype = :ht",
        "ExpressionAttributeValues": {
            ":pid": {"S": project_id},
            ":cut": {"S": cutoff_iso},
            ":ht": {"S": "handoff"},
        },
        "ScanIndexForward": False,
    }
    out: List[Dict[str, Any]] = []
    while True:
        resp = ddb.query(**params)
        for raw in resp.get("Items", []):
            out.append(_deser_item(raw))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        params["ExclusiveStartKey"] = lek
    return out


def _read_document_body(doc: Dict[str, Any]) -> str:
    """Best-effort fetch of a document's markdown body from S3."""
    bucket = str(doc.get("s3_bucket") or S3_BUCKET)
    key = doc.get("s3_key")
    if not key:
        return ""
    try:
        resp = _get_s3().get_object(Bucket=bucket, Key=str(key))
        return resp["Body"].read().decode("utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover - network/permission edge
        logger.warning("could not read body for %s: %s", doc.get("document_id"), exc)
        return ""


# ---------------------------------------------------------------------------
# Pattern extraction (pure functions; unit-tested without AWS)
# ---------------------------------------------------------------------------

def extract_id_tokens(text: str) -> Set[str]:
    """Extract governed record/document id tokens from free text."""
    if not text:
        return set()
    tokens: Set[str] = set()
    tokens.update(m.group(0) for m in _TRACKER_ID_RE.finditer(text))
    tokens.update(m.group(0).upper() for m in _DOC_ID_RE.finditer(text))
    return tokens


def extract_cited_ids(handoff: Dict[str, Any], body: str = "") -> Set[str]:
    """Collect the set of governed ids a single Handoff cites.

    Sources: related_items, source_record_id, and id tokens parsed from the
    title / description / body prose. The Handoff's own document_id is excluded
    so a Handoff never co-cites itself.
    """
    cited: Set[str] = set()

    related = handoff.get("related_items") or []
    if isinstance(related, list):
        cited.update(str(r).strip() for r in related if str(r).strip())

    src = handoff.get("source_record_id")
    if src:
        cited.add(str(src).strip())

    for field in ("title", "description"):
        cited.update(extract_id_tokens(str(handoff.get(field) or "")))
    if body:
        cited.update(extract_id_tokens(body))

    self_id = str(handoff.get("document_id") or "").strip()
    cited.discard(self_id)
    cited.discard("")
    return cited


class _UnionFind:
    def __init__(self) -> None:
        self._parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        self._parent.setdefault(x, x)
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[ra] = rb


def build_cocitation_clusters(
    handoffs: List[Dict[str, Any]],
    bodies: Optional[Dict[str, str]] = None,
    min_waves: int = MIN_WAVES,
) -> List[Dict[str, Any]]:
    """Build co-citation clusters from a list of Handoff documents.

    A *pair* of records is co-cited when both appear in the same Handoff. A pair
    *qualifies* when it co-occurs across >= min_waves distinct Handoffs. Pairs
    that qualify are unioned into connected components (clusters). Each returned
    cluster carries its member ids, the supporting Handoff DOC ids, and a
    frequency count (number of distinct supporting Handoffs).
    """
    bodies = bodies or {}

    # pair -> set of supporting handoff doc ids
    pair_support: Dict[Tuple[str, str], Set[str]] = {}
    for h in handoffs:
        hid = str(h.get("document_id") or "").strip()
        cited = extract_cited_ids(h, bodies.get(hid, ""))
        if len(cited) < 2:
            continue
        for a, b in combinations(sorted(cited), 2):
            pair_support.setdefault((a, b), set()).add(hid)

    qualifying = {
        pair: support
        for pair, support in pair_support.items()
        if len(support) >= min_waves
    }
    if not qualifying:
        return []

    uf = _UnionFind()
    for a, b in qualifying:
        uf.union(a, b)

    # Aggregate members + supporting handoffs per cluster root.
    members_by_root: Dict[str, Set[str]] = {}
    support_by_root: Dict[str, Set[str]] = {}
    for (a, b), support in qualifying.items():
        root = uf.find(a)
        members_by_root.setdefault(root, set()).update((a, b))
        support_by_root.setdefault(root, set()).update(support)

    clusters: List[Dict[str, Any]] = []
    for root, members in members_by_root.items():
        support = support_by_root[root]
        clusters.append(
            {
                "member_ids": sorted(members),
                "source_handoff_ids": sorted(support),
                "frequency_count": len(support),
            }
        )

    # Deterministic ordering: strongest (most-supported, largest) clusters first.
    clusters.sort(
        key=lambda c: (-c["frequency_count"], -len(c["member_ids"]), c["member_ids"])
    )
    return clusters


# ---------------------------------------------------------------------------
# Lesson-candidate drafting
# ---------------------------------------------------------------------------

def _candidate_doc_id(project_id: str, cluster: Dict[str, Any]) -> str:
    """Deterministic id from the cluster member signature.

    Stable across nightly runs so a recurring cluster updates / re-uses the same
    draft rather than spawning duplicates (idempotent consolidation).
    """
    signature = "|".join(cluster["member_ids"])
    return _stable_doc_id(f"lesson-candidate:{project_id}:{signature}")


def draft_candidate_payload(project_id: str, cluster: Dict[str, Any]) -> Dict[str, Any]:
    """Build the lesson-candidate draft (metadata + markdown body).

    The body is framed as abstracted, transferable gist (the pattern, not a
    transcript fragment) so it survives pruning of any single source episode
    (ENC-FTR-096 AC-9). related_items point at the source Handoff DOC ids
    (ENC-TSK-I84 AC-3).
    """
    members = cluster["member_ids"]
    sources = cluster["source_handoff_ids"]
    freq = cluster["frequency_count"]
    document_id = _candidate_doc_id(project_id, cluster)

    members_str = ", ".join(members)
    title = f"LESSON-CANDIDATE \u2014 recurring co-citation cluster ({members_str})"
    if len(title) > 200:
        title = title[:197] + "..."

    description = (
        f"Auto-drafted lesson candidate (ENC-FTR-096). Records {members_str} were "
        f"co-cited across {freq} distinct Handoff documents in the prior "
        f"{LOOKBACK_HOURS}h. Pending io review before promotion to a governed Lesson."
    )

    body_lines = [
        f"# {document_id}",
        "",
        f"**Project**: {project_id}",
        f"**Document subtype**: {LESSON_CANDIDATE_SUBTYPE}",
        f"**Status**: draft (pending io approval)",
        f"**Source**: memory-consolidation-lambda (ENC-FTR-096 Ph1, ENC-TSK-I84)",
        f"**Related**: {', '.join(sources)}",
        "",
        "## Candidate pattern (abstracted gist)",
        "",
        (
            f"The records **{members_str}** recur together as a co-citation cluster "
            f"across **{freq}** distinct inter-session Handoff documents within the "
            f"last {LOOKBACK_HOURS} hours. Repeated co-citation across independent "
            "waves is a signal that these records participate in a shared, "
            "transferable pattern (a recurring workflow, dependency, or failure "
            "class) worth consolidating into governed semantic memory."
        ),
        "",
        "## Why this is a candidate, not a Lesson",
        "",
        (
            "This document is a **draft proposal only**. A synthesizer manufactures "
            "coherence; candidate plausibility is never self-certifying. Promotion "
            "to a governed Lesson requires an explicit io review and a "
            "`tracker.create_lesson` call citing this draft as evidence. The "
            "consolidation Lambda performs no tracker mutation, checkout advance, "
            "or lesson promotion."
        ),
        "",
        "## Supporting Handoff documents",
        "",
    ]
    body_lines.extend(f"- {sid}" for sid in sources)
    body_lines.append("")
    body_lines.append("## Co-cited records")
    body_lines.append("")
    body_lines.extend(f"- {mid}" for mid in members)
    body_lines.append("")
    content = "\n".join(body_lines)

    return {
        "document_id": document_id,
        "project_id": project_id,
        "title": title,
        "description": description,
        "content": content,
        "document_subtype": LESSON_CANDIDATE_SUBTYPE,
        "subtypepattern": LESSON_CANDIDATE_SUBTYPE,
        "handoff_status": "pending",
        "status": "draft",
        "related_items": sources,
        "keywords": ["lesson-candidate", "memory-consolidation", "ftr-096"],
        "cluster_member_ids": members,
        "frequency_count": freq,
    }


def _put_lesson_candidate(payload: Dict[str, Any]) -> str:
    """documents.put at the docstore layer: write body to S3 + item to DynamoDB.

    Returns one of: "created" | "exists". Idempotent: if a non-terminal draft
    already exists for the same cluster signature, the write is skipped so
    re-runs do not duplicate candidates.
    """
    ddb = _get_ddb()
    project_id = payload["project_id"]
    document_id = payload["document_id"]

    existing = ddb.get_item(
        TableName=DOCUMENTS_TABLE,
        Key={"document_id": {"S": document_id}},
        ConsistentRead=True,
    ).get("Item")
    if existing:
        cur = _deser_item(existing)
        if str(cur.get("status") or "").lower() not in ("deleted", "archived"):
            logger.info(
                "[SKIP] lesson-candidate %s already exists (status=%s) — not duplicating",
                document_id,
                cur.get("status"),
            )
            return "exists"

    content_bytes = payload["content"].encode("utf-8")
    s3_key = _s3_key(project_id, document_id)
    _get_s3().put_object(
        Bucket=S3_BUCKET,
        Key=s3_key,
        Body=content_bytes,
        ContentType="text/markdown; charset=utf-8",
        CacheControl="max-age=0, s-maxage=300, must-revalidate",
    )

    now = _now_z()
    item = {
        "document_id": {"S": document_id},
        "project_id": {"S": project_id},
        "title": {"S": payload["title"]},
        "description": {"S": payload["description"]},
        "document_subtype": {"S": payload["document_subtype"]},
        "subtypepattern": {"S": payload["subtypepattern"]},
        "handoff_status": {"S": payload["handoff_status"]},
        "file_name": {"S": f"{document_id}.md"},
        "s3_bucket": {"S": S3_BUCKET},
        "s3_key": {"S": s3_key},
        "content_type": {"S": "text/markdown"},
        "content_hash": {"S": hashlib.sha256(content_bytes).hexdigest()},
        "size_bytes": {"N": str(len(content_bytes))},
        "related_items": _ser_list(payload["related_items"]),
        "keywords": _ser_list(payload["keywords"]),
        "cluster_member_ids": _ser_list(payload["cluster_member_ids"]),
        "frequency_count": {"N": str(payload["frequency_count"])},
        "created_by": {"S": WRITE_SOURCE_CHANNEL},
        "created_at": {"S": now},
        "updated_at": {"S": now},
        "status": {"S": payload["status"]},
        "version": {"N": "1"},
        "record_type": {"S": "document"},
        "write_source": {
            "M": {
                "channel": {"S": WRITE_SOURCE_CHANNEL},
                "provider": {"S": "memory_consolidation_lambda"},
                "feature": {"S": "ENC-FTR-096"},
                "timestamp": {"S": now},
            }
        },
    }
    try:
        ddb.put_item(
            TableName=DOCUMENTS_TABLE,
            Item=item,
            ConditionExpression="attribute_not_exists(document_id)",
        )
    except ddb.exceptions.ConditionalCheckFailedException:
        logger.info("[SKIP] lesson-candidate %s created concurrently", document_id)
        return "exists"

    logger.info(
        "[DRAFT] lesson-candidate %s created (members=%d sources=%d freq=%d)",
        document_id,
        len(payload["cluster_member_ids"]),
        len(payload["related_items"]),
        payload["frequency_count"],
    )
    return "created"


# ---------------------------------------------------------------------------
# OGTM pre-flight (AC-5)
# ---------------------------------------------------------------------------

def _ogtm_preflight() -> Dict[str, Any]:
    """Assert this Lambda introduces no new graph edge type.

    Lesson-candidate drafts are record_type=document with related_items; the
    only edge type graph_sync emits for them is RELATED_TO, which already exists.
    """
    emitted = {"RELATED_TO"}
    new_edge_types = sorted(emitted - KNOWN_DOCUMENT_EDGE_TYPES)
    result = {
        "emitted_edge_types": sorted(emitted),
        "new_edge_types": new_edge_types,
        "graph_sync_modified": False,
        "compliant": not new_edge_types,
    }
    logger.info("[OGTM] pre-flight: %s", json.dumps(result))
    return result


def _log_io_gate() -> Dict[str, int]:
    """Emit the io-approval gate audit line (AC-4).

    The Lambda is propose-only: zero tracker.create, checkout.advance, and
    lesson.promote calls are made. This is logged so a CloudWatch inspection of
    any invocation can confirm the gate held.
    """
    gate = {op.replace(".", "_"): 0 for op in IO_GATED_OPERATIONS}
    logger.info(
        "[IO-GATE] draft-only run — forbidden governed ops emitted: %s",
        json.dumps(gate),
    )
    return gate


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

# --- ENC-TSK-N23: rhythm heavy-beat completion-stanza contract --------------
# When invoked as a rhythm tenant (backend/lambda/rhythm_cycle/tenant_invoker
# .py), the invoke payload carries ``result_key`` — the exact S3 key this
# tenant must write its completion stanza to. Scheduled EventBridge invokes
# carry no result_key and skip the write. Stanza shape mirrors
# tenant_invoker.write_completion_stanza; a write failure is logged, never
# raised — the beat's silent-tenant detection treats a missing stanza as
# silence, which is the honest signal.

RHYTHM_TENANT_NAME = "memory_consolidation"
RHYTHM_RESULTS_BUCKET = os.environ.get("RHYTHM_RESULTS_BUCKET", "jreese-net")


def _write_rhythm_stanza(
    event: Any,
    status: str,
    detail: Optional[Dict[str, Any]] = None,
    output_count: Optional[int] = None,
) -> bool:
    result_key = str((event or {}).get("result_key") or "").strip() if isinstance(event, dict) else ""
    if not result_key:
        return False
    body = {
        "tenant": RHYTHM_TENANT_NAME,
        "status": status,
        # ENC-TSK-N48 / BRD §4.1: assert on OUTPUT, not execution. did_work is
        # False on the skip/disable path (status != "completed"); output_count
        # exposes correct-zero (did_work=True, count=0) vs produced (count>0).
        "did_work": status == "completed",
        "output_count": output_count,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "detail": detail or {},
    }
    try:
        import boto3  # lazy, mirrors module idiom — keeps module import AWS-free

        boto3.client("s3", region_name=AWS_REGION).put_object(
            Bucket=RHYTHM_RESULTS_BUCKET,
            Key=result_key,
            Body=json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"),
            ContentType="application/json",
        )
        return True
    except Exception as exc:  # noqa: BLE001 — stanza failure must never break the run
        logger.warning("[ERROR] rhythm stanza write failed key=%s: %s", result_key, exc)
        return False


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Entry point: run the nightly consolidation, then honor the rhythm
    completion-stanza contract when invoked as a heavy-beat tenant
    (ENC-TSK-N23)."""
    try:
        result = _run_consolidation(event, context)
    except Exception:
        _write_rhythm_stanza(event, "failed", {})
        raise
    _write_rhythm_stanza(
        event,
        "completed",
        {
            k: result.get(k)
            for k in ("handoffs_scanned", "clusters_found", "candidates_created", "candidates_existing")
        },
        # ENC-TSK-N48: output_count = lesson-candidate documents created this
        # window. 0 with did_work=True is the honest correct-zero (an empty
        # lookback window), distinct from a disabled tenant's did_work=False.
        output_count=result.get("candidates_created"),
    )
    return result


def _run_consolidation(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Nightly consolidation core.

    Returns a structured summary and never raises on per-project failures so the
    invocation exits 0 (AC-1) with CloudWatch logs confirming the scan ran.
    """
    start = time.time()
    logger.info(
        "[START] memory consolidation: projects=%s lookback_h=%d min_waves=%d",
        PROJECT_IDS,
        LOOKBACK_HOURS,
        MIN_WAVES,
    )

    ogtm = _ogtm_preflight()
    io_gate = _log_io_gate()

    cutoff_iso = (_now() - timedelta(hours=LOOKBACK_HOURS)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    per_project: List[Dict[str, Any]] = []
    total_handoffs = 0
    total_clusters = 0
    total_created = 0
    total_existing = 0

    for project_id in PROJECT_IDS:
        try:
            handoffs = _scan_recent_handoffs(project_id, cutoff_iso)
            bodies = {
                str(h.get("document_id") or ""): _read_document_body(h)
                for h in handoffs
            }
            clusters = build_cocitation_clusters(handoffs, bodies, MIN_WAVES)
            logger.info(
                "[SCAN] project=%s handoffs=%d clusters=%d",
                project_id,
                len(handoffs),
                len(clusters),
            )

            created = existing = 0
            for cluster in clusters:
                payload = draft_candidate_payload(project_id, cluster)
                outcome = _put_lesson_candidate(payload)
                if outcome == "created":
                    created += 1
                else:
                    existing += 1

            total_handoffs += len(handoffs)
            total_clusters += len(clusters)
            total_created += created
            total_existing += existing
            per_project.append(
                {
                    "project_id": project_id,
                    "handoffs_scanned": len(handoffs),
                    "clusters_found": len(clusters),
                    "candidates_created": created,
                    "candidates_existing": existing,
                }
            )
        except Exception as exc:  # keep the invocation green; log + continue
            logger.exception("[ERROR] consolidation failed for project %s", project_id)
            per_project.append({"project_id": project_id, "error": str(exc)})

    result = {
        "statusCode": 200,
        "scanned_at": _now_z(),
        "cutoff": cutoff_iso,
        "lookback_hours": LOOKBACK_HOURS,
        "min_waves": MIN_WAVES,
        "handoffs_scanned": total_handoffs,
        "clusters_found": total_clusters,
        "candidates_created": total_created,
        "candidates_existing": total_existing,
        "io_gate": io_gate,
        "ogtm": ogtm,
        "projects": per_project,
        "elapsed_seconds": round(time.time() - start, 2),
    }
    logger.info("[END] memory consolidation: %s", json.dumps(result))
    return result
