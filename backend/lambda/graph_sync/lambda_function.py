"""devops-graph-sync Lambda -- DynamoDB stream consumer for Neo4j AuraDB graph index.

Triggered by SQS FIFO queue (devops-graph-sync-queue.fifo) which receives
events from an EventBridge Pipe connected to the devops-project-tracker
DynamoDB Stream.

Flow:
  DynamoDB Streams -> EventBridge Pipe -> SQS FIFO -> This Lambda
  -> MERGE/DELETE Cypher operations against AuraDB Free

The graph is a READ-ONLY derived index. DynamoDB remains the sole source
of truth. Graph unavailability does NOT affect tracker mutations.

Node labels: Task, Issue, Feature, Project
Edge types: CHILD_OF, RELATED_TO, BELONGS_TO, ADDRESSES, IMPLEMENTS
           + ENC-FTR-049 typed edges: BLOCKS, BLOCKED_BY, DUPLICATES, DUPLICATED_BY,
             RELATES_TO, PARENT_OF, CHILD_OF_TYPED, DEPENDS_ON, DEPENDED_ON_BY,
             CLONES, CLONED_BY, AFFECTS, AFFECTED_BY, TESTS, TESTED_BY,
             CONSUMES_FROM, PRODUCES_FOR

Environment variables:
  NEO4J_SECRET_NAME    Secrets Manager secret ID (default: enceladus/neo4j/auradb-credentials)
  SECRETS_REGION       AWS region for Secrets Manager (default: us-west-2)
  BEDROCK_REGION       AWS region for Bedrock runtime (default: us-west-2)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Set, Tuple

# ENC-TSK-B94: Incremental Titan V2 embedding helpers. build_embedding_text,
# hash_embedding_text, compute_embedding_for_record, and the model/property
# constants are the shared contract between this incremental path and the
# ENC-TSK-B91 backfill path. Keep imports colocated with lambda_function.py
# so the helper module is packaged automatically by deploy.sh.
from embedding import (
    EMBEDDABLE_RECORD_TYPES,
    EMBEDDING_HASH_PROPERTY,
    EMBEDDING_PROPERTY,
    compute_embedding_for_record,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NEO4J_SECRET_NAME = os.environ.get("NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials")
SECRETS_REGION = os.environ.get("SECRETS_REGION", "us-west-2")

# ---------------------------------------------------------------------------
# Lazy singletons (cold-start cached)
# ---------------------------------------------------------------------------

_neo4j_driver = None
_secretsmanager = None


def _get_secretsmanager():
    global _secretsmanager
    if _secretsmanager is None:
        import boto3
        from botocore.config import Config
        _secretsmanager = boto3.client(
            "secretsmanager",
            region_name=SECRETS_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _secretsmanager


def _get_neo4j_credentials() -> Dict[str, str]:
    sm = _get_secretsmanager()
    resp = sm.get_secret_value(SecretId=NEO4J_SECRET_NAME)
    return json.loads(resp["SecretString"])


def _get_neo4j_driver():
    global _neo4j_driver
    if _neo4j_driver is None:
        try:
            from neo4j import GraphDatabase
        except ImportError:
            logger.error("[ERROR] neo4j driver not installed")
            return None
        creds = _get_neo4j_credentials()
        uri = creds["NEO4J_URI"]
        user = creds.get("NEO4J_USERNAME", "neo4j")
        password = creds["NEO4J_PASSWORD"]
        _neo4j_driver = GraphDatabase.driver(uri, auth=(user, password))
    return _neo4j_driver


# ---------------------------------------------------------------------------
# DynamoDB deserialization
# ---------------------------------------------------------------------------

def _deser_value(ddb_val: Dict) -> Any:
    """Deserialize a single DynamoDB-typed value."""
    if "S" in ddb_val:
        return ddb_val["S"]
    if "N" in ddb_val:
        return ddb_val["N"]
    if "BOOL" in ddb_val:
        return ddb_val["BOOL"]
    if "NULL" in ddb_val:
        return None
    if "L" in ddb_val:
        return [_deser_value(v) for v in ddb_val["L"]]
    if "M" in ddb_val:
        return {k: _deser_value(v) for k, v in ddb_val["M"].items()}
    if "SS" in ddb_val:
        return list(ddb_val["SS"])
    return str(ddb_val)


def _deser_image(image: Dict) -> Dict[str, Any]:
    """Deserialize a DynamoDB stream NewImage/OldImage dict."""
    return {k: _deser_value(v) for k, v in image.items()}


def _normalize_record_for_graph(record: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize cross-table record identity before graph projection.

    Tracker rows key on ``record_id`` while document rows key on
    ``document_id``. The graph projection code expects ``record_id``.
    """
    normalized = dict(record or {})
    if not normalized:
        return normalized

    record_type = str(normalized.get("record_type") or "").strip()
    if not record_type and normalized.get("document_id"):
        record_type = "document"
        normalized["record_type"] = record_type

    if record_type == "document" and not normalized.get("record_id"):
        normalized["record_id"] = normalized.get("document_id", "")

    return normalized


def _extract_remove_record_id(keys: Dict[str, Any], old_record: Optional[Dict[str, Any]] = None) -> str:
    """Resolve the primary ID for REMOVE events across tracker + document tables."""
    for key_name in ("record_id", "document_id", "item_id"):
        typed = keys.get(key_name) or {}
        value = str(typed.get("S") or "").strip()
        if value:
            return value

    if old_record:
        for key_name in ("record_id", "document_id", "item_id"):
            value = str(old_record.get(key_name) or "").strip()
            if value:
                return value

    return ""


# ---------------------------------------------------------------------------
# Graph schema constants
# ---------------------------------------------------------------------------

RECORD_TYPE_TO_LABEL = {
    "task": "Task",
    "issue": "Issue",
    "feature": "Feature",
    "plan": "Plan",  # ENC-FTR-058
    "lesson": "Lesson",  # ENC-FTR-052 / ENC-TSK-983
    "document": "Document",  # ENC-FTR-065 / ENC-PLN-014
    "generation": "Generation",  # GMF DOC-63420302EF65
}

# ENC-TSK-E01 / ENC-ISS-184: ID-prefix to Neo4j label mapping for placeholder
# node creation. When a plan emits a PLAN_CONTAINS edge to an objective task
# that has not yet been projected (race window after plan.add_objective is
# called before the target task's own DDB stream event reaches graph_sync),
# we MERGE a placeholder node with the inferred label so the edge always
# lands. The target's own stream event later MERGEs by the same label and
# record_id, augmenting the placeholder with full properties without
# creating a duplicate node.
ID_PREFIX_TO_LABEL = {
    "TSK": "Task",
    "ISS": "Issue",
    "FTR": "Feature",
    "PLN": "Plan",
    "LSN": "Lesson",
    "DOC": "Document",
    "GEN": "Generation",
    "DPL": "DeploymentDecision",
}


def _bare_id(record_id: str) -> str:
    """Strip 'type#' prefix from composite DynamoDB record_id.

    DynamoDB record_id: 'task#ENC-TSK-890' -> 'ENC-TSK-890'
    Bare IDs pass through unchanged.
    """
    return record_id.split("#", 1)[-1] if "#" in record_id else record_id


def _infer_label_from_id(record_id: str) -> str:
    """Infer a Neo4j node label from a bare record_id like 'ENC-TSK-C59'.

    Returns '' when the prefix is not recognised so callers can skip
    placeholder creation rather than spawning unlabelled nodes.
    Document IDs may be 'DOC-XXXX' (no project prefix); both single- and
    triple-segment IDs are handled.
    """
    if not record_id:
        return ""
    parts = record_id.split("-")
    # Document IDs: 'DOC-XXXX' (2 segments) or PROJECT-DOC-XXXX (3+)
    if parts[0].upper() == "DOC":
        return "Document"
    # ENC-TSK-F45: Component IDs use 'comp-<name>' prefix (not the 3-segment ENC-TYPE-XXX form)
    if parts[0].lower() == "comp":
        return "Component"
    if len(parts) < 2:
        return ""
    type_code = parts[1].upper()
    return ID_PREFIX_TO_LABEL.get(type_code, "")


# Properties to copy from DynamoDB record to Neo4j node
NODE_PROPERTIES = [
    "record_id", "project_id", "title", "status", "priority",
    "category", "updated_at", "created_at",
]


PlaceholderRef = Tuple[str, str]


def _add_placeholder_ref(refs: Set[PlaceholderRef], label: str, raw_id: Any) -> None:
    """Add a label-qualified placeholder candidate if the id is non-empty."""
    record_id = _bare_id(str(raw_id).strip()) if raw_id is not None else ""
    if label and record_id:
        refs.add((label, record_id))


def _collect_placeholder_target_refs(record: Dict[str, Any]) -> Set[PlaceholderRef]:
    """Collect label-qualified placeholder nodes that a record may create.

    Only graph_sync branches that use placeholder MERGE participate here.
    This lets MODIFY/REMOVE flows prune stale placeholders after edges are
    removed without touching real projected nodes.
    """
    refs: Set[PlaceholderRef] = set()
    record_type = str(record.get("record_type") or "").strip()

    if record_type == "plan":
        for objective_id in record.get("objectives_set", []) or []:
            obj_id = _bare_id(str(objective_id).strip()) if objective_id else ""
            _add_placeholder_ref(refs, _infer_label_from_id(obj_id), obj_id)
        for document_id in record.get("attached_documents", []) or []:
            _add_placeholder_ref(refs, "Document", document_id)
        _add_placeholder_ref(refs, "Feature", record.get("related_feature_id", ""))

    elif record_type == "lesson":
        for evidence_id in record.get("evidence_chain", []) or []:
            ev_id = _bare_id(str(evidence_id).strip()) if evidence_id else ""
            _add_placeholder_ref(refs, _infer_label_from_id(ev_id), ev_id)
        for ext in record.get("extensions", []) or []:
            if not isinstance(ext, dict):
                continue
            for evidence_id in ext.get("evidence_ids", []) or []:
                ev_id = _bare_id(str(evidence_id).strip()) if evidence_id else ""
                _add_placeholder_ref(refs, _infer_label_from_id(ev_id), ev_id)

    elif record_type == "document":
        for related_id in record.get("related_items", []) or []:
            rid = _bare_id(str(related_id).strip()) if related_id else ""
            _add_placeholder_ref(refs, _infer_label_from_id(rid), rid)
        for source_id in record.get("informed_by", []) or []:
            _add_placeholder_ref(refs, "Document", source_id)

        doc_subtype = str(record.get("document_subtype") or "").strip()
        if doc_subtype == "coe":
            src = _bare_id(str(record.get("source_incident_id") or "").strip())
            _add_placeholder_ref(refs, _infer_label_from_id(src), src)
        elif doc_subtype == "wave":
            _add_placeholder_ref(refs, "Plan", record.get("plan_anchor_id", ""))
        elif doc_subtype == "handoff":
            src = _bare_id(str(record.get("source_record_id") or "").strip())
            _add_placeholder_ref(refs, _infer_label_from_id(src), src)

    elif record_type == "relationship":
        for endpoint in (record.get("source_id", ""), record.get("target_id", "")):
            endpoint_id = _bare_id(str(endpoint).strip()) if endpoint else ""
            _add_placeholder_ref(refs, _infer_label_from_id(endpoint_id), endpoint_id)

    return refs


def _relationship_placeholder_refs_from_sk(record_id_sk: str) -> Set[PlaceholderRef]:
    """Infer placeholder endpoints from a rel# sort key when OldImage is absent."""
    refs: Set[PlaceholderRef] = set()
    parts = str(record_id_sk or "").split("#")
    if len(parts) < 4 or parts[0] != "rel":
        return refs
    for endpoint in (parts[1], parts[3]):
        endpoint_id = _bare_id(endpoint)
        _add_placeholder_ref(refs, _infer_label_from_id(endpoint_id), endpoint_id)
    return refs


def _purge_orphan_placeholders(tx, refs: Set[PlaceholderRef]) -> None:
    """Delete placeholder nodes that no longer participate in any edge."""
    for label, record_id in refs:
        tx.run(
            f"MATCH (n:{label} {{record_id: $rid}}) "
            "WHERE coalesce(n.is_placeholder, false) = true "
            "AND NOT (n)--() "
            "DETACH DELETE n",
            rid=record_id,
        )


# ---------------------------------------------------------------------------
# Cypher operations
# ---------------------------------------------------------------------------

def _upsert_node(tx, record: Dict[str, Any]) -> None:
    """MERGE a node by record_id (bare format) and set properties."""
    record_type = record.get("record_type", "")
    label = RECORD_TYPE_TO_LABEL.get(record_type)
    if not label:
        return

    record_id = _bare_id(record.get("record_id", record.get("item_id", "")))
    if not record_id:
        return

    props = {k: record.get(k) for k in NODE_PROPERTIES if record.get(k) is not None}
    props["record_id"] = record_id

    cypher = (
        f"MERGE (n:{label} {{record_id: $record_id}}) "
        "SET n += $props "
        "SET n.is_placeholder = false"
    )
    tx.run(cypher, record_id=record_id, props=props)


def _upsert_project_node(tx, project_id: str) -> None:
    """Ensure a :Project node exists."""
    tx.run(
        "MERGE (p:Project {project_id: $pid})",
        pid=project_id,
    )


def _read_existing_embedding_hash(tx, label: str, record_id: str) -> str:
    """Return the current `embedding_text_hash` on the node, or '' if absent.

    Used by the incremental embedding path to short-circuit no-op MODIFY
    events (e.g. status transitions) without invoking Bedrock when the
    embedding input text has not changed.
    """
    result = tx.run(
        f"MATCH (n:{label} {{record_id: $rid}}) "
        f"RETURN n.{EMBEDDING_HASH_PROPERTY} AS h",
        rid=record_id,
    )
    record = result.single()
    if record is None:
        return ""
    hash_val = record.get("h")
    return str(hash_val) if hash_val is not None else ""


def _write_embedding(tx, label: str, record_id: str, payload: Dict[str, Any]) -> None:
    """Set `embedding` and `embedding_text_hash` on the node.

    Payload is the dict returned by `compute_embedding_for_record`:
    `{embedding: [256 floats], embedding_text_hash: str}`. The node is
    assumed to already exist (upserted by `_upsert_node` earlier in the
    same session); SET on a non-existent match is a no-op and that is
    acceptable — the next stream event will retry.
    """
    tx.run(
        f"MATCH (n:{label} {{record_id: $rid}}) "
        f"SET n.{EMBEDDING_PROPERTY} = $embedding, "
        f"    n.{EMBEDDING_HASH_PROPERTY} = $hash",
        rid=record_id,
        embedding=payload[EMBEDDING_PROPERTY],
        hash=payload[EMBEDDING_HASH_PROPERTY],
    )


def _reconcile_edges(tx, record: Dict[str, Any]) -> None:
    """Delete existing edges for node then re-create from record fields."""
    record_id = _bare_id(record.get("record_id", record.get("item_id", "")))
    record_type = record.get("record_type", "")
    label = RECORD_TYPE_TO_LABEL.get(record_type)
    if not label or not record_id:
        return

    # Remove all outgoing relationships so we can re-create from current state
    tx.run(
        f"MATCH (n:{label}) WHERE n.record_id = $rid "
        "OPTIONAL MATCH (n)-[r]->() DELETE r",
        rid=record_id,
    )
    # Also remove incoming RELATED_TO since we'll re-create from current state
    tx.run(
        f"MATCH (n:{label}) WHERE n.record_id = $rid "
        "OPTIONAL MATCH ()-[r:RELATED_TO]->(n) DELETE r",
        rid=record_id,
    )

    project_id = record.get("project_id", "")

    # BELONGS_TO -> Project
    if project_id:
        tx.run(
            f"MATCH (n:{label}), (p:Project) "
            "WHERE n.record_id = $rid AND p.project_id = $pid "
            "MERGE (n)-[:BELONGS_TO]->(p)",
            rid=record_id, pid=project_id,
        )

    # CHILD_OF -> parent Task
    parent = _bare_id(record.get("parent", ""))
    if parent and record_type == "task":
        tx.run(
            "MATCH (child:Task), (parent:Task) "
            "WHERE child.record_id = $child_id AND parent.record_id = $parent_id "
            "MERGE (child)-[:CHILD_OF]->(parent)",
            child_id=record_id, parent_id=parent,
        )

    # RELATED_TO from related_task_ids (single directed edge, not bidirectional)
    for related_id in record.get("related_task_ids", []) or []:
        related_id = _bare_id(related_id) if related_id else ""
        if not related_id:
            continue
        tx.run(
            f"MATCH (a:{label}), (b:Task) "
            "WHERE a.record_id = $aid AND b.record_id = $bid "
            "MERGE (a)-[:RELATED_TO]->(b)",
            aid=record_id, bid=related_id,
        )

    # RELATED_TO from related_issue_ids + ADDRESSES (Task->Issue)
    for related_id in record.get("related_issue_ids", []) or []:
        related_id = _bare_id(related_id) if related_id else ""
        if not related_id:
            continue
        tx.run(
            f"MATCH (a:{label}), (b:Issue) "
            "WHERE a.record_id = $aid AND b.record_id = $bid "
            "MERGE (a)-[:RELATED_TO]->(b)",
            aid=record_id, bid=related_id,
        )
        if record_type == "task":
            tx.run(
                "MATCH (t:Task), (i:Issue) "
                "WHERE t.record_id = $tid AND i.record_id = $iid "
                "MERGE (t)-[:ADDRESSES]->(i)",
                tid=record_id, iid=related_id,
            )

    # RELATED_TO from related_feature_ids + IMPLEMENTS (Task->Feature)
    for related_id in record.get("related_feature_ids", []) or []:
        related_id = _bare_id(related_id) if related_id else ""
        if not related_id:
            continue
        tx.run(
            f"MATCH (a:{label}), (b:Feature) "
            "WHERE a.record_id = $aid AND b.record_id = $bid "
            "MERGE (a)-[:RELATED_TO]->(b)",
            aid=record_id, bid=related_id,
        )
        if record_type == "task":
            tx.run(
                "MATCH (t:Task), (f:Feature) "
                "WHERE t.record_id = $tid AND f.record_id = $fid "
                "MERGE (t)-[:IMPLEMENTS]->(f)",
                tid=record_id, fid=related_id,
            )

    # ENC-ISS-150 / ENC-TSK-B14: Plan-specific edge projections
    # ENC-TSK-E01 / ENC-ISS-184: emit edges via labelled-target MERGE so the
    # PLAN_CONTAINS / PLAN_ATTACHED_DOC edges land even when the target node
    # is not yet projected. The previous Cartesian MATCH pattern silently
    # produced zero rows (and zero edges) when the objective task or
    # attached document had not been processed yet by graph_sync, leaving
    # plans like ENC-PLN-016 with zero PLAN_CONTAINS edges despite a
    # populated objectives_set. Placeholder MERGE attaches a label-correct
    # node by record_id; the target's own stream event later MERGEs by the
    # same (label, record_id) pair and augments the placeholder with full
    # properties without duplicating it.
    if record_type == "plan":
        objectives_set = record.get("objectives_set", []) or []
        attached_documents = record.get("attached_documents", []) or []
        logger.info(
            "[INFO] Plan reconcile %s: objectives_set=%d attached_documents=%d",
            record_id, len(objectives_set), len(attached_documents),
        )

        # PLAN_CONTAINS -> each objective (Task/Issue/Feature)
        for obj_id in objectives_set:
            obj_id = _bare_id(obj_id) if obj_id else ""
            if not obj_id:
                continue
            target_label = _infer_label_from_id(obj_id)
            if target_label:
                # Ensure a label-correct target node exists. Placeholder is
                # idempotent with the target's own _upsert_node MERGE.
                # ENC-TSK-E06: tag new placeholders so downstream embedding +
                # coverage pipelines can filter them out; _upsert_node clears
                # the flag to false when the real record materializes.
                tx.run(
                    f"MERGE (t:{target_label} {{record_id: $tid}}) "
                    "ON CREATE SET t.is_placeholder = true",
                    tid=obj_id,
                )
                tx.run(
                    f"MATCH (p:Plan), (t:{target_label}) "
                    "WHERE p.record_id = $pid AND t.record_id = $tid "
                    "MERGE (p)-[:PLAN_CONTAINS]->(t)",
                    pid=record_id, tid=obj_id,
                )
            else:
                # Unknown ID prefix: fall back to the legacy unlabelled
                # MATCH so we do not silently lose the edge if the prefix
                # registry is incomplete.
                logger.warning(
                    "[WARNING] Plan %s objective %s has unrecognised ID prefix; "
                    "falling back to unlabelled MATCH (edge may not land if target absent)",
                    record_id, obj_id,
                )
                tx.run(
                    "MATCH (p:Plan), (t {record_id: $tid}) "
                    "WHERE p.record_id = $pid "
                    "MERGE (p)-[:PLAN_CONTAINS]->(t)",
                    pid=record_id, tid=obj_id,
                )

        # PLAN_ATTACHED_DOC -> each document
        for doc_id in attached_documents:
            doc_id = str(doc_id).strip() if doc_id else ""
            if not doc_id:
                continue
            # Documents always project to the :Document label.
            # ENC-TSK-E06: tag placeholder on create.
            tx.run(
                "MERGE (d:Document {record_id: $did}) "
                "ON CREATE SET d.is_placeholder = true",
                did=doc_id,
            )
            tx.run(
                "MATCH (p:Plan), (d:Document) "
                "WHERE p.record_id = $pid AND d.record_id = $did "
                "MERGE (p)-[:PLAN_ATTACHED_DOC]->(d)",
                pid=record_id, did=doc_id,
            )
            # ENC-PLN-014 / ENC-FTR-065: inverse DOC_ATTACHED_TO_PLAN
            tx.run(
                "MATCH (p:Plan), (d:Document) "
                "WHERE p.record_id = $pid AND d.record_id = $did "
                "MERGE (d)-[:DOC_ATTACHED_TO_PLAN]->(p)",
                pid=record_id, did=doc_id,
            )

        # PLAN_IMPLEMENTS -> related feature
        feat_id = _bare_id(record.get("related_feature_id", "") or "")
        if feat_id:
            # Placeholder MERGE so the edge lands even if the Feature node
            # has not been projected yet (ENC-TSK-E01).
            # ENC-TSK-E06: tag placeholder on create.
            tx.run(
                "MERGE (f:Feature {record_id: $fid}) "
                "ON CREATE SET f.is_placeholder = true",
                fid=feat_id,
            )
            tx.run(
                "MATCH (p:Plan), (f:Feature) "
                "WHERE p.record_id = $pid AND f.record_id = $fid "
                "MERGE (p)-[:PLAN_IMPLEMENTS]->(f)",
                pid=record_id, fid=feat_id,
            )

    # ENC-FTR-052 / ENC-TSK-B89: Lesson edge projections.
    # Lesson records carry evidence_chain (list of tracker/document record IDs)
    # as their canonical LEARNED_FROM source plus extensions[].evidence_ids for
    # append-only extensions. Prior to ENC-TSK-B89, _reconcile_edges() had no
    # lesson branch at all, so every lesson node landed with exactly one edge
    # (BELONGS_TO->Project) and zero relationship neighbors. LEARNED_FROM edges
    # existed only for the subset of lessons whose evidence_chain entries were
    # historically backfilled into rel# DynamoDB items by ENC-TSK-C38 Phase 2;
    # any lesson created or updated after that backfill had zero LEARNED_FROM
    # edges in the graph, breaking depth-1 traversal from lessons (see
    # ENC-ISS-189 for the canonical legacy-ID manifestation).
    #
    # Fix: iterate both evidence_chain and every extension's evidence_ids,
    # dedupe, then emit (Lesson)-[:LEARNED_FROM]->(target) via the E01
    # placeholder MERGE pattern so the edge lands even when the target node is
    # not yet projected. Unrecognised ID prefixes (e.g. legacy JAP-*, MJR-*
    # records or pre-ENC-FTR-056 flat IDs) fall back to the legacy unlabelled
    # MATCH with a WARNING log line so OGTM does not silently drop the edge.
    if record_type == "lesson":
        evidence_ids_ordered: List[str] = []
        seen_ev: set = set()

        def _collect_evidence(eid: Any) -> None:
            if eid is None:
                return
            if isinstance(eid, dict):
                return
            val = _bare_id(str(eid).strip())
            if val and val not in seen_ev:
                seen_ev.add(val)
                evidence_ids_ordered.append(val)

        for ev in record.get("evidence_chain", []) or []:
            _collect_evidence(ev)
        # Extensions are append-only lesson_version increments; each carries
        # its own evidence_ids bag. Project every extension's evidence IDs as
        # additional LEARNED_FROM edges so the corpus-wide lesson graph
        # reflects the full provenance, not just the bootstrap chain.
        for ext in record.get("extensions", []) or []:
            if isinstance(ext, dict):
                for ev in ext.get("evidence_ids", []) or []:
                    _collect_evidence(ev)

        logger.info(
            "[INFO] Lesson reconcile %s: evidence_ids=%d (deduped)",
            record_id, len(evidence_ids_ordered),
        )

        for ev_id in evidence_ids_ordered:
            target_label = _infer_label_from_id(ev_id)
            if target_label:
                # Placeholder MERGE on inferred label so the edge lands even
                # when the target node has not been projected yet
                # (ENC-TSK-E01 pattern).
                # ENC-TSK-E06: tag placeholder on create.
                tx.run(
                    f"MERGE (t:{target_label} {{record_id: $tid}}) "
                    "ON CREATE SET t.is_placeholder = true",
                    tid=ev_id,
                )
                tx.run(
                    f"MATCH (l:Lesson), (t:{target_label}) "
                    "WHERE l.record_id = $lid AND t.record_id = $tid "
                    "MERGE (l)-[:LEARNED_FROM]->(t)",
                    lid=record_id, tid=ev_id,
                )
            else:
                # Unknown/legacy ID prefix: fall back to unlabelled MATCH so
                # pre-ENC-FTR-056 legacy IDs (JAP-*, MJR-*, bare non-canonical
                # strings) still produce an edge when the target happens to
                # be present. ENC-ISS-189 documents why the warning is
                # useful for future rationalization work.
                logger.warning(
                    "[WARNING] Lesson %s evidence_id %s has unrecognised ID prefix; "
                    "falling back to unlabelled MATCH (edge may not land if target absent)",
                    record_id, ev_id,
                )
                tx.run(
                    "MATCH (l:Lesson), (t {record_id: $tid}) "
                    "WHERE l.record_id = $lid "
                    "MERGE (l)-[:LEARNED_FROM]->(t)",
                    lid=record_id, tid=ev_id,
                )

    # ENC-FTR-065 / ENC-PLN-014: Document edge projections
    if record_type == "document":
        doc_id = record_id  # already _bare_id-stripped at the top of the function

        # Note: BELONGS_TO -> Project is emitted by the record_type-agnostic
        # block above at lines 198-205 and fires automatically for documents
        # once RECORD_TYPE_TO_LABEL contains the "document" entry. The
        # outgoing-edge delete prelude at lines 183-194 also strips the
        # Document node's outgoing relationships before the new MERGEs run,
        # so re-running graph_sync on a backfill is idempotent.

        # RELATED_TO -> each related_items target (any node label)
        # ENC-TSK-E01: placeholder MERGE on inferred label so the edge lands
        # even when the target has not been projected yet.
        for related_id in record.get("related_items", []) or []:
            related_id = _bare_id(related_id) if related_id else ""
            if not related_id:
                continue
            target_label = _infer_label_from_id(related_id)
            if target_label:
                # ENC-TSK-E06: tag placeholder on create.
                tx.run(
                    f"MERGE (t:{target_label} {{record_id: $tid}}) "
                    "ON CREATE SET t.is_placeholder = true",
                    tid=related_id,
                )
                tx.run(
                    f"MATCH (d:Document), (t:{target_label}) "
                    "WHERE d.record_id = $did AND t.record_id = $tid "
                    "MERGE (d)-[:RELATED_TO]->(t)",
                    did=doc_id, tid=related_id,
                )
            else:
                logger.warning(
                    "[WARNING] Document %s related_item %s has unrecognised ID prefix; "
                    "falling back to unlabelled MATCH",
                    doc_id, related_id,
                )
                tx.run(
                    "MATCH (d:Document), (t {record_id: $tid}) "
                    "WHERE d.record_id = $did "
                    "MERGE (d)-[:RELATED_TO]->(t)",
                    did=doc_id, tid=related_id,
                )

        # INFORMED_BY -> source document; INFORMS inverse from source -> this doc
        # ENC-TSK-E01: placeholder MERGE so edges land even if the source
        # document has not been projected yet.
        for informed_id in record.get("informed_by", []) or []:
            informed_id = _bare_id(informed_id) if informed_id else ""
            if not informed_id:
                continue
            # ENC-TSK-E06: tag placeholder on create.
            tx.run(
                "MERGE (s:Document {record_id: $sid}) "
                "ON CREATE SET s.is_placeholder = true",
                sid=informed_id,
            )
            tx.run(
                "MATCH (d:Document), (s:Document) "
                "WHERE d.record_id = $did AND s.record_id = $sid "
                "MERGE (d)-[:INFORMED_BY]->(s) "
                "MERGE (s)-[:INFORMS]->(d)",
                did=doc_id, sid=informed_id,
            )

        # --- Subtype-specific document edges (ENC-FTR-077) ---
        doc_subtype = record.get("document_subtype", "")

        # COE: INVESTIGATES / INVESTIGATED_BY (source_incident_id -> Issue/Task)
        if doc_subtype == "coe":
            source_incident_id = record.get("source_incident_id", "")
            if source_incident_id:
                source_incident_id = _bare_id(source_incident_id)
                target_label = _infer_label_from_id(source_incident_id)
                if target_label:
                    tx.run(
                        f"MERGE (t:{target_label} {{record_id: $target_id}}) "
                        "ON CREATE SET t.is_placeholder = true",
                        target_id=source_incident_id,
                    )
                    tx.run(
                        f"MATCH (d:Document), (t:{target_label}) "
                        "WHERE d.record_id = $did AND t.record_id = $target_id "
                        "MERGE (d)-[:INVESTIGATES]->(t) "
                        "MERGE (t)-[:INVESTIGATED_BY]->(d)",
                        did=doc_id, target_id=source_incident_id,
                    )
                else:
                    logger.warning(
                        "[WARNING] COE document %s source_incident_id %s has unrecognised "
                        "ID prefix; skipping INVESTIGATES edge",
                        doc_id, source_incident_id,
                    )

        # Wave: TRACKS_WAVE_OF / HAS_WAVE_DOC (plan_anchor_id -> Plan)
        if doc_subtype == "wave":
            plan_anchor_id = record.get("plan_anchor_id", "")
            if plan_anchor_id:
                plan_anchor_id = _bare_id(plan_anchor_id)
                tx.run(
                    "MERGE (p:Plan {record_id: $plan_id}) "
                    "ON CREATE SET p.is_placeholder = true",
                    plan_id=plan_anchor_id,
                )
                tx.run(
                    "MATCH (d:Document), (p:Plan) "
                    "WHERE d.record_id = $did AND p.record_id = $plan_id "
                    "MERGE (d)-[:TRACKS_WAVE_OF]->(p) "
                    "MERGE (p)-[:HAS_WAVE_DOC]->(d)",
                    did=doc_id, plan_id=plan_anchor_id,
                )

        # Handoff: HANDS_OFF / HANDED_OFF_BY (source_record_id -> Task/Issue/Feature)
        if doc_subtype == "handoff":
            source_record_id = record.get("source_record_id", "")
            if source_record_id:
                source_record_id = _bare_id(source_record_id)
                target_label = _infer_label_from_id(source_record_id)
                if target_label:
                    tx.run(
                        f"MERGE (t:{target_label} {{record_id: $source_rec_id}}) "
                        "ON CREATE SET t.is_placeholder = true",
                        source_rec_id=source_record_id,
                    )
                    tx.run(
                        f"MATCH (d:Document), (t:{target_label}) "
                        "WHERE d.record_id = $did AND t.record_id = $source_rec_id "
                        "MERGE (d)-[:HANDS_OFF]->(t) "
                        "MERGE (t)-[:HANDED_OFF_BY]->(d)",
                        did=doc_id, source_rec_id=source_record_id,
                    )
                else:
                    logger.warning(
                        "[WARNING] Handoff document %s source_record_id %s has unrecognised "
                        "ID prefix; skipping HANDS_OFF edge",
                        doc_id, source_record_id,
                    )

    # GMF: Generation edge projections (DOC-63420302EF65 §8.2)
    if record_type == "generation":
        gen_id = record_id
        # SUCCEEDS -> parent generation (lineage chain)
        parent_gen = record.get("parent_generation_id", "")
        if parent_gen:
            parent_gen = _bare_id(parent_gen)
            tx.run(
                "MATCH (g:Generation), (p:Generation) "
                "WHERE g.record_id = $gid AND p.record_id = $pid "
                "MERGE (g)-[:SUCCEEDS]->(p)",
                gid=gen_id, pid=parent_gen,
            )

    # GMF: target_generation edges on existing types
    if record_type in ("task", "feature", "plan", "lesson"):
        target_gen = record.get("target_generation", "")
        if target_gen:
            target_gen = _bare_id(target_gen)
            edge_type = {
                "task": "TARGETS_GENERATION",
                "feature": "BELONGS_TO_GENERATION",
                "plan": "EXECUTES_WITHIN",
                "lesson": "TARGETS_GENERATION",
            }.get(record_type, "TARGETS_GENERATION")
            label = RECORD_TYPE_TO_LABEL.get(record_type, "Task")
            tx.run(
                f"MATCH (n:{label}), (g:Generation) "
                "WHERE n.record_id = $nid AND g.record_id = $gid "
                f"MERGE (n)-[:{edge_type}]->(g)",
                nid=record_id, gid=target_gen,
            )


# ---------------------------------------------------------------------------
# Typed Relationship Edge Projection (ENC-FTR-049)
# ---------------------------------------------------------------------------

RELATIONSHIP_TYPE_TO_EDGE_LABEL = {
    "blocks": "BLOCKS", "blocked-by": "BLOCKED_BY",
    "duplicates": "DUPLICATES", "duplicated-by": "DUPLICATED_BY",
    # ENC-ISS-178: typed 'relates-to' projects to RELATED_TO so it converges with the
    # legacy related_*_ids projection and is visible via tracker.graphsearch
    # edge_types=['RELATED_TO']. Previously emitted 'RELATES_TO' which silently
    # diverged from the legacy label and broke OGTM end-to-end traversability.
    "relates-to": "RELATED_TO",
    "parent-of": "PARENT_OF", "child-of": "CHILD_OF_TYPED",
    "depends-on": "DEPENDS_ON", "depended-on-by": "DEPENDED_ON_BY",
    "clones": "CLONES", "cloned-by": "CLONED_BY",
    "affects": "AFFECTS", "affected-by": "AFFECTED_BY",
    "tests": "TESTS", "tested-by": "TESTED_BY",
    "consumes-from": "CONSUMES_FROM", "produces-for": "PRODUCES_FOR",
    # ENC-ISS-150 / ENC-TSK-B14: Plan edge types
    "plan-contains": "PLAN_CONTAINS",
    "plan-attached-doc": "PLAN_ATTACHED_DOC",
    "plan-implements": "PLAN_IMPLEMENTS",
    # ENC-FTR-052 / ENC-TSK-983: Lesson edge types
    "learned-from": "LEARNED_FROM", "teaches": "TEACHES",
    "supersedes": "SUPERSEDES", "superseded-by": "SUPERSEDED_BY",
    # ENC-FTR-061: Handoff edge types
    "hands-off": "HANDS_OFF", "handed-off-by": "HANDED_OFF_BY",
    # ENC-TSK-960: Coordination dispatch edge types
    "dispatches": "DISPATCHES", "dispatched-by": "DISPATCHED_BY",
    # ENC-FTR-076 / ENC-TSK-E08: Component proposal provenance
    "component-proposed-by": "COMPONENT_PROPOSED_BY",
    "proposes-component": "PROPOSES_COMPONENT",
    # ENC-PLN-014 / ENC-FTR-065: Document edge types
    "doc-attached-to-plan": "DOC_ATTACHED_TO_PLAN",  # Document -> Plan (inverse of plan-attached-doc)
    "informed-by": "INFORMED_BY",                      # Document -> Document (GDMP provenance)
    "informs": "INFORMS",                              # Document -> Document (inverse provenance)
    # ENC-FTR-077: Docstore subtype edges
    "investigates": "INVESTIGATES",                    # Document (coe) -> Issue/Task
    "investigated-by": "INVESTIGATED_BY",              # Issue/Task -> Document (coe)
    "tracks-wave-of": "TRACKS_WAVE_OF",                # Document (wave) -> Plan
    "has-wave-doc": "HAS_WAVE_DOC",                    # Plan -> Document (wave)
    # GMF: Generational Metabolism Framework (DOC-63420302EF65 §8.2)
    "succeeds": "SUCCEEDS",                            # Generation -> Generation (lineage)
    "belongs-to-generation": "BELONGS_TO_GENERATION",  # Feature -> Generation
    "synthesized-in": "SYNTHESIZED_IN",                # Lesson -> Chapter document
    "seeds-thesis-of": "SEEDS_THESIS_OF",              # Chapter document -> Generation
    "advances-generation": "ADVANCES_GENERATION",      # DeploymentDecision -> Generation
    "targets-generation": "TARGETS_GENERATION",        # Task -> Generation
    "executes-within": "EXECUTES_WITHIN",              # Plan -> Generation
    # ENC-FTR-076 v2 / ENC-TSK-F45: Component-task lifecycle edges
    "designs": "DESIGNS",                              # Component -> Task
    "designed-by": "DESIGNED_BY",                     # Task -> Component
    "implements": "IMPLEMENTS",                        # Component -> Task (IMPLEMENTS label shared with Task->Feature generic edge)
    "implemented-by": "IMPLEMENTED_BY",               # Task -> Component
    "deploys": "DEPLOYS",                              # Component -> Task
    "deployed-by": "DEPLOYED_BY",                     # Task -> Component
}


def _upsert_relationship_edge(tx, record: Dict[str, Any]) -> None:
    """MERGE a typed relationship edge with properties from a DynamoDB relationship record."""
    rel_type = record.get("relationship_type", "")
    edge_label = RELATIONSHIP_TYPE_TO_EDGE_LABEL.get(rel_type)
    if not edge_label:
        return

    source_id = _bare_id(record.get("source_id", ""))
    target_id = _bare_id(record.get("target_id", ""))
    if not source_id or not target_id:
        return

    props = {}
    for key in ("weight", "confidence", "reason", "provenance", "is_inverse", "created_at"):
        val = record.get(key)
        if val is not None:
            props[key] = float(val) if key in ("weight", "confidence") else val

    # ENC-TSK-F45 / ENC-TSK-E01: Ensure labeled placeholder nodes exist for both
    # endpoints so edges land even when one side (e.g. comp-* Component nodes) has
    # not yet been projected to Neo4j. Mirrors the PLAN_CONTAINS/LEARNED_FROM
    # placeholder pattern in _reconcile_edges.
    for nid in (source_id, target_id):
        n_label = _infer_label_from_id(nid)
        if n_label:
            tx.run(
                f"MERGE (n:{n_label} {{record_id: $rid}}) ON CREATE SET n.is_placeholder = true",
                rid=nid,
            )

    cypher = (
        f"MATCH (s {{record_id: $source_id}}), (t {{record_id: $target_id}}) "
        f"MERGE (s)-[r:{edge_label} {{source_id: $source_id, target_id: $target_id}}]->(t) "
        "SET r += $props"
    )
    tx.run(cypher, source_id=source_id, target_id=target_id, props=props)


def _delete_relationship_edge(tx, record_id_sk: str) -> None:
    """Delete a typed relationship edge from Neo4j using the DynamoDB SK."""
    parts = record_id_sk.split("#")
    if len(parts) < 4 or parts[0] != "rel":
        return
    source_id = parts[1]
    rel_type = parts[2]
    target_id = parts[3]

    edge_label = RELATIONSHIP_TYPE_TO_EDGE_LABEL.get(rel_type)
    if not edge_label:
        return

    cypher = (
        f"MATCH (s {{record_id: $source_id}})-[r:{edge_label}]->(t {{record_id: $target_id}}) "
        "DELETE r"
    )
    tx.run(cypher, source_id=source_id, target_id=target_id)


def _delete_node(tx, record_id: str) -> None:
    """DETACH DELETE a node by record_id across all labels."""
    for label in RECORD_TYPE_TO_LABEL.values():
        tx.run(
            f"MATCH (n:{label} {{record_id: $rid}}) DETACH DELETE n",
            rid=record_id,
        )


# ---------------------------------------------------------------------------
# SQS event processing
# ---------------------------------------------------------------------------

def _extract_stream_record(sqs_body: Dict) -> Optional[Dict]:
    """Extract the DynamoDB stream record from an SQS message body."""
    # EventBridge Pipe wraps stream records in the SQS body
    if "dynamodb" in sqs_body:
        return sqs_body
    # Sometimes the body is double-wrapped
    if isinstance(sqs_body, str):
        try:
            return json.loads(sqs_body)
        except (json.JSONDecodeError, TypeError):
            return None
    return sqs_body


def _process_record(driver, stream_record: Dict) -> None:
    """Process a single DynamoDB stream record."""
    event_name = stream_record.get("eventName", "")
    dynamodb = stream_record.get("dynamodb", {})

    if event_name in ("INSERT", "MODIFY"):
        new_image = dynamodb.get("NewImage", {})
        if not new_image:
            return

        record = _normalize_record_for_graph(_deser_image(new_image))
        record_type = record.get("record_type", "")
        old_image = dynamodb.get("OldImage", {})
        old_record = _normalize_record_for_graph(_deser_image(old_image)) if old_image else {}
        stale_placeholder_refs = _collect_placeholder_target_refs(old_record) - _collect_placeholder_target_refs(record)

        # ENC-FTR-049: Handle typed relationship records
        if record_type == "relationship":
            rel_status = record.get("status", "")
            record_id_sk = record.get("record_id", "")
            relationship_refs = (
                _collect_placeholder_target_refs(record)
                if rel_status == "archived"
                else set()
            )
            with driver.session() as session:
                if rel_status == "archived":
                    # Soft-deleted: remove edge from Neo4j projection
                    session.execute_write(lambda tx: _delete_relationship_edge(tx, record_id_sk))
                    if relationship_refs:
                        session.execute_write(lambda tx: _purge_orphan_placeholders(tx, relationship_refs))
                    logger.info(
                        "[INFO] Archived relationship edge removed from graph: %s",
                        record_id_sk,
                    )
                else:
                    session.execute_write(lambda tx: _upsert_relationship_edge(tx, record))
                    logger.info(
                        "[INFO] Synced relationship %s -> %s (%s, event=%s)",
                        record.get("source_id", ""), record.get("target_id", ""),
                        record.get("relationship_type", ""), event_name,
                    )
            return

        # Skip non-entity records
        if record_type not in RECORD_TYPE_TO_LABEL:
            return

        # Skip COUNTER records
        record_id = record.get("record_id", record.get("item_id", ""))
        if record_id and record_id.startswith("COUNTER-"):
            return

        with driver.session() as session:
            # Ensure project node exists
            project_id = record.get("project_id", "")
            if project_id:
                session.execute_write(lambda tx: _upsert_project_node(tx, project_id))

            session.execute_write(lambda tx: _upsert_node(tx, record))
            session.execute_write(lambda tx: _reconcile_edges(tx, record))
            if stale_placeholder_refs:
                session.execute_write(lambda tx: _purge_orphan_placeholders(tx, stale_placeholder_refs))

            # ENC-TSK-B94: Incremental Titan V2 embedding. Runs inline on the
            # already-async SQS consumer so the user-visible mutation path is
            # unaffected. Wrapped in try/except so Bedrock, IAM, or vector
            # model failures NEVER break the primary node + edge projection.
            # Skip non-embeddable record types (e.g. "generation") fast.
            if record_type in EMBEDDABLE_RECORD_TYPES:
                try:
                    bare = _bare_id(record_id)
                    label = RECORD_TYPE_TO_LABEL.get(record_type)
                    existing_hash = session.execute_read(
                        lambda tx: _read_existing_embedding_hash(tx, label, bare)
                    )
                    # Thread the existing hash into the record so the helper
                    # can short-circuit no-op MODIFY events (e.g. status
                    # transitions that do not change title/intent/description).
                    record["_existing_embedding_hash"] = existing_hash
                    payload = compute_embedding_for_record(record)
                    if payload is not None:
                        session.execute_write(
                            lambda tx: _write_embedding(tx, label, bare, payload)
                        )
                        logger.info(
                            "[INFO] Embedded %s %s (dims=%d, hash=%s)",
                            record_type, bare, len(payload[EMBEDDING_PROPERTY]),
                            payload[EMBEDDING_HASH_PROPERTY],
                        )
                    else:
                        logger.info(
                            "[INFO] Skipped embedding for %s %s (no-op or empty text or bedrock failure)",
                            record_type, bare,
                        )
                except Exception:
                    logger.exception(
                        "[ERROR] Incremental embedding failed for %s %s; "
                        "primary projection preserved",
                        record_type, record_id,
                    )

        logger.info(
            "[INFO] Synced %s %s (event=%s, project=%s)",
            record_type, record_id, event_name, record.get("project_id", ""),
        )

    elif event_name == "REMOVE":
        old_image = dynamodb.get("OldImage", {})
        old_record = _normalize_record_for_graph(_deser_image(old_image)) if old_image else {}
        keys = dynamodb.get("Keys", {})
        record_id_val = _extract_remove_record_id(keys, old_record)
        if not record_id_val:
            return

        # ENC-FTR-049: Handle relationship record removal
        if record_id_val.startswith("rel#"):
            relationship_refs = _collect_placeholder_target_refs(old_record)
            if not relationship_refs:
                relationship_refs = _relationship_placeholder_refs_from_sk(record_id_val)
            with driver.session() as session:
                session.execute_write(lambda tx: _delete_relationship_edge(tx, record_id_val))
                if relationship_refs:
                    session.execute_write(lambda tx: _purge_orphan_placeholders(tx, relationship_refs))
            logger.info("[INFO] Deleted relationship edge %s (event=REMOVE)", record_id_val)
            return

        # Extract the actual item_id from the record_id key
        # DynamoDB record_id format: "task#ENC-TSK-123" or bare "ENC-TSK-123"
        item_id = record_id_val.split("#", 1)[-1] if "#" in record_id_val else record_id_val
        stale_placeholder_refs = _collect_placeholder_target_refs(old_record)

        with driver.session() as session:
            session.execute_write(lambda tx: _delete_node(tx, item_id))
            if stale_placeholder_refs:
                session.execute_write(lambda tx: _purge_orphan_placeholders(tx, stale_placeholder_refs))

        logger.info("[INFO] Deleted node %s (event=REMOVE)", item_id)


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """SQS-triggered handler. Processes DynamoDB stream records from EventBridge Pipe."""
    records = event.get("Records", [])
    if not records:
        return {"statusCode": 200, "body": "no records"}

    driver = _get_neo4j_driver()
    if driver is None:
        logger.error("[ERROR] Neo4j driver unavailable; returning success to avoid infinite SQS retry")
        return {"statusCode": 200, "body": "neo4j unavailable - skipping"}

    processed = 0
    errors = 0

    for sqs_record in records:
        try:
            body = sqs_record.get("body", "{}")
            if isinstance(body, str):
                body = json.loads(body)

            stream_record = _extract_stream_record(body)
            if stream_record and "dynamodb" in stream_record:
                _process_record(driver, stream_record)
                processed += 1
        except Exception:
            errors += 1
            logger.exception("[ERROR] Failed to process SQS record")
            # Don't re-raise; let the batch continue.
            # Failed messages will be retried via SQS visibility timeout
            # and eventually land in DLQ after maxReceiveCount.

    logger.info("[INFO] Batch complete: processed=%d, errors=%d, total=%d", processed, errors, len(records))

    # If ALL records failed, raise to trigger SQS retry for the batch
    if errors > 0 and processed == 0:
        raise RuntimeError(f"All {errors} records in batch failed")

    return {"statusCode": 200, "body": json.dumps({"processed": processed, "errors": errors})}
