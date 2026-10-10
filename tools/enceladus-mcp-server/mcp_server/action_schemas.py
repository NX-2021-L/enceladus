"""Input schemas for actions whose underlying tool has no raw ``Tool(...)`` definition.

DVP-TSK-843.  server.py lists ~53 flat tools with a real ``inputSchema``; the 55
actions below (graph, manifest, agent, component, plan, handoff, lesson,
escalation, ... families) are reachable only through the search / execute /
coordination wrappers, so no schema was retrievable for them.

Single-source rule: each schema is declared ONCE, here, keyed by the underlying
tool name, and is the only place the action argument contract is written down.
It is kept honest against the handlers in server.py by tests, not by convention:

  * ``test_action_registry_parity.py`` reads every handler's source with
    ``parity/args_introspect.py`` and fails if a handler consumes an argument key
    that is not declared here, or this table declares a key the handler never
    reads (except in ``PASSTHROUGH_TOOLS``, which forward the whole dict).
  * every ``required`` key is proven to be enforced by the handler: the test
    calls the handler without that key, with all network helpers replaced by a
    tripwire, and fails if the handler reaches the network.
  * a tool that gains a raw ``Tool(...)`` definition must be removed from this
    table (the definition wins) -- the test fails on duplicates.

Keys that the handler forwards without checking, but the backend API rejects when
absent, are NOT listed in ``required``; they carry ``"x-io-required-by": "backend"``
so a client can still tell the caller must supply them.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Optional

BACKEND = "backend"

_GOV = {
    "type": "string",
    "description": "Current governance hash; obtain from governance.hash (search).",
}


def _str(description: str, *, backend: bool = False, enum: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    prop: Dict[str, Any] = {"type": "string", "description": description}
    if enum is not None:
        prop["enum"] = list(enum)
    if backend:
        prop["x-io-required-by"] = BACKEND
    return prop


def _int(description: str) -> Dict[str, Any]:
    return {"type": "integer", "description": description}


def _num(description: str) -> Dict[str, Any]:
    return {"type": "number", "description": description}


def _bool(description: str) -> Dict[str, Any]:
    return {"type": "boolean", "description": description}


def _obj(description: str, *, backend: bool = False) -> Dict[str, Any]:
    prop: Dict[str, Any] = {"type": "object", "description": description}
    if backend:
        prop["x-io-required-by"] = BACKEND
    return prop


def _arr(description: str, items: Optional[Mapping[str, Any]] = None, *, backend: bool = False) -> Dict[str, Any]:
    prop: Dict[str, Any] = {
        "type": "array",
        "items": dict(items) if items is not None else {"type": "string"},
        "description": description,
    }
    if backend:
        prop["x-io-required-by"] = BACKEND
    return prop


def _schema(properties: Mapping[str, Any], required: Iterable[str] = (), **extra: Any) -> Dict[str, Any]:
    schema: Dict[str, Any] = {"type": "object", "properties": dict(properties)}
    req = list(required)
    if req:
        schema["required"] = req
    schema.update(extra)
    return schema


def _governed(properties: Mapping[str, Any], required: Iterable[str] = ()) -> Dict[str, Any]:
    props = {"governance_hash": _GOV, **properties}
    return _schema(props, ["governance_hash", *required])


_PROJECT = _str("Project id (for example 'enceladus' or 'devops').")
_RECORD_ID = "Tracker record id (for example DVP-TSK-001)."
_DOC_ID = "Document id (DOC-...)."
_PROVIDER = _str("Provider identity forwarded to the backend for checkout-ownership checks.")
_SCI = _str("Session Claim ID returned by agent.claim; forwarded as-is (ENC-ISS-441).")
_CRQ = _str("Coordination request id (CRQ-* or DSP-*).")
_CURSOR = _str("Opaque pagination cursor from a previous response's next_cursor.")
_PAGE = _int("Maximum records per page.")

# Tools whose handler forwards the caller's whole argument dict to the backend; the
# introspection test only checks that every handler-read key is declared for these.
PASSTHROUGH_TOOLS = frozenset({"documents_patch_section"})

# Tools whose "required" cannot be expressed as a plain list (alias pairs): the
# schema carries an ``anyOf`` of ``required`` clauses instead.
ALIAS_REQUIRED_TOOLS = frozenset({"telemetry_rank"})

ACTION_INPUT_SCHEMAS: Dict[str, Dict[str, Any]] = {
    # ------------------------------------------------------------------ search
    "projects_prefix_map": _schema({}),
    "documents_manifest": _schema(
        {
            "document_id": _str(_DOC_ID),
            "digest_only": _bool("If true, return only the digest portion of the manifest."),
        },
        ["document_id"],
    ),
    "documents_history": _schema(
        {
            "document_id": _str(_DOC_ID),
            "since": _str("Lower bound (ISO-8601) on change timestamps."),
            "until": _str("Upper bound (ISO-8601) on change timestamps."),
            "actor": _str("Filter by the actor that made the change."),
            "op": _str("Filter by operation type."),
            "block_id": _str("Filter by document block id."),
            "cursor": _CURSOR,
            "page_size": _PAGE,
        },
        ["document_id"],
    ),
    "documents_diff": _schema(
        {
            "document_id": _str(_DOC_ID),
            "from": _str("Version to diff from."),
            "to": _str("Version to diff to."),
        },
        ["document_id"],
    ),
    "tracker_graphsearch": _schema(
        {
            "search_type": _str(
                "Graph search mode.",
                enum=["adjacency", "dedup_convergence", "hybrid", "keyword", "laplacian",
                      "neighbors", "path", "sheaf_cohomology", "traversal"],
            ),
            "project_id": _PROJECT,
            "record_id": _str("Anchor record id for neighbor/traversal searches."),
            "depth": _int("Traversal depth."),
            "direction": _str("Traversal direction.", enum=["up", "down", "both"]),
            "record_type": _str("Restrict results to one record type."),
            "keyword": _str("Keyword query (alias of query)."),
            "query": _str("Keyword or hybrid query text."),
            "from_record_id": _str("Path search start record id."),
            "to_record_id": _str("Path search end record id."),
            "edge_types": {
                "anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "string"}],
                "description": "Relationship edge types to follow (ENC-FTR-049).",
            },
            "edge_type": _str("Single relationship edge type to follow."),
            "min_weight": _num("Minimum edge weight."),
            "anchor_record_id": _str("Graph anchor for hybrid retrieval (ENC-TSK-B92)."),
            "top_n": _int("Hybrid retrieval result count."),
            "include_below_threshold": _bool("Include lessons below the FSRS-6 T3 threshold in hybrid retrieval."),
        },
        ["search_type", "project_id"],
    ),
    "tracker_embeddings_for": _schema(
        {
            "project_id": _PROJECT,
            "record_ids": {
                "anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "string"}],
                "description": "Record ids (array, or comma-separated string) whose stored embeddings to return. Admin-scoped.",
            },
        },
        ["project_id", "record_ids"],
    ),
    "tracker_sheaf_cohomology": _schema(
        {
            "project_id": _PROJECT,
            "vertex_set_query": _str("Optional anchor restricting the computation to a connected subgraph."),
        },
        ["project_id"],
    ),
    "tracker_graph_laplacian": _schema(
        {
            "project_id": _str("Project id; defaults to 'enceladus'."),
            "vertex_set_query": _str("Keyword query selecting the vertex set."),
            "record_ids": {
                "anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "string"}],
                "description": "Explicit vertex set (array, or comma-separated string).",
            },
            "edge_type_filter": {
                "anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "string"}],
                "description": "Restrict the induced subgraph to these edge types.",
            },
            "k": _int("Number of smallest Laplacian eigenvalues to return."),
            "limit": _int("Maximum vertices in the induced subgraph."),
            "normalization": _str("Laplacian normalization mode."),
        },
    ),
    "tracker_manifest": _schema(
        {
            "record_id": _str(_RECORD_ID),
            "fields": _arr("Restrict the manifest to these field names; identity and freshness fields are always kept."),
        },
        ["record_id"],
    ),
    "tracker_get_acs": _schema(
        {
            "record_id": _str(_RECORD_ID),
            "indices": _arr("Zero-based acceptance-criterion indices to fetch.", {"type": "integer", "minimum": 0}),
            "content_hash": _str("Manifest content_hash for the freshness check; a stale hash returns a staleness envelope."),
        },
        ["record_id", "indices"],
    ),
    "tracker_worklog_timeline": _schema({"record_id": _str(_RECORD_ID)}, ["record_id"]),
    "tracker_worklogs": _schema(
        {
            "record_id": _str(_RECORD_ID),
            "since": _str("Lower bound (ISO-8601) on worklog timestamps."),
            "until": _str("Upper bound (ISO-8601) on worklog timestamps."),
            "ids": _arr("Worklog ids (wl-NNNN) to fetch."),
            "content_hash": _str("Manifest content_hash for the freshness check."),
        },
        ["record_id"],
    ),
    "tracker_manifest_bulk": _schema(
        {
            "record_ids": _arr("Record ids to fetch manifests for (non-empty; capped per call by the server)."),
            "fields": _arr("Restrict each manifest to these field names."),
        },
        ["record_ids"],
    ),
    "telemetry_rank": _schema(
        {
            "attribute_name": _str("Telemetry-eligible attribute to rank."),
            "attribute": _str("Alias of attribute_name."),
            "project_id": _str("Project id; defaults to 'enceladus'."),
            "record_type": _str("Record type; resolved from the attribute when omitted."),
            "limit": _int("Maximum rows (default 10, max 100)."),
            "top_n": _int("Alias of limit."),
            "cursor": _CURSOR,
        },
        anyOf=[{"required": ["attribute_name"]}, {"required": ["attribute"]}],
    ),
    "tracker_list_relationships": _schema(
        {
            "project_id": _PROJECT,
            "source_id": _str("Filter by source record id."),
            "target_id": _str("Filter by target record id."),
            "relationship_type": _str("Filter by relationship type."),
            "min_weight": _num("Minimum edge weight."),
            "provenance": _str("Filter by edge provenance."),
            "page_size": _PAGE,
            "cursor": _CURSOR,
        },
        ["project_id"],
    ),
    "escalation_get": _schema(
        {"project_id": _PROJECT, "escalation_id": _str("Escalation id (ENC-ESC-...).")},
        ["project_id", "escalation_id"],
    ),
    "escalation_list": _schema(
        {
            "project_id": _PROJECT,
            "status": _str("Filter by escalation status."),
            "target_record_id": _str("Filter by the record the escalation targets."),
            "session_id": _str("Filter by originating session id (ENC-SES-...)."),
            "page_size": _PAGE,
        },
        ["project_id"],
    ),
    "tracker_list_lessons": _schema(
        {
            "project_id": _PROJECT,
            "status": _str("Filter by lesson status."),
            "category": _str("Filter by lesson category."),
            "page_size": _PAGE,
            "cursor": _CURSOR,
        },
        ["project_id"],
    ),
    "plan_objectives_status": _schema(
        {"record_id": _str("Plan record id (for example DVP-PLN-001).")}, ["record_id"],
    ),
    # ------------------------------------------------------------ coordination
    "agent_register": _schema(
        {
            "agent_type_id": _str("Agent type id (ENC-AGT-...)."),
            "runtime": _str("Runtime identifier for the session."),
            "parent_session_id": _str("Parent session id (ENC-SES-...)."),
            "status": _str("Initial session status."),
            "credential_id": _str("Optional ENC-CRED credential binding (ENC-TSK-J43)."),
        },
    ),
    "agent_claim": _schema(
        {
            "session_id": _str("Pre-minted session id (ENC-SES-...) to claim."),
            "expected_agent_type_id": _str("Agent type id the claim must match."),
        },
        ["session_id"],
    ),
    "agent_list": _schema(
        {
            "status": _str("Filter by session status."),
            "agent_type_id": _str("Filter by agent type id."),
        },
    ),
    "agent_retire": _schema({"session_id": _str("Session id (ENC-SES-...) to retire.")}, ["session_id"]),
    "agent_checkout_release_backfill": _schema(
        {
            "dry_run": _bool("If true, report the checkouts that would be released without releasing them."),
            "session_ids": _arr("Restrict the backfill to these retired session ids."),
        },
    ),
    "agent_type_list": _schema({"status": _str("Filter by agent-type status.")}),
    "agent_type_register": _schema(
        {
            "surface": _str("Agent surface (for example claude-code)."),
            "model": _str("Model identifier."),
            "cost_tier": _str("Cost tier."),
        },
    ),
    "escalation_watch": _schema(
        {
            "session_id": _str("Session id (ENC-SES-...) whose escalations to poll."),
            "since": _str("Cursor: pass the previous response's next_cursor."),
            "project_id": _PROJECT,
        },
        ["session_id"],
    ),
    # ----------------------------------------------------------------- execute
    "tracker_relate": _governed(
        {
            "source_id": _str("Record that gains the related_* pointer."),
            "target_id": _str("Record to relate; must be a task, issue or feature."),
            "provider": _PROVIDER,
            "coordination_request_id": _CRQ,
            "sci": _SCI,
        },
        ["source_id", "target_id"],
    ),
    "documents_patch_section": {
        **_governed(
            {
                "document_id": _str(_DOC_ID),
                "op": _str("Section operation (for example replace, insert_after, delete).", backend=True),
                "anchor": _obj("Section anchor: {block_id} or {heading_path}.", backend=True),
                "body": _str("Markdown body for the operation."),
                "if_match": _str("Content hash precondition; required by the backend (no unconditional mode).", backend=True),
                "include_heading": _bool("Include the heading in the replaced body."),
                "rebase_headings": _bool("Rebase heading levels to the anchor (default true)."),
                "idempotency_key": _str("Caller-supplied idempotency key."),
                "caused_by": _str("Record or document that caused this change."),
                "dry_run": _bool("Validate and report without writing."),
                "provider": _PROVIDER,
                "sci": _SCI,
            },
            ["document_id"],
        ),
        "additionalProperties": True,
    },
    "tracker_create_relationship": _governed(
        {
            "project_id": _PROJECT,
            "source_id": _str("Source record id.", backend=True),
            "target_id": _str("Target record id.", backend=True),
            "relationship_type": _str("Typed relationship (ENC-FTR-049).", backend=True),
            "reason": _str("Why the relationship exists."),
            "weight": _num("Edge weight."),
            "confidence": _num("Edge confidence."),
            "provenance": _str("Edge provenance."),
        },
        ["project_id"],
    ),
    "tracker_archive_relationship": _governed(
        {
            "project_id": _PROJECT,
            "source_id": _str("Source record id.", backend=True),
            "target_id": _str("Target record id.", backend=True),
            "relationship_type": _str("Typed relationship to archive.", backend=True),
        },
        ["project_id"],
    ),
    "escalation_request": _governed(
        {
            "project_id": _PROJECT,
            "target_record_id": _str("Record the escalation targets.", backend=True),
            "mutation_type": _str("Lifecycle-forbidden mutation being proposed.", backend=True),
            "payload": _obj("Mutation payload, validated by the backend mutation-handler registry.", backend=True),
            "justification": _str("Why io should approve.", backend=True),
            "expected_version": _int("Record version the mutation was computed against."),
            "requested_by": _str("Requesting identity."),
            "provider": _PROVIDER,
            "coordination_request_id": _CRQ,
            "dispatch_id": _str("Dispatch id (DSP-*)."),
        },
        ["project_id"],
    ),
    "tracker_create_lesson": _governed(
        {
            "project_id": _PROJECT,
            "title": _str("Lesson title.", backend=True),
            "observation": _str("What was observed.", backend=True),
            "insight": _str("What it means.", backend=True),
            "evidence_chain": _arr("Evidence record ids supporting the lesson.", backend=True),
            "category": _str("Lesson category."),
            "provenance": _str("Lesson provenance."),
            "confidence": _num("Confidence in the lesson."),
            "analysis_reference": _str("Analysis document or record reference."),
            "pillar_scores": _obj("Pillar score map."),
            "priority": _str("Lesson priority."),
            "description": _str("Longer description."),
            "related": _arr("Related record ids."),
        },
        ["project_id"],
    ),
    "tracker_extend_lesson": _governed(
        {
            "record_id": _str("Lesson record id."),
            "content": _str("Extension text (append-only).", backend=True),
            "author": _str("Extension author.", backend=True),
            "evidence_ids": _arr("Evidence record ids."),
            "pillar_scores": _obj("Pillar score map."),
        },
        ["record_id"],
    ),
    "document_create_handoff": _governed(
        {
            "project_id": _PROJECT,
            "title": _str("Handoff title."),
            "content": _str("Handoff body (markdown)."),
            "source_record_id": _str("Record the handoff originates from."),
            "prerequisite_state": _str("State required before the handoff can be claimed."),
            "verification_criteria": _str("How completion is verified."),
            "expires_at": _str("Expiry timestamp (ISO-8601)."),
            "action_checklist": _arr("Checklist items.", {}),
            "description": _str("Short description."),
            "keywords": _arr("Keywords."),
            "related_items": _arr("Related record or document ids."),
        },
        ["project_id", "title", "content", "source_record_id"],
    ),
    "document_claim_handoff": _governed({"document_id": _str("Handoff document id.")}, ["document_id"]),
    "document_complete_handoff": _governed({"document_id": _str("Handoff document id.")}, ["document_id"]),
    "document_create_coe": _governed(
        {
            "project_id": _PROJECT,
            "title": _str("COE title."),
            "content": _str("COE body (markdown)."),
            "source_incident_id": _str("Incident the COE analyses."),
            "description": _str("Short description."),
            "keywords": _arr("Keywords."),
            "related_items": _arr("Related record or document ids."),
            "file_name": _str("File name (markdown)."),
            "informed_by": _arr("Documents that informed this COE."),
        },
        ["project_id", "title", "content", "source_incident_id"],
    ),
    "document_create_wave": _governed(
        {
            "project_id": _PROJECT,
            "title": _str("Wave title."),
            "content": _str("Wave body (markdown)."),
            "plan_anchor_id": _str("Plan record the wave is anchored to."),
            "description": _str("Short description."),
            "keywords": _arr("Keywords."),
            "related_items": _arr("Related record or document ids."),
            "file_name": _str("File name (markdown)."),
        },
        ["project_id", "title", "content", "plan_anchor_id"],
    ),
    "document_create_note": _governed(
        {
            "project_id": _PROJECT,
            "title": _str("Note title."),
            "content": _str("Note body (markdown)."),
            "document_subtype": _str("Pinned to 'doc'; any other value is rejected.", enum=["doc"]),
            "description": _str("Short description."),
            "keywords": _arr("Keywords."),
            "related_items": _arr("Related record or document ids."),
            "file_name": _str("File name (markdown)."),
            "informed_by": _arr("Documents that informed this note."),
        },
        ["project_id", "title", "content"],
    ),
    "document_append_handoff_reply": _governed(
        {
            "document_id": _str("Handoff document id."),
            "content": _str("Reply body (markdown)."),
            "agent_layer": _str(
                "Layer of the replying agent.",
                enum=["supervisor", "coord-lead", "dispatched-agent", "product-lead-terminal"],
            ),
            "author": _str("Reply author; defaults to agent_layer."),
            "originating_handoff_ref": _str("Handoff the reply answers; defaults to document_id."),
        },
        ["document_id", "content", "agent_layer"],
    ),
    "document_append_wave_entry": _governed(
        {
            "document_id": _str("Wave document id."),
            "content": _str("Entry body (markdown)."),
            "agent_layer": _str("Layer of the appending agent."),
            "author": _str("Entry author; defaults to agent_layer."),
            "originating_handoff_ref": _str("Handoff the entry relates to."),
        },
        ["document_id", "content", "agent_layer"],
    ),
    "component_propose": _governed(
        {
            "component_id": _str("Proposed component id.", backend=True),
            "display_name": _str("Human-readable component name.", backend=True),
            "project_id": _str("Owning project id.", backend=True),
            "source_paths": _arr("Repository paths the component owns.", backend=True),
            "description": _str("Component description.", backend=True),
            "requested_minimum_transition_type": _str("Minimum transition type requested.", backend=True),
            "proposing_agent_session_id": _str("Proposing session id (ENC-SES-...)."),
            "category": _str("Component category."),
            "component_address": _str("v3 component address."),
            "component_repo_dir": _str("Repository directory for the component."),
            "component_address_class": _str("Component address class."),
            "component_class": _str("Component class."),
            "requested_required_transition_type": _str("Required transition type requested."),
            "required_transition_type_rationale": _str("Rationale for the required transition type."),
        },
    ),
    "component_advance": _governed(
        {
            "component_id": _str("Component id."),
            "target_status": _str("Target lifecycle_status.", backend=True),
            "reason": _str("Reason for the transition."),
        },
        ["component_id"],
    ),
    "component_revert": _governed(
        {
            "component_id": _str("Component id."),
            "reverted_reason": _str("Why the component is reverted (minimum 10 characters; io-only).", backend=True),
        },
        ["component_id"],
    ),
    "component_deprecate": _governed(
        {"component_id": _str("Component id."), "reason": _str("Reason for deprecation (io-only).")},
        ["component_id"],
    ),
    "component_restore": _governed({"component_id": _str("Component id.")}, ["component_id"]),
    "component_add_edge": _governed(
        {
            "component_id": _str("Component id."),
            "edge_type": _str("Edge type (DESIGNS, IMPLEMENTS or DEPLOYS).", backend=True),
            "task_id": _str("Task id the edge points at.", backend=True),
        },
        ["component_id"],
    ),
    "component_remove_edge": _governed(
        {
            "component_id": _str("Component id."),
            "edge_type": _str("Edge type to remove.", backend=True),
            "task_id": _str("Task id the edge points at.", backend=True),
        },
        ["component_id"],
    ),
    "plan_checkout": _governed(
        {
            "record_id": _str("Plan record id."),
            "active_agent_session_id": _str("Claiming session id (ENC-SES-...)."),
            "coordination_request_id": _CRQ,
            "sci": _SCI,
        },
        ["record_id", "active_agent_session_id"],
    ),
    "plan_advance": _governed(
        {
            "record_id": _str("Plan record id."),
            "active_agent_session_id": _str("Owning session id; the checkout service enforces ownership.", backend=True),
            "target_status": _str("Target plan status.", backend=True),
            "provider": _str("Provider identity.", backend=True),
            "transition_evidence": _obj("Evidence required by the transition."),
            "sci": _SCI,
        },
        ["record_id"],
    ),
    "plan_add_objective": _governed(
        {
            "record_id": _str("Plan record id."),
            "objective_task_id": _str("Task id to add as an objective."),
            "provider": _PROVIDER,
        },
        ["record_id", "objective_task_id"],
    ),
    "plan_remove_objective": _governed(
        {
            "record_id": _str("Plan record id."),
            "objective_task_id": _str("Task id to remove; closed objectives cannot be removed."),
            "provider": _PROVIDER,
        },
        ["record_id", "objective_task_id"],
    ),
    "plan_reorder_objectives": _governed(
        {
            "record_id": _str("Plan record id."),
            "ordered_objective_ids": _arr("The existing objectives in their new order (must be a permutation)."),
            "provider": _PROVIDER,
        },
        ["record_id", "ordered_objective_ids"],
    ),
    "plan_replace_objectives": _governed(
        {
            "record_id": _str("Plan record id."),
            "objective_ids": _arr("Complete replacement objectives_set; only allowed while the plan is drafted."),
            "provider": _PROVIDER,
        },
        ["record_id", "objective_ids"],
    ),
}
