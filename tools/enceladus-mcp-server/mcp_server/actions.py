"""Code-mode action registries for search/coordination/execute meta-tools.

DVP-TSK-843 (unwrapped action registry): every registry entry now carries the
metadata a client needs to render the action without the wrapper's free-form
``arguments`` object -- ``title``, MCP ``annotations`` (readOnly / destructive /
idempotent), the optional ``output`` schema for minted ids, and the ``flag`` that
gates the action.  The entry keeps the two keys the dispatchers already read
(``tool`` and ``requires_governance_hash``), so call behaviour is unchanged.

Where the input schema comes from (see ``mcp_server/catalog.py``):
  * a raw ``Tool(...)`` definition in server.py exists for the underlying tool
    -> that definition's ``inputSchema`` is reused verbatim (one declaration);
  * otherwise -> ``mcp_server/action_schemas.py`` declares it once, and
    ``parity/args_introspect.py`` + the registry tests fail if the declaration
    and the handler's actual argument reads ever disagree.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

# Annotation presets: (readOnlyHint, destructiveHint, idempotentHint).
# MCP semantics: destructiveHint is only meaningful when readOnlyHint is false;
# we still emit all three explicitly so consumers never apply the spec defaults
# (destructive=true, idempotent=false) by omission.
READ = (True, False, True)            # no mutation
CREATE = (False, False, False)        # mints something / appends; repeat = new effect
APPEND = (False, False, False)        # append-only; repeat appends again
TRANSITION = (False, False, False)    # state transition / acquire / release; repeat may fail or re-run
SET = (False, True, True)             # overwrites stored state with the given value
OVERWRITE = (False, True, False)      # overwrites or removes state, repeat is not a no-op
ADDITIVE_ONCE = (False, False, True)  # additive, repeating the call changes nothing more

ENTRY_KEYS = ("tool", "title", "annotations")


@dataclass(frozen=True)
class ActionFeatureFlags:
    enable_typed_relationships: bool = False
    enable_escalation_primitive: bool = True
    enable_lesson_primitive: bool = False
    enable_handoff_primitive: bool = False
    enable_component_proposal: bool = False


def _minted(*names: str, description: str = "Minted server-side; never supply on input.") -> Dict[str, Any]:
    """outputSchema declaring server-minted id fields (``x-io-minted``)."""
    return {
        "type": "object",
        "properties": {
            name: {"type": "string", "x-io-minted": True, "description": description}
            for name in names
        },
    }


def _entry(
    tool: str,
    title: str,
    preset: Tuple[bool, bool, bool],
    *,
    gov: bool = False,
    flag: Optional[str] = None,
    output: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    read_only, destructive, idempotent = preset
    entry: Dict[str, Any] = {"tool": tool}
    if gov:
        entry["requires_governance_hash"] = True
    entry["title"] = title
    entry["annotations"] = {
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
    }
    if output is not None:
        entry["output"] = output
    if flag:
        entry["flag"] = flag
    return entry


def build_action_registries(flags: ActionFeatureFlags) -> Tuple[
    Dict[str, Dict[str, Any]],
    Dict[str, Dict[str, Any]],
    Dict[str, Dict[str, Any]],
]:
    """Return (search_actions, coordination_actions, execute_actions)."""
    search_actions: Dict[str, Dict[str, Any]] = {
        # DVP-TSK-843: discovery action. Handled inside the search dispatcher
        # (``builtin``) -- it has no underlying raw tool and needs no boundary
        # allowlist entry; it lists every action reachable through the three
        # code-mode wrappers plus the first-party top-level tools.
        "actions.schemas": {
            "tool": "actions_schemas",
            "builtin": True,
            "title": "List action schemas",
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        },
        "projects.list": _entry("projects_list", "List projects", READ),
        "projects.get": _entry("projects_get", "Get project", READ),
        # ENC-TSK-P74 / FR-B4-2: prefix -> project_id map (server half of ELR v2
        # prefix resolution; ELR-side consumer is a separate PR).
        "projects.prefix_map": _entry("projects_prefix_map", "Get record-id prefix map", READ),
        "tracker.get": _entry("tracker_get", "Get tracker record", READ),
        "tracker.list": _entry("tracker_list", "List tracker records", READ),
        "tracker.pending_updates": _entry("tracker_pending_updates", "List pending tracker updates", READ),
        "tracker.validation_rules": _entry("tracker_validation_rules", "Get tracker edit rules", READ),
        "tracker.creation_rules": _entry("tracker_creation_rules", "Get tracker creation rules", READ),
        "documents.search": _entry("documents_search", "Search documents", READ),
        "documents.get": _entry("documents_get", "Get document", READ),
        "documents.list": _entry("documents_list", "List documents", READ),
        # ENC-TSK-P73 / FR-B3-2..4: read-only document manifest/history/diff
        # forwarding actions (backend: ENC-TSK-P69 manifest, ENC-TSK-P72 history/diff).
        "documents.manifest": _entry("documents_manifest", "Get document manifest", READ),
        "documents.history": _entry("documents_history", "Get document history", READ),
        "documents.diff": _entry("documents_diff", "Diff document versions", READ),
        "reference.search": _entry("reference_search", "Search project reference", READ),
        "deploy.state_get": _entry("deploy_state_get", "Get deploy state", READ),
        "deploy.history": _entry("deploy_history", "Get deploy history", READ),
        "deploy.history_list": _entry("deploy_history_list", "List deploy history", READ),
        "deploy.status": _entry("deploy_status", "Get deploy status", READ),
        "deploy.status_get": _entry("deploy_status_get", "Get deploy status record", READ),
        "deploy.pending_requests": _entry("deploy_pending_requests", "List pending deploy requests", READ),
        "changelog.history": _entry("changelog_history", "Get changelog history", READ),
        "changelog.history_all": _entry("changelog_history_all", "Get changelog history across projects", READ),
        "changelog.version": _entry("changelog_version", "Get changelog version", READ),
        "governance.hash": _entry("governance_hash", "Get governance hash", READ),
        "governance.get": _entry("governance_get", "Get governance file", READ),
        "governance.dictionary": _entry("governance_dictionary", "Get governance data dictionary", READ),
        "system.connection_health": _entry("connection_health", "Check connection health", READ),
        "github.projects_list": _entry("github_projects_list", "List GitHub projects", READ),
        "tracker.graphsearch": _entry("tracker_graphsearch", "Search the tracker graph", READ),
        # ENC-FTR-089 / ENC-TSK-I89: admin-scoped raw-embedding egress.
        "tracker.embeddings_for": _entry("tracker_embeddings_for", "Get record embeddings", READ),
        # ENC-FTR-095 / ENC-TSK-I90: Sheaf Laplacian H1 inconsistency detection
        "tracker.sheaf_cohomology": _entry("tracker_sheaf_cohomology", "Detect graph inconsistencies", READ),
        # ENC-FTR-088 / ENC-TSK-I81: graph Laplacian read action (CSR adjacency +
        # Fiedler eigenvector via scipy.sparse.linalg.eigsh in graph_query_api).
        "tracker.graph_laplacian": _entry("tracker_graph_laplacian", "Compute graph Laplacian", READ),
        # ENC-FTR-097 / ENC-TSK-G27: Manifest Primitive v1 read actions
        "tracker.manifest": _entry("tracker_manifest", "Get record manifest", READ),
        "tracker.get_acs": _entry("tracker_get_acs", "Get acceptance criteria", READ),
        "tracker.worklog_timeline": _entry("tracker_worklog_timeline", "Get worklog timeline", READ),
        "tracker.worklogs": _entry("tracker_worklogs", "Get worklog entries", READ),
        "tracker.manifest_bulk": _entry("tracker_manifest_bulk", "Get record manifests in bulk", READ),
        # ENC-FTR-086 / ENC-TSK-I83: Convergence Surface frequency-rank read action
        "telemetry.rank": _entry("telemetry_rank", "Rank attribute values", READ),
    }

    coordination_actions: Dict[str, Dict[str, Any]] = {
        "capabilities.get": _entry("coordination_capabilities", "Get coordination capabilities", READ),
        "request.get": _entry("coordination_request_get", "Get coordination request", READ),
        # Mints a short-lived Cognito cookie bundle: not read-only, nothing is destroyed.
        "auth.cognito_session": _entry("coordination_cognito_session", "Create Cognito session", CREATE),
        "dispatch_plan.generate": _entry("dispatch_plan_generate", "Generate dispatch plan", CREATE),
        "dispatch_plan.dry_run": _entry("dispatch_plan_dry_run", "Preview dispatch plan", READ),
        # ENC-FTR-084 Phase 1 / ENC-TSK-I93: session-init intent classifier.
        "session.classify_intent": _entry("coordination_classify_intent", "Classify session intent", READ),
        "session.intent_centroid_drift": _entry(
            "coordination_intent_centroid_drift", "Measure intent centroid drift", READ,
        ),
        # ENC-TSK-I38: Agent identity surface (ENC-FTR-117); ported to v4/main by ENC-TSK-J43.
        "agent.register": _entry(
            "agent_register", "Register agent session", CREATE, output=_minted("session_id"),
        ),
        "agent.claim": _entry(
            "agent_claim", "Claim agent session", TRANSITION,
            output=_minted("sci", description="Session Claim ID issued on claim (ENC-ISS-441); never supply on input."),
        ),
        "agent.list": _entry("agent_list", "List agent sessions", READ),
        "agent.retire": _entry("agent_retire", "Retire agent session", TRANSITION),
        "agent.checkout_release_backfill": _entry(
            "agent_checkout_release_backfill", "Release checkouts of retired sessions", OVERWRITE,
        ),
        "agent.type.list": _entry("agent_type_list", "List agent types", READ),
        # Docstring: "Idempotently register an agent type".
        "agent.type.register": _entry(
            "agent_type_register", "Register agent type", ADDITIVE_ONCE, output=_minted("agent_type_id"),
        ),
    }

    execute_actions: Dict[str, Dict[str, Any]] = {
        "tracker.create": _entry(
            "tracker_create", "Create tracker record", CREATE, gov=True,
            output=_minted("record_id"),
        ),
        "tracker.set": _entry("tracker_set", "Set tracker record field", SET, gov=True),
        # ENC-TSK-L07 (B63 AC-7 / B65 AC-5/AC-7): simple symmetric cross-reference
        # convenience, distinct from the typed tracker.create_relationship edge graph.
        "tracker.relate": _entry("tracker_relate", "Relate two tracker records", ADDITIVE_ONCE, gov=True),
        "tracker.log": _entry("tracker_log", "Append worklog entry", APPEND, gov=True),
        "tracker.set_acceptance_evidence": _entry(
            "tracker_set_acceptance_evidence", "Set acceptance-criterion evidence", SET, gov=True,
        ),
        # Evaluates policy and returns allow/deny. The audit event it writes is the same
        # infrastructure telemetry every tool call emits, not a change to governed data.
        "documents.check_policy": _entry("check_document_policy", "Check document storage policy", READ),
        "documents.put": _entry(
            "documents_put", "Create document", CREATE, gov=True, output=_minted("document_id"),
        ),
        "documents.patch": _entry("documents_patch", "Update document", OVERWRITE, gov=True),
        # ENC-TSK-P73 / FR-B3-1: governed section-level patch (ENC-TSK-P71 backend handler).
        "documents.patch_section": _entry(
            "documents_patch_section", "Patch document section", SET, gov=True,
        ),
        "deploy.submit": _entry(
            "deploy_submit", "Submit deploy request", CREATE, gov=True, output=_minted("request_id"),
        ),
        "deploy.state_set": _entry("deploy_state_set", "Set deploy state", SET, gov=True),
        "deploy.trigger": _entry("deploy_trigger", "Trigger deploy pipeline", OVERWRITE),
        "checkout.task": _entry("checkout_task", "Check out task", TRANSITION, gov=True),
        "checkout.release": _entry("release_task", "Release task checkout", TRANSITION, gov=True),
        "checkout.advance": _entry(
            "advance_task_status", "Advance task status", TRANSITION, gov=True,
            output=_minted(
                "commit_approval_id", "commit_complete_id",
                description="CAI/CCI token minted by the checkout service on the matching transition; never supply on input.",
            ),
        ),
        "checkout.append_worklog": _entry("append_worklog", "Append task worklog", APPEND, gov=True),
        "github.create_issue": _entry("github_create_issue", "Create GitHub issue", CREATE),
        "github.projects_sync": _entry("github_projects_sync", "Sync issue to GitHub project", ADDITIVE_ONCE),
    }

    # ENC-FTR-049: Conditionally register typed relationship actions behind feature flag
    if flags.enable_typed_relationships:
        flag = "enable_typed_relationships"
        execute_actions["tracker.create_relationship"] = _entry(
            "tracker_create_relationship", "Create typed relationship", CREATE, gov=True, flag=flag,
        )
        execute_actions["tracker.archive_relationship"] = _entry(
            "tracker_archive_relationship", "Archive typed relationship", SET, gov=True, flag=flag,
        )
        search_actions["tracker.list_relationships"] = _entry(
            "tracker_list_relationships", "List typed relationships", READ, flag=flag,
        )

    # ENC-FTR-121 / ENC-TSK-J68: Escalations — governed request/read surface.
    # escalation.request proposes a lifecycle-forbidden mutation for io approval;
    # approve/deny deliberately have NO MCP action (Cognito human path only, §6).
    if flags.enable_escalation_primitive:
        flag = "enable_escalation_primitive"
        execute_actions["escalation.request"] = _entry(
            "escalation_request", "Request escalation", CREATE, gov=True, flag=flag,
            output=_minted("escalation_id"),
        )
        search_actions["escalation.get"] = _entry("escalation_get", "Get escalation", READ, flag=flag)
        search_actions["escalation.list"] = _entry("escalation_list", "List escalations", READ, flag=flag)
        # ENC-TSK-J71 (Ph4): session-scoped cursor polling — the listening agent's
        # side of the loop (§5.4 coordination surface, §5.9 activity rule). It refreshes
        # the session heartbeat, so it is not read-only, but repeating it is harmless.
        coordination_actions["escalation.watch"] = _entry(
            "escalation_watch", "Poll escalation events", ADDITIVE_ONCE, flag=flag,
        )

    # ENC-FTR-052: Conditionally register lesson actions behind feature flag
    if flags.enable_lesson_primitive:
        flag = "enable_lesson_primitive"
        execute_actions["tracker.create_lesson"] = _entry(
            "tracker_create_lesson", "Create lesson", CREATE, gov=True, flag=flag,
            output=_minted("record_id"),
        )
        execute_actions["tracker.extend_lesson"] = _entry(
            "tracker_extend_lesson", "Extend lesson", APPEND, gov=True, flag=flag,
        )
        search_actions["tracker.list_lessons"] = _entry(
            "tracker_list_lessons", "List lessons", READ, flag=flag,
        )

    # ENC-FTR-061: Conditionally register handoff actions behind feature flag
    if flags.enable_handoff_primitive:
        flag = "enable_handoff_primitive"
        doc_id = _minted("document_id")
        execute_actions["document.create_handoff"] = _entry(
            "document_create_handoff", "Create handoff document", CREATE, gov=True, flag=flag, output=doc_id,
        )
        execute_actions["document.claim_handoff"] = _entry(
            "document_claim_handoff", "Claim handoff document", TRANSITION, gov=True, flag=flag,
        )
        execute_actions["document.complete_handoff"] = _entry(
            "document_complete_handoff", "Complete handoff document", TRANSITION, gov=True, flag=flag,
        )
        # ENC-FTR-077 / ENC-TSK-E53: COE + Wave docstore subtype actions
        execute_actions["document.create_coe"] = _entry(
            "document_create_coe", "Create COE document", CREATE, gov=True, flag=flag, output=doc_id,
        )
        execute_actions["document.create_wave"] = _entry(
            "document_create_wave", "Create wave document", CREATE, gov=True, flag=flag, output=doc_id,
        )
        execute_actions["document.append_handoff_reply"] = _entry(
            "document_append_handoff_reply", "Append handoff reply", APPEND, gov=True, flag=flag,
        )
        execute_actions["document.append_wave_entry"] = _entry(
            "document_append_wave_entry", "Append wave entry", APPEND, gov=True, flag=flag,
        )

    # ENC-ISS-259: document.create_note — governed ad-hoc note path for coord-lead /
    # supervisor sessions. Wraps documents.put with document_subtype pinned to 'doc'.
    # Not gated behind flags.enable_handoff_primitive because the 'doc' subtype is the
    # stable, always-available baseline and pre-dates the handoff primitive rollout.
    execute_actions["document.create_note"] = _entry(
        "document_create_note", "Create note document", CREATE, gov=True, output=_minted("document_id"),
    )

    # ENC-FTR-076 / ENC-TSK-E08: Conditionally register component.propose behind feature flag
    if flags.enable_component_proposal:
        flag = "enable_component_proposal"
        execute_actions["component.propose"] = _entry(
            "component_propose", "Propose component", CREATE, gov=True, flag=flag,
        )
        # ENC-FTR-076 v2 / ENC-TSK-F40 (DOC-546B896390EA §9): state machine + edge
        # + lifecycle actions. All 6 require governance hash (governed mutations).
        # Authority enforcement (io-only vs agent-permitted) is server-side in
        # coordination_api handlers — the MCP surface forwards the request along
        # with the caller's Cognito claims so the Lambda can gate per action.
        execute_actions["component.advance"] = _entry(
            "component_advance", "Advance component lifecycle", TRANSITION, gov=True, flag=flag,
        )
        execute_actions["component.revert"] = _entry(
            "component_revert", "Revert component", OVERWRITE, gov=True, flag=flag,
        )
        execute_actions["component.deprecate"] = _entry(
            "component_deprecate", "Deprecate component", SET, gov=True, flag=flag,
        )
        execute_actions["component.restore"] = _entry(
            "component_restore", "Restore component", TRANSITION, gov=True, flag=flag,
        )
        execute_actions["component.add_edge"] = _entry(
            "component_add_edge", "Add component edge", ADDITIVE_ONCE, gov=True, flag=flag,
        )
        execute_actions["component.remove_edge"] = _entry(
            "component_remove_edge", "Remove component edge", SET, gov=True, flag=flag,
        )

    # ENC-FTR-058 / ENC-TSK-A97 / ENC-TSK-C09: Plan action aliases in code-mode surface
    search_actions["plan.objectives_status"] = _entry("plan_objectives_status", "Get plan objectives status", READ)
    execute_actions["plan.create"] = _entry(
        "tracker_create", "Create plan", CREATE, gov=True, output=_minted("record_id"),
    )
    execute_actions["plan.checkout"] = _entry("plan_checkout", "Check out plan", TRANSITION, gov=True)
    execute_actions["plan.advance"] = _entry("plan_advance", "Advance plan status", TRANSITION, gov=True)
    # Docstring: "Idempotent: skip if already present".
    execute_actions["plan.add_objective"] = _entry(
        "plan_add_objective", "Add plan objective", ADDITIVE_ONCE, gov=True,
    )
    execute_actions["plan.remove_objective"] = _entry(
        "plan_remove_objective", "Remove plan objective", SET, gov=True,
    )
    execute_actions["plan.reorder_objectives"] = _entry(
        "plan_reorder_objectives", "Reorder plan objectives", SET, gov=True,
    )
    execute_actions["plan.replace_objectives"] = _entry(
        "plan_replace_objectives", "Replace plan objectives", SET, gov=True,
    )
    return search_actions, coordination_actions, execute_actions
