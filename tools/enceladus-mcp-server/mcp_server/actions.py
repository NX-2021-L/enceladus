"""Code-mode action registries for search/coordination/execute meta-tools."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple


@dataclass(frozen=True)
class ActionFeatureFlags:
    enable_typed_relationships: bool = False
    enable_escalation_primitive: bool = True
    enable_lesson_primitive: bool = False
    enable_handoff_primitive: bool = False
    enable_component_proposal: bool = False


def build_action_registries(flags: ActionFeatureFlags) -> Tuple[
    Dict[str, Dict[str, Any]],
    Dict[str, Dict[str, Any]],
    Dict[str, Dict[str, Any]],
]:
    """Return (search_actions, coordination_actions, execute_actions)."""
    search_actions: Dict[str, Dict[str, Any]] = {
        "projects.list": {"tool": "projects_list"},
        "projects.get": {"tool": "projects_get"},
        "tracker.get": {"tool": "tracker_get"},
        "tracker.list": {"tool": "tracker_list"},
        "tracker.pending_updates": {"tool": "tracker_pending_updates"},
        "tracker.validation_rules": {"tool": "tracker_validation_rules"},
        "documents.search": {"tool": "documents_search"},
        "documents.get": {"tool": "documents_get"},
        "documents.list": {"tool": "documents_list"},
        "reference.search": {"tool": "reference_search"},
        "deploy.state_get": {"tool": "deploy_state_get"},
        "deploy.history": {"tool": "deploy_history"},
        "deploy.history_list": {"tool": "deploy_history_list"},
        "deploy.status": {"tool": "deploy_status"},
        "deploy.status_get": {"tool": "deploy_status_get"},
        "deploy.pending_requests": {"tool": "deploy_pending_requests"},
        "changelog.history": {"tool": "changelog_history"},
        "changelog.history_all": {"tool": "changelog_history_all"},
        "changelog.version": {"tool": "changelog_version"},
        "governance.hash": {"tool": "governance_hash"},
        "governance.get": {"tool": "governance_get"},
        "governance.dictionary": {"tool": "governance_dictionary"},
        "system.connection_health": {"tool": "connection_health"},
        "github.projects_list": {"tool": "github_projects_list"},
        "tracker.graphsearch": {"tool": "tracker_graphsearch"},
        # ENC-FTR-089 / ENC-TSK-I89: admin-scoped raw-embedding egress.
        "tracker.embeddings_for": {"tool": "tracker_embeddings_for"},
        # ENC-FTR-095 / ENC-TSK-I90: Sheaf Laplacian H1 inconsistency detection
        "tracker.sheaf_cohomology": {"tool": "tracker_sheaf_cohomology"},
        # ENC-FTR-088 / ENC-TSK-I81: graph Laplacian read action (CSR adjacency +
        # Fiedler eigenvector via scipy.sparse.linalg.eigsh in graph_query_api).
        "tracker.graph_laplacian": {"tool": "tracker_graph_laplacian"},
        # ENC-FTR-097 / ENC-TSK-G27: Manifest Primitive v1 read actions
        "tracker.manifest": {"tool": "tracker_manifest"},
        "tracker.get_acs": {"tool": "tracker_get_acs"},
        "tracker.worklog_timeline": {"tool": "tracker_worklog_timeline"},
        "tracker.worklogs": {"tool": "tracker_worklogs"},
        "tracker.manifest_bulk": {"tool": "tracker_manifest_bulk"},
        # ENC-FTR-086 / ENC-TSK-I83: Convergence Surface frequency-rank read action
        "telemetry.rank": {"tool": "telemetry_rank"},
    }

    coordination_actions: Dict[str, Dict[str, Any]] = {
        "capabilities.get": {"tool": "coordination_capabilities"},
        "request.get": {"tool": "coordination_request_get"},
        "auth.cognito_session": {"tool": "coordination_cognito_session"},
        "dispatch_plan.generate": {"tool": "dispatch_plan_generate"},
        "dispatch_plan.dry_run": {"tool": "dispatch_plan_dry_run"},
        # ENC-FTR-084 Phase 1 / ENC-TSK-I93: session-init intent classifier.
        "session.classify_intent": {"tool": "coordination_classify_intent"},
        "session.intent_centroid_drift": {"tool": "coordination_intent_centroid_drift"},
        # ENC-TSK-I38: Agent identity surface (ENC-FTR-117); ported to v4/main by ENC-TSK-J43.
        "agent.register": {"tool": "agent_register"},
        "agent.claim": {"tool": "agent_claim"},
        "agent.list": {"tool": "agent_list"},
        "agent.retire": {"tool": "agent_retire"},
        "agent.type.list": {"tool": "agent_type_list"},
        "agent.type.register": {"tool": "agent_type_register"},
    }

    execute_actions: Dict[str, Dict[str, Any]] = {
        "tracker.create": {"tool": "tracker_create", "requires_governance_hash": True},
        "tracker.set": {"tool": "tracker_set", "requires_governance_hash": True},
        # ENC-TSK-L07 (B63 AC-7 / B65 AC-5/AC-7): simple symmetric cross-reference
        # convenience, distinct from the typed tracker.create_relationship edge graph.
        "tracker.relate": {"tool": "tracker_relate", "requires_governance_hash": True},
        "tracker.log": {"tool": "tracker_log", "requires_governance_hash": True},
        "tracker.set_acceptance_evidence": {
            "tool": "tracker_set_acceptance_evidence",
            "requires_governance_hash": True,
        },
        "documents.check_policy": {"tool": "check_document_policy"},
        "documents.put": {"tool": "documents_put", "requires_governance_hash": True},
        "documents.patch": {"tool": "documents_patch", "requires_governance_hash": True},
        "deploy.submit": {"tool": "deploy_submit", "requires_governance_hash": True},
        "deploy.state_set": {"tool": "deploy_state_set", "requires_governance_hash": True},
        "deploy.trigger": {"tool": "deploy_trigger"},
        "checkout.task": {"tool": "checkout_task", "requires_governance_hash": True},
        "checkout.release": {"tool": "release_task", "requires_governance_hash": True},
        "checkout.advance": {"tool": "advance_task_status", "requires_governance_hash": True},
        "checkout.append_worklog": {"tool": "append_worklog", "requires_governance_hash": True},
        "github.create_issue": {"tool": "github_create_issue"},
        "github.projects_sync": {"tool": "github_projects_sync"},
    }

    # ENC-FTR-049: Conditionally register typed relationship actions behind feature flag
    if flags.enable_typed_relationships:
        execute_actions["tracker.create_relationship"] = {
            "tool": "tracker_create_relationship", "requires_governance_hash": True,
        }
        execute_actions["tracker.archive_relationship"] = {
            "tool": "tracker_archive_relationship", "requires_governance_hash": True,
        }
        search_actions["tracker.list_relationships"] = {
            "tool": "tracker_list_relationships",
        }

    # ENC-FTR-121 / ENC-TSK-J68: Escalations — governed request/read surface.
    # escalation.request proposes a lifecycle-forbidden mutation for io approval;
    # approve/deny deliberately have NO MCP action (Cognito human path only, §6).
    if flags.enable_escalation_primitive:
        execute_actions["escalation.request"] = {
            "tool": "escalation_request", "requires_governance_hash": True,
        }
        search_actions["escalation.get"] = {
            "tool": "escalation_get",
        }
        search_actions["escalation.list"] = {
            "tool": "escalation_list",
        }
        # ENC-TSK-J71 (Ph4): session-scoped cursor polling — the listening agent's
        # side of the loop (§5.4 coordination surface, §5.9 activity rule).
        coordination_actions["escalation.watch"] = {
            "tool": "escalation_watch",
        }

    # ENC-FTR-052: Conditionally register lesson actions behind feature flag
    if flags.enable_lesson_primitive:
        execute_actions["tracker.create_lesson"] = {
            "tool": "tracker_create_lesson", "requires_governance_hash": True,
        }
        execute_actions["tracker.extend_lesson"] = {
            "tool": "tracker_extend_lesson", "requires_governance_hash": True,
        }
        search_actions["tracker.list_lessons"] = {
            "tool": "tracker_list_lessons",
        }

    # ENC-FTR-061: Conditionally register handoff actions behind feature flag
    if flags.enable_handoff_primitive:
        execute_actions["document.create_handoff"] = {
            "tool": "document_create_handoff", "requires_governance_hash": True,
        }
        execute_actions["document.claim_handoff"] = {
            "tool": "document_claim_handoff", "requires_governance_hash": True,
        }
        execute_actions["document.complete_handoff"] = {
            "tool": "document_complete_handoff", "requires_governance_hash": True,
        }
        # ENC-FTR-077 / ENC-TSK-E53: COE + Wave docstore subtype actions
        execute_actions["document.create_coe"] = {
            "tool": "document_create_coe", "requires_governance_hash": True,
        }
        execute_actions["document.create_wave"] = {
            "tool": "document_create_wave", "requires_governance_hash": True,
        }
        execute_actions["document.append_handoff_reply"] = {
            "tool": "document_append_handoff_reply", "requires_governance_hash": True,
        }
        execute_actions["document.append_wave_entry"] = {
            "tool": "document_append_wave_entry", "requires_governance_hash": True,
        }

    # ENC-ISS-259: document.create_note \u2014 governed ad-hoc note path for coord-lead /
    # supervisor sessions. Wraps documents.put with document_subtype pinned to 'doc'.
    # Not gated behind flags.enable_handoff_primitive because the 'doc' subtype is the
    # stable, always-available baseline and pre-dates the handoff primitive rollout.
    execute_actions["document.create_note"] = {
        "tool": "document_create_note", "requires_governance_hash": True,
    }

    # ENC-FTR-076 / ENC-TSK-E08: Conditionally register component.propose behind feature flag
    if flags.enable_component_proposal:
        execute_actions["component.propose"] = {
            "tool": "component_propose", "requires_governance_hash": True,
        }
        # ENC-FTR-076 v2 / ENC-TSK-F40 (DOC-546B896390EA §9): state machine + edge
        # + lifecycle actions. All 6 require governance hash (governed mutations).
        # Authority enforcement (io-only vs agent-permitted) is server-side in
        # coordination_api handlers — the MCP surface forwards the request along
        # with the caller's Cognito claims so the Lambda can gate per action.
        execute_actions["component.advance"] = {
            "tool": "component_advance", "requires_governance_hash": True,
        }
        execute_actions["component.revert"] = {
            "tool": "component_revert", "requires_governance_hash": True,
        }
        execute_actions["component.deprecate"] = {
            "tool": "component_deprecate", "requires_governance_hash": True,
        }
        execute_actions["component.restore"] = {
            "tool": "component_restore", "requires_governance_hash": True,
        }
        execute_actions["component.add_edge"] = {
            "tool": "component_add_edge", "requires_governance_hash": True,
        }
        execute_actions["component.remove_edge"] = {
            "tool": "component_remove_edge", "requires_governance_hash": True,
        }

    # ENC-FTR-058 / ENC-TSK-A97 / ENC-TSK-C09: Plan action aliases in code-mode surface
    search_actions["plan.objectives_status"] = {"tool": "plan_objectives_status"}
    execute_actions["plan.create"] = {"tool": "tracker_create", "requires_governance_hash": True}
    execute_actions["plan.checkout"] = {"tool": "plan_checkout", "requires_governance_hash": True}
    execute_actions["plan.advance"] = {"tool": "plan_advance", "requires_governance_hash": True}
    execute_actions["plan.add_objective"] = {"tool": "plan_add_objective", "requires_governance_hash": True}
    execute_actions["plan.remove_objective"] = {"tool": "plan_remove_objective", "requires_governance_hash": True}
    execute_actions["plan.reorder_objectives"] = {"tool": "plan_reorder_objectives", "requires_governance_hash": True}
    execute_actions["plan.replace_objectives"] = {"tool": "plan_replace_objectives", "requires_governance_hash": True}
    return search_actions, coordination_actions, execute_actions
