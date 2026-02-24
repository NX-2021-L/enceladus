#!/usr/bin/env python3
"""Tests for dispatch_plan_generator.py and MCP server dispatch-plan tools.

Validates:
  - Governance hash computation
  - Connection health testing
  - Provider selection heuristics
  - Outcome classification
  - Decomposition logic
  - Quality gate validation
  - Feed subscription auto-linking
  - Concurrency and conflict detection
  - MCP tool handler integration

Related: DVP-TSK-252, DVP-FTR-023
"""

import asyncio
import json
import os
import sys
import uuid

# Ensure dispatch_plan_generator is importable from this directory
sys.path.insert(0, os.path.dirname(__file__))

import dispatch_plan_generator as dpg
from dispatch_plan_generator import (
    PROVIDER_CAPACITY,
    VALID_PROVIDERS,
    QualityGateError,
    build_dispatch_plan,
    check_concurrency,
    classify_outcome,
    compute_feed_subscription,
    compute_governance_hash,
    decompose_outcomes,
    detect_conflicts,
    estimate_duration,
    select_provider,
    select_provider_for_task_type,
    should_decompose,
    validate_dispatch_plan,
)


def _header(label: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")


def _pass(test_name: str) -> None:
    print(f"  ✅ {test_name}")


def _fail(test_name: str, detail: str) -> None:
    print(f"  ❌ {test_name}: {detail}")
    global _failures
    _failures += 1


_failures = 0


# =================================================================
# Test: Governance Hash
# =================================================================

def test_governance_hash():
    _header("Governance Hash")
    h = compute_governance_hash()
    assert isinstance(h, str), "hash should be string"
    assert len(h) == 64, f"SHA-256 should be 64 chars, got {len(h)}"
    _pass(f"governance_hash computed: {h[:16]}...")

    # Stability: same hash on second call
    h2 = compute_governance_hash()
    assert h == h2, "governance hash should be stable"
    _pass("governance_hash is stable across calls")


# =================================================================
# Test: Connection Health
# =================================================================

def test_conn_health():
    _header("Connection Health")
    health = dpg.test_connection_health()
    assert "dynamodb" in health, "should have dynamodb key"
    assert "s3" in health, "should have s3 key"
    assert "api_gateway" in health, "should have api_gateway key"
    _pass(f"connection_health returned: ddb={health['dynamodb']}, s3={health['s3']}, api={health['api_gateway']}")


# =================================================================
# Test: Outcome Classification
# =================================================================

def test_classify_outcome():
    _header("Outcome Classification")

    cases = [
        ("Implement new REST API endpoint for user authentication", "code"),
        ("Design architecture contract for multi-tenant support", "architecture"),
        ("Deploy Lambda function to production", "infrastructure"),
        ("Write unit tests for the payment module", "test"),
        ("Bulk update tracker records for sprint closure", "tracker_crud"),
        ("Refactor the database access layer", "code"),
        ("Investigate root cause of memory leak", "architecture"),
        ("Provision new S3 bucket for analytics pipeline", "infrastructure"),
        ("Create integration test suite for the API", "test"),
    ]

    for text, expected in cases:
        result = classify_outcome(text)
        if result == expected:
            _pass(f"'{text[:50]}...' -> '{result}'")
        else:
            _fail(f"'{text[:50]}...'", f"expected '{expected}', got '{result}'")


# =================================================================
# Test: Provider Selection
# =================================================================

def test_provider_selection():
    _header("Provider Selection")

    # Test 1: Explicit preferred provider
    prov, rationale = select_provider(["implement something"], "devops", preferred_provider="openai_codex")
    assert prov == "openai_codex", f"expected openai_codex, got {prov}"
    _pass(f"preferred_provider override: {prov}")

    # Test 2: Code outcomes -> openai_codex
    prov, rationale = select_provider(["implement new feature", "write the code"], "harrisonfamily")
    assert prov == "openai_codex", f"expected openai_codex, got {prov}"
    _pass(f"code outcomes -> {prov}: {rationale[:60]}...")

    # Test 3: Architecture outcomes -> claude_agent_sdk
    prov, rationale = select_provider(["design the architecture", "review the contract"], "devops")
    assert prov == "claude_agent_sdk", f"expected claude_agent_sdk, got {prov}"
    _pass(f"architecture outcomes -> {prov}")

    # Test 4: Infrastructure -> aws_native
    prov, rationale = select_provider(["deploy Lambda to production", "provision S3 bucket"], "devops")
    assert prov == "aws_native", f"expected aws_native, got {prov}"
    _pass(f"infrastructure outcomes -> {prov}")

    # Test 5: Mixed outcomes -> project affinity
    prov, rationale = select_provider(
        ["implement feature", "design architecture", "deploy lambda"],
        "devops",
    )
    assert prov == "claude_agent_sdk", f"expected claude_agent_sdk (devops affinity), got {prov}"
    _pass(f"mixed outcomes, devops project -> {prov}")

    # Test 6: Mixed outcomes for harrisonfamily -> openai_codex
    prov, rationale = select_provider(
        ["implement feature", "design architecture"],
        "harrisonfamily",
    )
    assert prov == "openai_codex", f"expected openai_codex (harrisonfamily affinity), got {prov}"
    _pass(f"mixed outcomes, harrisonfamily project -> {prov}")


# =================================================================
# Test: Decomposition
# =================================================================

def test_decomposition():
    _header("Decomposition")

    # Test 1: Few same-type outcomes -> no decomposition
    needs, strategy = should_decompose(
        ["implement feature A", "implement feature B"],
        "openai_codex",
    )
    assert not needs, "should not decompose 2 same-type outcomes"
    assert strategy == "single"
    _pass("2 same-type outcomes -> single (no decomposition)")

    # Test 2: Exceeding capacity -> decompose
    outcomes = [f"implement feature {i}" for i in range(8)]
    needs, strategy = should_decompose(outcomes, "openai_codex")
    assert needs, "should decompose 8 outcomes for openai_codex (max 5)"
    _pass("8 outcomes for openai_codex -> decompose (exceeds capacity)")

    # Test 3: Mixed types -> decompose
    outcomes = ["implement feature", "design architecture", "deploy lambda"]
    needs, strategy = should_decompose(outcomes, "claude_agent_sdk")
    assert needs, "should decompose mixed types"
    assert strategy == "parallel"
    _pass("mixed types -> parallel decomposition")

    # Test 4: Explicit constraint decomposition=single -> no decompose
    needs, strategy = should_decompose(
        ["implement A", "design B"],
        "claude_agent_sdk",
        constraints={"decomposition": "single"},
    )
    assert not needs, "should not decompose when constraint says single"
    _pass("decomposition='single' constraint honored")

    # Test 5: decompose_outcomes produces correct groups
    outcomes = [
        "implement authentication endpoint",
        "design API contract",
        "deploy Lambda update",
        "write unit tests",
    ]
    groups = decompose_outcomes(outcomes, "devops", None, {"dynamodb": "ok", "s3": "ok", "api_gateway": "ok"})
    providers_used = {g["provider"] for g in groups}
    assert len(providers_used) > 1, f"expected multiple providers, got {providers_used}"
    total_outcomes = sum(len(g["outcomes"]) for g in groups)
    assert total_outcomes == len(outcomes), f"expected {len(outcomes)} total outcomes, got {total_outcomes}"
    _pass(f"decompose_outcomes: {len(groups)} groups, providers={providers_used}")


# =================================================================
# Test: Conflict Detection
# =================================================================

def test_conflict_detection():
    _header("Conflict Detection")

    # Test 1: No active dispatches -> no conflicts
    conflicts = detect_conflicts("devops", ["DVP-TSK-100"], [])
    assert len(conflicts) == 0
    _pass("no active dispatches -> no conflicts")

    # Test 2: Overlapping record IDs
    active = [
        {"request_id": "req-001", "related_record_ids": ["DVP-TSK-100", "DVP-FTR-023"]},
    ]
    conflicts = detect_conflicts("devops", ["DVP-TSK-100", "DVP-TSK-200"], active)
    assert len(conflicts) == 1
    assert "DVP-TSK-100" in conflicts[0]["overlapping_records"]
    _pass(f"overlapping records detected: {conflicts[0]['overlapping_records']}")

    # Test 3: No overlap
    conflicts = detect_conflicts("devops", ["DVP-TSK-999"], active)
    assert len(conflicts) == 0
    _pass("no overlap -> no conflicts")


# =================================================================
# Test: Concurrency Limits
# =================================================================

def test_concurrency():
    _header("Concurrency Limits")

    # Test 1: Within limits
    within, msg = check_concurrency("devops", "claude_agent_sdk", [], 1)
    assert within, f"should be within limits: {msg}"
    _pass(f"within limits: {msg}")

    # Test 2: Exceeding per-project limit
    active = [
        {"project_id": "devops", "request_id": "r1"},
        {"project_id": "devops", "request_id": "r2"},
    ]
    within, msg = check_concurrency("devops", "claude_agent_sdk", active, 1)
    assert not within, "should exceed per-project limit"
    _pass(f"exceeds per-project: {msg}")

    # Test 3: Exceeding global limit
    active = [{"project_id": f"proj{i}", "request_id": f"r{i}"} for i in range(6)]
    within, msg = check_concurrency("newproj", "claude_agent_sdk", active, 1)
    assert not within, "should exceed global limit"
    _pass(f"exceeds global: {msg}")


# =================================================================
# Test: Feed Subscription
# =================================================================

def test_feed_subscription():
    _header("Feed Subscription Auto-Linking")

    # Test 1: With session ID
    sub = compute_feed_subscription(["DVP-TSK-100"], "session-123", 30)
    assert sub is not None
    assert sub["auto_subscribe"] is True
    assert sub["duration_minutes"] == 60  # 30 * 2
    _pass(f"auto-subscribe: duration={sub['duration_minutes']}min")

    # Test 2: Floor at 30 min
    sub = compute_feed_subscription(["DVP-TSK-100"], "session-123", 10)
    assert sub["duration_minutes"] == 30  # floor
    _pass(f"duration floor: {sub['duration_minutes']}min")

    # Test 3: Ceiling at 1440 min
    sub = compute_feed_subscription(["DVP-TSK-100"], "session-123", 1000)
    assert sub["duration_minutes"] == 1440  # ceiling
    _pass(f"duration ceiling: {sub['duration_minutes']}min")

    # Test 4: No session ID -> no subscription
    sub = compute_feed_subscription(["DVP-TSK-100"], None, 30)
    assert sub is None
    _pass("no session ID -> no subscription")

    # Test 5: No records -> no subscription
    sub = compute_feed_subscription([], "session-123", 30)
    assert sub is None
    _pass("no records -> no subscription")


# =================================================================
# Test: Plan Assembly
# =================================================================

def test_plan_assembly():
    _header("Plan Assembly")

    groups = [
        {
            "provider": "claude_agent_sdk",
            "execution_mode": "claude_agent_sdk",
            "outcomes": ["outcome A", "outcome B"],
            "sequence_order": 0,
        },
    ]

    plan = build_dispatch_plan(
        request_id="test-req-001",
        project_id="devops",
        outcomes=["outcome A", "outcome B"],
        governance_hash="abc123" * 10 + "abcd",
        connection_health={"dynamodb": "ok", "s3": "ok", "api_gateway": "ok"},
        dispatch_groups=groups,
        rationale="Test rationale",
        decomposition="single",
        estimated_duration_minutes=30,
        related_record_ids=["DVP-TSK-100"],
        requestor_session_id="session-123",
    )

    assert plan["plan_version"] == "0.3.0"
    assert plan["project_id"] == "devops"
    assert len(plan["dispatches"]) == 1
    assert plan["dispatches"][0]["provider"] == "claude_agent_sdk"
    assert plan["dispatches"][0]["callback_config"]["endpoint"].endswith("/callback")
    assert plan["rollback_policy"]["on_partial_failure"] == "continue"
    assert plan["dispatches"][0].get("feed_subscription") is not None

    _pass(f"plan assembled: {plan['plan_id'][:8]}..., {len(plan['dispatches'])} dispatch(es)")


# =================================================================
# Test: Quality Gate Validation
# =================================================================

def test_quality_gates():
    _header("Quality Gate Validation")

    # Build a valid plan first
    groups = [
        {
            "provider": "claude_agent_sdk",
            "execution_mode": "claude_agent_sdk",
            "outcomes": ["outcome A"],
            "sequence_order": 0,
        },
    ]
    valid_plan = build_dispatch_plan(
        request_id="test-gates",
        project_id="devops",
        outcomes=["outcome A"],
        governance_hash="a" * 64,
        connection_health={"dynamodb": "ok", "s3": "ok", "api_gateway": "ok"},
        dispatch_groups=groups,
        rationale="test",
        decomposition="single",
        estimated_duration_minutes=15,
        related_record_ids=[],
        requestor_session_id=None,
    )

    # Test 1: Valid plan passes
    warnings = validate_dispatch_plan(valid_plan, ["outcome A"])
    _pass(f"valid plan passes gates, warnings={len(warnings)}")

    # Test 2: Missing governance hash
    bad_plan = {**valid_plan, "governance_hash": ""}
    try:
        validate_dispatch_plan(bad_plan, ["outcome A"])
        _fail("missing governance_hash", "should have raised QualityGateError")
    except QualityGateError as e:
        assert e.gate == "governance_hash"
        _pass(f"missing governance_hash -> {e.gate}")

    # Test 3: DynamoDB unreachable
    bad_plan = {**valid_plan, "connection_health": {"dynamodb": "unreachable", "s3": "ok"}}
    try:
        validate_dispatch_plan(bad_plan, ["outcome A"])
        _fail("ddb unreachable", "should have raised QualityGateError")
    except QualityGateError as e:
        assert e.gate == "connection_health"
        _pass(f"ddb unreachable -> {e.gate}")

    # Test 4: Missing outcomes
    try:
        validate_dispatch_plan(valid_plan, ["outcome A", "outcome B (missing)"])
        _fail("missing outcomes", "should have raised QualityGateError")
    except QualityGateError as e:
        assert e.gate == "outcomes_mapped"
        _pass(f"missing outcomes -> {e.gate}")

    # Test 5: Invalid provider
    bad_dispatch = {**valid_plan}
    bad_dispatch["dispatches"] = [
        {**valid_plan["dispatches"][0], "provider": "invalid_provider"}
    ]
    try:
        validate_dispatch_plan(bad_dispatch, ["outcome A"])
        _fail("invalid provider", "should have raised QualityGateError")
    except QualityGateError as e:
        assert e.gate == "provider_validity"
        _pass(f"invalid provider -> {e.gate}")

    # Test 6: Missing callback
    bad_dispatch = {**valid_plan}
    bad_cb = {**valid_plan["dispatches"][0], "callback_config": {"endpoint": ""}}
    bad_dispatch["dispatches"] = [bad_cb]
    try:
        validate_dispatch_plan(bad_dispatch, ["outcome A"])
        _fail("missing callback", "should have raised QualityGateError")
    except QualityGateError as e:
        assert e.gate == "callback_configured"
        _pass(f"missing callback -> {e.gate}")


# =================================================================
# Test: Duration Estimation
# =================================================================

def test_duration_estimation():
    _header("Duration Estimation")

    # Test 1: Single group, 2 outcomes, openai_codex
    groups = [{"provider": "openai_codex", "outcomes": ["a", "b"], "sequence_order": 0}]
    est = estimate_duration(groups)
    assert est >= 5, f"minimum duration should be 5, got {est}"
    _pass(f"2 outcomes for openai_codex: {est} min")

    # Test 2: Parallel groups
    groups = [
        {"provider": "openai_codex", "outcomes": ["a", "b", "c"], "sequence_order": 0},
        {"provider": "claude_agent_sdk", "outcomes": ["d"], "sequence_order": 0},
    ]
    est = estimate_duration(groups)
    _pass(f"parallel groups: {est} min (max of group estimates)")

    # Test 3: Empty
    est = estimate_duration([])
    assert est == 15
    _pass(f"empty groups: {est} min (default)")


# =================================================================
# Test: MCP Tool Handlers
# =================================================================

def test_mcp_tool_handlers():
    _header("MCP Tool Handlers (server.py)")

    # Import server module
    sys.path.insert(0, os.path.dirname(__file__))
    import server

    # Verify tools are registered
    assert "dispatch_plan_generate" in server._TOOL_HANDLERS
    assert "dispatch_plan_dry_run" in server._TOOL_HANDLERS
    assert "deploy_status_get" in server._TOOL_HANDLERS
    assert "deploy_history_list" in server._TOOL_HANDLERS
    _pass("dispatch_plan_generate registered in _TOOL_HANDLERS")
    _pass("dispatch_plan_dry_run registered in _TOOL_HANDLERS")
    _pass("deploy_status_get registered in _TOOL_HANDLERS")
    _pass("deploy_history_list registered in _TOOL_HANDLERS")

    # Test dry-run through MCP handler
    loop = asyncio.new_event_loop()
    result = loop.run_until_complete(
        server._TOOL_HANDLERS["dispatch_plan_dry_run"]({
            "project_id": "devops",
            "outcomes": ["implement a feature", "write tests"],
        })
    )
    loop.close()

    assert len(result) == 1
    plan_json = json.loads(result[0].text)
    assert plan_json.get("_dry_run") is True
    assert plan_json.get("plan_version") == "0.3.0"
    assert len(plan_json.get("dispatches", [])) >= 1
    _pass(f"dry_run via MCP handler: plan_id={plan_json['plan_id'][:8]}...")


# =================================================================
# Test: Deployment MCP Adapter
# =================================================================

def test_deploy_adapter_contract():
    _header("Deployment MCP Adapter Contract")

    sys.path.insert(0, os.path.dirname(__file__))
    import server

    # Capture outbound API route mappings without making network calls.
    calls = []

    def fake_deploy_api_request(method, path, payload=None, query=None):
        calls.append(
            {"method": method, "path": path, "payload": payload, "query": query}
        )
        return {"success": True, "method": method, "path": path}

    # Monkeypatch helpers
    server._deploy_api_request = fake_deploy_api_request
    server._compute_governance_hash = lambda: "a" * 64

    loop = asyncio.new_event_loop()
    try:
        # 1) deploy_submit rejects invalid deployment_type with v0.3 envelope.
        invalid_submit = loop.run_until_complete(
            server._deploy_submit(
                {
                    "project_id": "devops",
                    "change_type": "patch",
                    "deployment_type": "invalid_type",
                    "summary": "bad type",
                    "changes": ["x"],
                }
            )
        )
        invalid_payload = json.loads(invalid_submit[0].text)
        assert invalid_payload["success"] is False
        assert invalid_payload["error"]["code"] == "INVALID_INPUT"
        _pass("deploy_submit invalid deployment_type -> INVALID_INPUT envelope")

        # 2) deploy_submit validates non-UI target_arn discipline.
        invalid_non_ui = loop.run_until_complete(
            server._deploy_submit(
                {
                    "project_id": "devops",
                    "change_type": "patch",
                    "deployment_type": "lambda_update",
                    "summary": "lambda deploy",
                    "changes": ["update handler"],
                    "non_ui_config": {"service_group": "lambda"},
                }
            )
        )
        invalid_non_ui_payload = json.loads(invalid_non_ui[0].text)
        assert invalid_non_ui_payload["success"] is False
        assert invalid_non_ui_payload["error"]["code"] == "INVALID_INPUT"
        _pass("deploy_submit non-UI missing target_arn -> INVALID_INPUT envelope")

        # 3) deploy_state_set requires governance hash.
        state_missing_hash = loop.run_until_complete(
            server._deploy_state_set({"project_id": "devops", "state": "PAUSED"})
        )
        state_missing_hash_payload = json.loads(state_missing_hash[0].text)
        assert state_missing_hash_payload["success"] is False
        assert state_missing_hash_payload["error"]["code"] == "PERMISSION_DENIED"
        _pass("deploy_state_set missing governance_hash -> PERMISSION_DENIED")

        # 4) Route mappings: state/status/history and typed submit.
        ok_submit = loop.run_until_complete(
            server._deploy_submit(
                {
                    "project_id": "devops",
                    "change_type": "patch",
                    "deployment_type": "github_public_static",
                    "summary": "ok submit",
                    "changes": ["build"],
                }
            )
        )
        assert json.loads(ok_submit[0].text)["success"] is True

        _ = loop.run_until_complete(
            server._deploy_state_get({"project_id": "devops"})
        )
        _ = loop.run_until_complete(
            server._deploy_status_get({"project_id": "devops", "spec_id": "SPEC-ABC123"})
        )
        _ = loop.run_until_complete(
            server._deploy_history_list({"project_id": "devops", "limit": 7})
        )
    finally:
        loop.close()

    assert any(c["method"] == "POST" and c["path"] == "/submit" for c in calls)
    assert any(c["method"] == "GET" and c["path"] == "/state/devops" for c in calls)
    assert any(c["method"] == "GET" and c["path"] == "/status/SPEC-ABC123" for c in calls)
    assert any(c["method"] == "GET" and c["path"] == "/history/devops" for c in calls)
    _pass("deploy adapter route mapping uses deploy_intake API paths")


# =================================================================
# Test: Bedrock Agent Provider (DVP-TSK-338)
# =================================================================

def test_classify_outcome_bedrock():
    _header("Bedrock Agent Outcome Classification")

    cases = [
        ("Use bedrock agent to orchestrate multi-step AWS operations", "bedrock_agent"),
        ("Perform RAG retrieval from the knowledge base", "bedrock_agent"),
        ("Bedrock agent service integration for the pipeline", "bedrock_agent"),
    ]

    for text, expected in cases:
        result = classify_outcome(text)
        if result == expected:
            _pass(f"'{text[:50]}...' -> '{result}'")
        else:
            _fail(f"'{text[:50]}...'", f"expected '{expected}', got '{result}'")


def test_provider_selection_bedrock():
    _header("Bedrock Agent Provider Selection")

    # Test 1: Bedrock outcomes -> aws_bedrock_agent
    prov, rationale = select_provider(
        ["Use bedrock agent for RAG retrieval", "Bedrock knowledge base query"],
        "devops",
    )
    assert prov == "aws_bedrock_agent", f"expected aws_bedrock_agent, got {prov}"
    _pass(f"bedrock outcomes -> {prov}: {rationale[:60]}...")

    # Test 2: Explicit preferred provider override
    prov, rationale = select_provider(
        ["implement a feature"],
        "devops",
        preferred_provider="aws_bedrock_agent",
    )
    assert prov == "aws_bedrock_agent", f"expected aws_bedrock_agent, got {prov}"
    _pass(f"preferred_provider=aws_bedrock_agent override: {prov}")

    # Test 3: Task type mapping
    prov = select_provider_for_task_type("bedrock_agent")
    assert prov == "aws_bedrock_agent", f"expected aws_bedrock_agent, got {prov}"
    _pass(f"task type 'bedrock_agent' -> {prov}")


def test_bedrock_capacity_constants():
    _header("Bedrock Agent Capacity Constants")

    assert "aws_bedrock_agent" in VALID_PROVIDERS
    _pass("aws_bedrock_agent in VALID_PROVIDERS")

    cap = PROVIDER_CAPACITY.get("aws_bedrock_agent")
    assert cap is not None, "aws_bedrock_agent should have capacity entry"
    assert cap["max_outcomes"] == 3, f"expected max_outcomes=3, got {cap['max_outcomes']}"
    assert cap["max_duration_min"] == 20, f"expected max_duration=20, got {cap['max_duration_min']}"
    _pass(f"capacity: max_outcomes={cap['max_outcomes']}, max_duration={cap['max_duration_min']}min")

    from dispatch_plan_generator import (
        CONCURRENCY_LIMITS,
        PROVIDER_EXECUTION_MODES,
        PROVIDER_FAILOVER,
    )

    assert PROVIDER_EXECUTION_MODES.get("aws_bedrock_agent") == "bedrock_agent"
    _pass("execution mode: bedrock_agent")

    assert CONCURRENCY_LIMITS.get("per_provider_aws_bedrock_agent") == 3
    _pass("concurrency limit: 3 per provider")


def test_bedrock_failover_chain():
    _header("Bedrock Agent Failover Chain")

    from dispatch_plan_generator import PROVIDER_FAILOVER

    assert PROVIDER_FAILOVER.get("aws_bedrock_agent") == "claude_agent_sdk"
    _pass("failover: aws_bedrock_agent -> claude_agent_sdk")


def test_plan_with_bedrock_provider():
    _header("Plan Assembly with Bedrock Provider")

    groups = [
        {
            "provider": "aws_bedrock_agent",
            "execution_mode": "bedrock_agent",
            "outcomes": ["Query knowledge base for architecture docs"],
            "sequence_order": 0,
            "foundation_model_id": "anthropic.claude-3-haiku-20240307-v1:0",
            "retain_agent": False,
            "idle_session_ttl_seconds": 300,
        },
    ]

    plan = build_dispatch_plan(
        request_id="test-bedrock-001",
        project_id="devops",
        outcomes=["Query knowledge base for architecture docs"],
        governance_hash="b" * 64,
        connection_health={"dynamodb": "ok", "s3": "ok", "api_gateway": "ok"},
        dispatch_groups=groups,
        rationale="Bedrock agent selected for KB query (task-type affinity)",
        decomposition="single",
        estimated_duration_minutes=20,
        related_record_ids=["DVP-FTR-023"],
        requestor_session_id="session-bedrock-test",
    )

    assert plan["plan_version"] == "0.3.0"
    assert len(plan["dispatches"]) == 1

    dispatch = plan["dispatches"][0]
    assert dispatch["provider"] == "aws_bedrock_agent"
    assert dispatch["execution_mode"] == "bedrock_agent"
    _pass(f"dispatch provider: {dispatch['provider']}")

    # Verify bedrock_config is present
    bedrock_config = dispatch["provider_config"].get("bedrock_config")
    assert bedrock_config is not None, "bedrock_config should be present in provider_config"
    assert bedrock_config["foundation_model_id"] == "anthropic.claude-3-haiku-20240307-v1:0"
    assert bedrock_config["retain_agent"] is False
    assert bedrock_config["idle_session_ttl_seconds"] == 300
    _pass(f"bedrock_config: model={bedrock_config['foundation_model_id']}, retain={bedrock_config['retain_agent']}")

    # Validate passes quality gates
    warnings = validate_dispatch_plan(plan, ["Query knowledge base for architecture docs"])
    _pass(f"quality gates passed, warnings={len(warnings)}")

    # Verify duration estimation for bedrock
    est = estimate_duration(groups)
    assert est >= 5, f"minimum duration should be 5, got {est}"
    _pass(f"bedrock duration estimate: {est} min")


# =================================================================
# Run all tests
# =================================================================

if __name__ == "__main__":
    print("\n🧪 Dispatch Plan Generator — Test Suite")
    print("=" * 60)

    test_governance_hash()
    test_conn_health()
    test_classify_outcome()
    test_provider_selection()
    test_decomposition()
    test_conflict_detection()
    test_concurrency()
    test_feed_subscription()
    test_plan_assembly()
    test_quality_gates()
    test_duration_estimation()
    test_classify_outcome_bedrock()
    test_provider_selection_bedrock()
    test_bedrock_capacity_constants()
    test_bedrock_failover_chain()
    test_plan_with_bedrock_provider()
    test_mcp_tool_handlers()
    test_deploy_adapter_contract()

    print(f"\n{'='*60}")
    if _failures:
        print(f"  ❌ {_failures} test(s) FAILED")
        sys.exit(1)
    else:
        print("  ✅ All tests passed!")
    print(f"{'='*60}\n")
