import importlib.util
import json
import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location("coordination_lambda", MODULE_PATH)
coordination_lambda = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = coordination_lambda
SPEC.loader.exec_module(coordination_lambda)


class CoordinationLambdaUnitTests(unittest.TestCase):
    def test_normalize_outcomes(self):
        outcomes = coordination_lambda._normalize_outcomes(["  First goal  ", "Second goal"])
        self.assertEqual(outcomes, ["First goal", "Second goal"])

    def test_derive_idempotency_key_is_stable(self):
        key_a = coordination_lambda._derive_idempotency_key(
            project_id="devops",
            initiative_title="Ship coordination",
            outcomes=["one", "two"],
            requestor_session_id="session-123",
        )
        key_b = coordination_lambda._derive_idempotency_key(
            project_id="devops",
            initiative_title="Ship coordination",
            outcomes=["one", "two"],
            requestor_session_id="session-123",
        )
        self.assertEqual(key_a, key_b)
        self.assertTrue(key_a.startswith("coord-"))

    def test_prepend_managed_session_bootstrap(self):
        text = coordination_lambda._prepend_managed_session_bootstrap(
            "Execute outcome checks",
            "devops",
        )
        self.assertTrue(text.startswith("agents.md project=devops"))
        self.assertIn("Execute outcome checks", text)

    @patch.object(
        coordination_lambda,
        "_build_mcp_governance_context",
        return_value={
            "loaded": True,
            "source": "mcp_resources",
            "included_uris": ["governance://agents.md"],
            "truncated": False,
            "text": "### governance://agents.md\n# Agent Rules",
        },
    )
    def test_build_managed_session_prompt_includes_governance_bundle(self, _mock_context):
        prompt, meta = coordination_lambda._build_managed_session_prompt(
            "Execute outcome checks",
            "devops",
        )
        self.assertTrue(prompt.startswith("agents.md project=devops"))
        self.assertIn("governance://agents.md", prompt)
        self.assertIn("Dispatch task:\nExecute outcome checks", prompt)
        self.assertTrue(meta["loaded"])
        self.assertEqual(meta["source"], "mcp_resources")

    @patch.object(
        coordination_lambda,
        "_build_mcp_governance_context",
        return_value={
            "loaded": False,
            "source": "mcp_resources",
            "included_uris": [],
            "truncated": False,
            "text": "",
        },
    )
    def test_build_managed_session_prompt_falls_back_to_bootstrap(self, _mock_context):
        prompt, meta = coordination_lambda._build_managed_session_prompt(
            "Execute outcome checks",
            "devops",
        )
        self.assertEqual(
            prompt,
            "agents.md project=devops\n\nExecute outcome checks",
        )
        self.assertFalse(meta["loaded"])

    def test_build_ssm_commands_preflight(self):
        request = {
            "request_id": "CRQ-ABC123",
            "project_id": "devops",
            "feature_id": "DVP-FTR-999",
        }
        commands = coordination_lambda._build_ssm_commands(request, "preflight", None)
        blob = "\n".join(commands)
        self.assertIn("context_sync.py --project devops --skip-records", blob)
        self.assertIn("tracker.py pending-updates --project devops", blob)
        self.assertIn("provider_rotation_check.py", blob)
        self.assertIn("preflight mode complete - provider checks passed", blob)
        self.assertIn("MCP_CHECK_SCRIPT_JSON", blob)
        self.assertIn("exec(json.loads(sys.argv[1]))", blob)
        self.assertIn("COORDINATION_CALLBACK_URL", blob)
        self.assertIn("trap '__coordination_callback_on_exit' EXIT", blob)

    def test_build_ssm_commands_includes_scoped_dispatch_payload(self):
        request = {
            "request_id": "CRQ-ABC123",
            "project_id": "devops",
            "feature_id": "DVP-FTR-999",
        }
        commands = coordination_lambda._build_ssm_commands(
            request,
            "codex_full_auto",
            "test prompt",
            dispatch_id="DSP-XYZ123",
        )
        blob = "\n".join(commands)
        self.assertIn("COORDINATION_DISPATCH_ID", blob)
        self.assertIn("COORDINATION_DISPATCH_PAYLOAD_PATH", blob)
        self.assertIn("COORDINATION_DISPATCH_PAYLOAD=", blob)
        self.assertIn("\"dispatch_id\":\"DSP-XYZ123\"", blob)
        self.assertIn("\"coordination_request_id\":\"CRQ-ABC123\"", blob)

    def test_build_ssm_commands_codex(self):
        request = {
            "request_id": "CRQ-ABC123",
            "project_id": "devops",
            "feature_id": "DVP-FTR-999",
        }
        commands = coordination_lambda._build_ssm_commands(
            request,
            "codex_full_auto",
            "test prompt",
        )
        blob = "\n".join(commands)
        self.assertIn("launch_devops_codex.sh", blob)
        self.assertIn("COORDINATION_PROMPT", blob)
        self.assertIn("secretsmanager get-secret-value", blob)
        self.assertIn("CODEX_API_KEY", blob)
        self.assertIn("COORDINATION_CALLBACK_PROVIDER=\"openai_codex\"", blob)

    def test_compute_governance_hash_local_uses_mcp_server_source(self):
        class _FakeMcpServer:
            def _compute_governance_hash(self, force_refresh=False):
                if force_refresh is not True:
                    raise AssertionError("force_refresh should be requested")
                return "c" * 64

        with patch.object(
            coordination_lambda,
            "_load_mcp_server_module",
            return_value=_FakeMcpServer(),
        ):
            result = coordination_lambda._compute_governance_hash_local()

        self.assertEqual(result, "c" * 64)

    def test_build_ssm_commands_uses_idempotent_mcp_profile_bootstrap(self):
        request = {
            "request_id": "CRQ-MCP001",
            "project_id": "enceladus",
            "feature_id": "ENC-FTR-016",
        }
        commands = coordination_lambda._build_ssm_commands(
            request,
            "codex_full_auto",
            "validate mcp bootstrap",
        )
        blob = "\n".join(commands)
        self.assertIn("COORD_MCP_INSTALLER_CANDIDATES_JSON", blob)
        self.assertIn("COORD_MCP_MARKER_PATH", blob)
        self.assertIn("COORD_MCP_PROFILE_PATH", blob)
        self.assertIn("COORD_MCP_SKIP_INSTALL=0", blob)
        self.assertIn("COORD_MCP_BOOTSTRAP_MAX_ATTEMPTS", blob)
        self.assertIn("COORDINATION_PREFLIGHT_MCP_PROFILE_MODE=warm_skip", blob)

    def test_build_ssm_commands_mcp_connectivity_checks_capabilities_and_governance_hash(self):
        request = {
            "request_id": "CRQ-MCP002",
            "project_id": "enceladus",
            "feature_id": "ENC-FTR-016",
        }
        commands = coordination_lambda._build_ssm_commands(
            request,
            "preflight",
            None,
        )
        blob = "\n".join(commands)
        self.assertIn("coordination_capabilities", blob)
        self.assertIn("governance_hash", blob)
        self.assertIn("api_gateway", blob)

    @patch.object(
        coordination_lambda,
        "_provider_secret_readiness",
        return_value={
            "openai_codex": {"secret_status": "active"},
            "claude_agent_sdk": {"secret_status": "active"},
        },
    )
    def test_handle_capabilities_exposes_host_v2_mcp_and_fleet_template(self, _mock_readiness):
        resp = coordination_lambda._handle_capabilities()
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        caps = body["capabilities"]
        self.assertIn("mcp_bootstrap", caps["host_v2"])
        self.assertIn("fleet_template", caps["host_v2"])
        self.assertIn("max_active_dispatches", caps["host_v2"]["fleet_template"])
        self.assertIn("auto_terminate_on_terminal", caps["host_v2"]["fleet_template"])
        self.assertIn("profile_path", caps["enceladus_mcp_profile"])
        self.assertIn("marker_path", caps["enceladus_mcp_profile"])
        self.assertEqual(
            caps["mcp_remote_gateway"]["transport"],
            "streamable_http",
        )
        self.assertTrue(caps["mcp_remote_gateway"]["compatibility"]["chatgpt_custom_gpt"])
        self.assertTrue(caps["mcp_remote_gateway"]["compatibility"]["managed_codex_sessions"])
        self.assertEqual(
            caps["providers"]["openai_codex"]["mcp_server_configuration"]["transport"],
            "streamable_http",
        )
        self.assertEqual(
            caps["providers"]["openai_codex"]["mcp_server_configuration"]["auth_header"],
            "X-Coordination-Internal-Key",
        )
        self.assertTrue(
            caps["providers"]["openai_codex"]["mcp_server_configuration"]["url"].endswith(
                "/api/v1/coordination/mcp"
            )
        )

    @patch.object(
        coordination_lambda,
        "_load_governance_dictionary",
        return_value=(
            {
                "version": "test-v1",
                "updated_at": "2026-02-27T00:00:00Z",
                "entities": {
                    "tracker.task": {
                        "fields": {
                            "status": {
                                "type": "enum",
                                "enum": ["open", "in-progress", "closed"],
                            }
                        }
                    }
                },
            },
            {"source": "dynamodb", "table": "governance-policies", "policy_id": "governance_data_dictionary"},
        ),
    )
    def test_governance_dictionary_lookup_validates_enum_value(self, _mock_dictionary):
        event = {
            "queryStringParameters": {
                "entity": "tracker.task",
                "field": "status",
                "value": "open",
            }
        }
        resp = coordination_lambda._handle_governance_dictionary(event)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["entity"], "tracker.task")
        self.assertEqual(body["field"], "status")
        self.assertTrue(body["validation"]["valid"])

    @patch.object(
        coordination_lambda,
        "_load_governance_dictionary",
        return_value=(
            {
                "version": "test-v1",
                "updated_at": "2026-02-27T00:00:00Z",
                "entities": {
                    "tracker.task": {
                        "fields": {
                            "status": {
                                "type": "enum",
                                "enum": ["open", "in-progress", "closed"],
                            }
                        }
                    }
                },
            },
            {"source": "dynamodb", "table": "governance-policies", "policy_id": "governance_data_dictionary"},
        ),
    )
    def test_governance_dictionary_lookup_rejects_unknown_field(self, _mock_dictionary):
        event = {"queryStringParameters": {"entity": "tracker.task", "field": "unknown"}}
        resp = coordination_lambda._handle_governance_dictionary(event)
        self.assertEqual(resp["statusCode"], 404)
        body = json.loads(resp["body"])
        self.assertFalse(body["success"])
        self.assertEqual(body["error_envelope"]["code"], "NOT_FOUND")

    @patch.object(
        coordination_lambda,
        "_load_governance_dictionary",
        return_value=(
            {
                "version": "test-v1",
                "updated_at": "2026-02-27T00:00:00Z",
                "entities": {
                    "tracker.task": {"description": "Task", "fields": {"status": {"type": "enum", "enum": ["open"]}}},
                    "deploy.request": {"description": "Deploy", "fields": {"change_type": {"type": "enum", "enum": ["patch"]}}},
                },
            },
            {"source": "fallback_file", "table": "governance-policies", "policy_id": "governance_data_dictionary"},
        ),
    )
    def test_governance_dictionary_index_lists_entities(self, _mock_dictionary):
        event = {"queryStringParameters": {}}
        resp = coordination_lambda._handle_governance_dictionary(event)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["count"], 2)
        self.assertIn("tracker.task", body["entities"])

    @patch.object(coordination_lambda, "_load_mcp_server_module")
    def test_mcp_http_initialize_and_tools_list(self, mock_load_module):
        class _FakeModule:
            async def list_tools(self):
                return [{"name": "connection_health", "description": "health"}]

            async def call_tool(self, name, arguments):
                return [{"type": "text", "text": json.dumps({"success": True, "name": name})}]

            async def list_resources(self):
                return [{"uri": "governance://agents.md", "name": "agents.md"}]

            async def list_resource_templates(self):
                return [{"uriTemplate": "projects://reference/{project_id}", "name": "Project reference document"}]

            async def read_resource(self, uri):
                return "# mock resource"

        mock_load_module.return_value = _FakeModule()

        init_event = {
            "requestContext": {"http": {"method": "POST"}},
            "rawPath": "/api/v1/coordination/mcp",
            "body": json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "req-init",
                    "method": "initialize",
                    "params": {},
                }
            ),
        }
        init_resp = coordination_lambda._handle_mcp_http(init_event, {"auth_mode": "internal-key"})
        self.assertEqual(init_resp["statusCode"], 200)
        init_body = json.loads(init_resp["body"])
        self.assertEqual(init_body["jsonrpc"], "2.0")
        self.assertEqual(init_body["id"], "req-init")
        self.assertEqual(init_body["result"]["protocolVersion"], "2024-11-05")
        self.assertIn("tools", init_body["result"]["capabilities"])

        list_tools_event = {
            "requestContext": {"http": {"method": "POST"}},
            "rawPath": "/api/v1/coordination/mcp",
            "body": json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "req-tools",
                    "method": "tools/list",
                    "params": {},
                }
            ),
        }
        list_tools_resp = coordination_lambda._handle_mcp_http(list_tools_event, {"auth_mode": "internal-key"})
        self.assertEqual(list_tools_resp["statusCode"], 200)
        list_tools_body = json.loads(list_tools_resp["body"])
        self.assertEqual(list_tools_body["id"], "req-tools")
        self.assertGreaterEqual(len(list_tools_body["result"]["tools"]), 1)
        self.assertEqual(list_tools_body["result"]["tools"][0]["name"], "connection_health")

    @patch.object(coordination_lambda, "_authenticate", return_value=({"auth_mode": "internal-key"}, None))
    @patch.object(coordination_lambda, "_handle_mcp_http")
    def test_lambda_handler_routes_mcp_endpoint(self, mock_handle_mcp_http, _mock_auth):
        mock_handle_mcp_http.return_value = coordination_lambda._response(
            200,
            {"jsonrpc": "2.0", "id": "req", "result": {"ok": True}},
        )
        event = {
            "requestContext": {"http": {"method": "POST"}},
            "rawPath": "/api/v1/coordination/mcp",
            "body": json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "req",
                    "method": "initialize",
                    "params": {},
                }
            ),
        }
        resp = coordination_lambda.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        mock_handle_mcp_http.assert_called_once()

    @patch.object(coordination_lambda, "DISPATCH_TIMEOUT_CEILING_SECONDS", 1800)
    @patch.object(coordination_lambda, "HOST_V2_TIMEOUT_SECONDS", 9999)
    @patch.object(coordination_lambda, "_build_ssm_commands", return_value=["echo ok"])
    @patch.object(coordination_lambda, "_get_ssm")
    def test_send_dispatch_applies_timeout_ceiling(
        self,
        mock_get_ssm,
        _mock_build_commands,
    ):
        mock_ssm = mock_get_ssm.return_value
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
        request = {"request_id": "CRQ-AAA111", "project_id": "devops"}
        result = coordination_lambda._send_dispatch(
            request=request,
            execution_mode="preflight",
            prompt=None,
            dispatch_id="DSP-AAA111",
        )
        self.assertEqual(result["timeout_seconds"], 1800)
        _, kwargs = mock_ssm.send_command.call_args
        self.assertEqual(kwargs["TimeoutSeconds"], 1800)
        self.assertEqual(kwargs["Parameters"]["executionTimeout"], ["1800"])
        self.assertEqual(
            kwargs["CloudWatchOutputConfig"]["CloudWatchLogGroupName"],
            coordination_lambda.WORKER_RUNTIME_LOG_GROUP,
        )

    @patch.object(
        coordination_lambda,
        "_resolve_host_dispatch_target",
        return_value={
            "instance_id": "i-fleet123",
            "host_kind": "fleet",
            "host_allocation": "fleet",
            "host_source": "launch_template",
            "launch_template_id": "lt-abc123",
            "launch_template_version": "$Latest",
        },
    )
    @patch.object(coordination_lambda, "_build_ssm_commands", return_value=["echo ok"])
    @patch.object(coordination_lambda, "_get_ssm")
    def test_send_dispatch_uses_resolved_target_instance(
        self,
        mock_get_ssm,
        _mock_build_commands,
        _mock_resolve_target,
    ):
        mock_ssm = mock_get_ssm.return_value
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-fleet"}}
        request = {"request_id": "CRQ-FLEET001", "project_id": "enceladus"}
        result = coordination_lambda._send_dispatch(
            request=request,
            execution_mode="preflight",
            prompt=None,
            dispatch_id="DSP-FLEET001",
            host_allocation="fleet",
        )
        _, kwargs = mock_ssm.send_command.call_args
        self.assertEqual(kwargs["InstanceIds"], ["i-fleet123"])
        self.assertEqual(result["instance_id"], "i-fleet123")
        self.assertEqual(result["host_kind"], "fleet")
        self.assertEqual(result["host_source"], "launch_template")

    @patch.object(coordination_lambda, "_get_ec2")
    def test_cleanup_dispatch_host_terminates_fleet_instance(self, mock_get_ec2):
        request = {
            "dispatch": {
                "host_kind": "fleet",
                "instance_id": "i-fleet123",
            }
        }
        updated = coordination_lambda._cleanup_dispatch_host(request, "callback_terminal")
        mock_get_ec2.return_value.terminate_instances.assert_called_once_with(
            InstanceIds=["i-fleet123"]
        )
        self.assertEqual(updated["dispatch"]["host_cleanup_state"], "terminated")

    @patch.object(coordination_lambda, "_sweep_orphan_fleet_hosts", return_value={"enabled": True, "terminated": 0})
    @patch.object(coordination_lambda, "_count_active_host_dispatches", return_value=0)
    @patch.object(
        coordination_lambda,
        "_launch_fleet_instance",
        return_value={"instance_id": "i-fleet123", "launched_at": "2026-02-24T00:00:00Z"},
    )
    @patch.object(
        coordination_lambda,
        "_wait_for_fleet_instance_readiness",
        return_value={"ready_at": "2026-02-24T00:01:00Z"},
    )
    @patch.object(coordination_lambda, "_fleet_launch_ready", return_value=True)
    def test_resolve_host_dispatch_target_launches_fleet_instance(
        self,
        _mock_fleet_ready,
        _mock_wait_ready,
        _mock_launch,
        _mock_count_active,
        _mock_sweep,
    ):
        request = {"request_id": "CRQ-FLEET002", "project_id": "enceladus"}
        target = coordination_lambda._resolve_host_dispatch_target(
            request,
            execution_mode="preflight",
            dispatch_id="DSP-FLEET002",
            host_allocation="auto",
        )
        self.assertEqual(target["instance_id"], "i-fleet123")
        self.assertEqual(target["host_kind"], "fleet")
        self.assertEqual(target["host_source"], "launch_template")

    def test_build_ssm_commands_claude(self):
        request = {
            "request_id": "CRQ-ABC123",
            "project_id": "devops",
            "feature_id": "DVP-FTR-999",
        }
        commands = coordination_lambda._build_ssm_commands(
            request,
            "claude_headless",
            "test prompt",
        )
        blob = "\n".join(commands)
        self.assertIn("secretsmanager get-secret-value", blob)
        self.assertIn("ANTHROPIC_API_KEY", blob)
        self.assertIn("claude \"$COORDINATION_PROMPT\"", blob)
        self.assertIn("dispatch_start", blob)
        self.assertIn("COORDINATION_DISPATCH_ID", blob)
        self.assertIn("COORDINATION_CALLBACK_PROVIDER=\"claude_agent_sdk\"", blob)

    @patch.object(
        coordination_lambda,
        "_build_managed_session_prompt",
        return_value=(
            "agents.md project=devops\n\nAuthoritative governance context loaded via Enceladus MCP resources.\n\nDispatch task:\nSay api path ok",
            {
                "loaded": True,
                "source": "mcp_resources",
                "included_uris": ["governance://agents.md"],
                "truncated": False,
            },
        ),
    )
    @patch.object(coordination_lambda, "_fetch_provider_api_key", return_value="sk-ant-test")
    @patch.object(coordination_lambda.urllib.request, "urlopen")
    def test_dispatch_claude_api_uses_authenticated_messages_request(
        self,
        mock_urlopen,
        _mock_fetch_key,
        _mock_managed_prompt,
    ):
        class _FakeResponse:
            status = 200
            headers = {"request-id": "req-test-123"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return json.dumps(
                    {
                        "id": "msg_test_123",
                        "model": "claude-sonnet-4-6",
                        "stop_reason": "end_turn",
                        "usage": {"input_tokens": 12, "output_tokens": 8},
                        "content": [{"type": "text", "text": "api path ok"}],
                    }
                ).encode("utf-8")

        mock_urlopen.return_value = _FakeResponse()
        request = {
            "request_id": "CRQ-CLAUDEAPI",
            "project_id": "devops",
            "initiative_title": "Claude API route",
            "outcomes": ["verify authenticated API call"],
            "constraints": {"max_tokens": 128},
            "provider_session": {
                "model": "claude-sonnet-4-6",
                "permission_mode": "acceptEdits",
                "allowed_tools": ["projects_get"],
            },
        }
        result = coordination_lambda._dispatch_claude_api(
            request=request,
            prompt="Say api path ok",
            dispatch_id="DSP-CLAUDEAPI",
        )

        self.assertEqual(result["provider"], "claude_agent_sdk")
        self.assertEqual(result["transport"], "anthropic_messages_api")
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["execution_id"], "msg_test_123")
        self.assertEqual(result["provider_result"]["summary"], "api path ok")
        self.assertEqual(result["provider_result"]["request_id"], "req-test-123")
        self.assertTrue(result["provider_result"]["governance_context"]["loaded"])
        self.assertEqual(
            result["provider_result"]["governance_context"]["source"],
            "mcp_resources",
        )

        called_req = mock_urlopen.call_args.args[0]
        self.assertEqual(called_req.full_url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(called_req.headers.get("X-api-key"), "sk-ant-test")
        self.assertEqual(called_req.headers.get("Anthropic-version"), "2023-06-01")
        payload = json.loads(called_req.data.decode("utf-8"))
        self.assertTrue(str(payload["messages"][0]["content"]).startswith("agents.md project=devops"))

    @patch.object(
        coordination_lambda,
        "_build_managed_session_prompt",
        return_value=(
            "agents.md project=devops\n\nAuthoritative governance context loaded via Enceladus MCP resources.\n\nDispatch task:\nReturn json result ok",
            {
                "loaded": True,
                "source": "mcp_resources",
                "included_uris": ["governance://agents.md"],
                "truncated": False,
            },
        ),
    )
    @patch.object(coordination_lambda, "_fetch_provider_api_key", return_value="sk-openai-test")
    @patch.object(coordination_lambda.urllib.request, "urlopen")
    def test_dispatch_openai_codex_api_uses_authenticated_responses_request(
        self,
        mock_urlopen,
        _mock_fetch_key,
        _mock_managed_prompt,
    ):
        class _FakeResponse:
            status = 200
            headers = {"x-request-id": "req-openai-123"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return json.dumps(
                    {
                        "id": "resp_test_123",
                        "model": "gpt-5.1-codex-max",
                        "status": "completed",
                        "conversation": "conv_test_1",
                        "usage": {"input_tokens": 21, "output_tokens": 13},
                        "output_text": "{\"result\":\"ok\"}",
                    }
                ).encode("utf-8")

        mock_urlopen.return_value = _FakeResponse()
        request = {
            "request_id": "CRQ-OPENAIAPI",
            "project_id": "devops",
            "initiative_title": "OpenAI API route",
            "outcomes": ["verify authenticated API call"],
            "constraints": {
                "max_output_tokens": 512,
                "functions": [
                    {
                        "name": "tracker_get",
                        "description": "Read tracker item",
                        "parameters": {"type": "object", "properties": {"id": {"type": "string"}}},
                        "strict": True,
                    }
                ],
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "coordination_result",
                        "schema": {
                            "type": "object",
                            "properties": {"result": {"type": "string"}},
                            "required": ["result"],
                        },
                        "strict": True,
                    },
                },
            },
            "provider_session": {
                "model": "gpt-5.1-codex-max",
                "session_id": "conv_test_1",
            },
        }
        result = coordination_lambda._dispatch_openai_codex_api(
            request=request,
            prompt="Return json result ok",
            dispatch_id="DSP-OPENAIAPI",
        )

        self.assertEqual(result["provider"], "openai_codex")
        self.assertEqual(result["transport"], "openai_responses_api")
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["execution_id"], "resp_test_123")
        self.assertEqual(result["provider_result"]["request_id"], "req-openai-123")
        self.assertEqual(result["provider_result"]["session_id"], "conv_test_1")
        self.assertTrue(result["provider_result"]["governance_context"]["loaded"])
        self.assertEqual(
            result["provider_result"]["governance_context"]["source"],
            "mcp_resources",
        )

        called_req = mock_urlopen.call_args.args[0]
        self.assertEqual(called_req.full_url, "https://api.openai.com/v1/responses")
        self.assertEqual(called_req.headers.get("Authorization"), "Bearer sk-openai-test")
        payload = json.loads(called_req.data.decode("utf-8"))
        self.assertEqual(payload["model"], "gpt-5.1-codex-max")
        self.assertEqual(payload["max_output_tokens"], 512)
        self.assertEqual(payload["conversation"], "conv_test_1")
        self.assertTrue(str(payload["input"]).startswith("agents.md project=devops"))
        self.assertEqual(payload["tools"][0]["type"], "function")
        self.assertEqual(payload["tools"][0]["name"], "tracker_get")
        self.assertEqual(payload["text"]["format"]["type"], "json_schema")

    def test_parse_mcp_result_json_payload(self):
        content = [type("Text", (), {"text": json.dumps({"success": True})})()]
        parsed = coordination_lambda._parse_mcp_result(content)
        self.assertEqual(parsed, {"success": True})

    @patch.object(coordination_lambda, "_load_project_meta")
    @patch.object(coordination_lambda, "_append_tracker_history")
    @patch.object(coordination_lambda, "_create_tracker_record_auto")
    def test_decomposition_uses_tracker_helpers_with_metadata(
        self,
        mock_create_tracker_record_auto,
        mock_append_tracker_history,
        mock_load_project_meta,
    ):
        mock_load_project_meta.return_value = coordination_lambda.ProjectMeta(
            project_id="devops",
            prefix="DVP",
        )

        mock_create_tracker_record_auto.side_effect = [
            "DVP-FTR-901",
            "DVP-TSK-901",
            "DVP-TSK-902",
            "DVP-ISS-901",
        ]

        out = coordination_lambda._decompose_and_create_tracker_artifacts(
            project_id="devops",
            initiative_title="Decompose work",
            outcomes=["First outcome", "Second outcome"],
            request_id="CRQ-123",
            assigned_to="AGENT-003",
        )

        self.assertEqual(out["feature_id"], "DVP-FTR-901")
        self.assertEqual(out["task_ids"], ["DVP-TSK-901", "DVP-TSK-902"])
        self.assertEqual(out["issue_ids"], ["DVP-ISS-901"])
        self.assertRegex(out["governance_hash"], r"^[0-9a-f]{64}$")

        self.assertEqual(mock_create_tracker_record_auto.call_count, 4)
        for call in mock_create_tracker_record_auto.call_args_list:
            payload = call.kwargs
            self.assertEqual(payload.get("coordination_request_id"), "CRQ-123")
            self.assertRegex(str(payload.get("governance_hash", "")), r"^[0-9a-f]{64}$")
            if payload.get("record_type") == "task":
                self.assertIsInstance(payload.get("acceptance_criteria"), list)
                self.assertGreaterEqual(len(payload.get("acceptance_criteria")), 1)

        self.assertTrue(mock_append_tracker_history.called)

    @patch.object(coordination_lambda, "_get_ddb")
    def test_create_tracker_record_auto_requires_acceptance_criteria_for_tasks(
        self,
        mock_get_ddb,
    ):
        with self.assertRaises(ValueError) as ctx:
            coordination_lambda._create_tracker_record_auto(
                project_id="devops",
                prefix="DVP",
                record_type="task",
                title="Task without acceptance criteria",
                description="Generated in test",
                priority="P1",
                assigned_to="AGENT-003",
            )

        self.assertIn("acceptance_criteria", str(ctx.exception))
        mock_get_ddb.assert_not_called()

    @patch.object(coordination_lambda, "_get_ddb")
    def test_next_tracker_sequence_seeds_counter_from_existing_records_when_missing(
        self,
        mock_get_ddb,
    ):
        class _FakeDdb:
            def __init__(self):
                self.query_calls = 0
                self.last_update_kwargs = None

            def get_item(self, **_kwargs):
                return {}

            def query(self, **_kwargs):
                self.query_calls += 1
                return {
                    "Items": [
                        {"item_id": {"S": "DVP-TSK-098"}},
                        {"item_id": {"S": "DVP-TSK-104"}},
                    ]
                }

            def update_item(self, **kwargs):
                self.last_update_kwargs = kwargs
                return {"Attributes": {"next_num": {"N": "105"}}}

        fake_ddb = _FakeDdb()
        mock_get_ddb.return_value = fake_ddb

        seq = coordination_lambda._next_tracker_sequence("devops", "task")

        self.assertEqual(seq, 105)
        self.assertEqual(fake_ddb.query_calls, 1)
        self.assertEqual(
            fake_ddb.last_update_kwargs["Key"]["record_id"]["S"],
            "counter#task",
        )

    @patch.object(coordination_lambda, "_get_ddb")
    def test_next_tracker_sequence_uses_existing_counter_without_scan(
        self,
        mock_get_ddb,
    ):
        class _FakeDdb:
            def get_item(self, **_kwargs):
                return {"Item": {"record_id": {"S": "counter#task"}, "next_num": {"N": "212"}}}

            def query(self, **_kwargs):
                raise AssertionError("query should not run when counter exists")

            def update_item(self, **_kwargs):
                return {"Attributes": {"next_num": {"N": "213"}}}

        mock_get_ddb.return_value = _FakeDdb()

        seq = coordination_lambda._next_tracker_sequence("devops", "task")
        self.assertEqual(seq, 213)

    def test_build_ssm_commands_claude_agent_sdk(self):
        request = {
            "request_id": "CRQ-ABC123",
            "project_id": "devops",
            "feature_id": "DVP-FTR-999",
            "provider_session": {
                "session_id": "sess_001",
                "fork_from_session_id": "sess_000",
                "model": "claude-sonnet-4-5",
                "permission_mode": "acceptEdits",
                "allowed_tools": ["tracker_get", "tracker_log"],
            },
        }
        commands = coordination_lambda._build_ssm_commands(
            request,
            "claude_agent_sdk",
            "test prompt",
        )
        blob = "\n".join(commands)
        self.assertIn("launch_devops_claude_agent_sdk.sh", blob)
        self.assertIn("COORDINATION_PROVIDER_SESSION_ID", blob)
        self.assertIn("COORDINATION_PROVIDER_FORK_FROM_SESSION_ID", blob)
        self.assertIn("COORDINATION_PERMISSION_MODE", blob)
        self.assertIn("COORDINATION_ALLOWED_TOOLS", blob)

    def test_build_ssm_commands_claude_agent_sdk_defaults_model_and_permission(self):
        request = {
            "request_id": "CRQ-DEF456",
            "project_id": "devops",
            "feature_id": "DVP-FTR-999",
            "provider_session": {},
        }
        commands = coordination_lambda._build_ssm_commands(
            request,
            "claude_agent_sdk",
            "test prompt",
        )
        blob = "\n".join(commands)
        self.assertIn('COORDINATION_PROVIDER_MODEL="claude-sonnet-4-6"', blob)
        self.assertIn('COORDINATION_PERMISSION_MODE="acceptEdits"', blob)

    def test_validate_provider_session_accepts_claude_fields(self):
        payload = {
            "preferred_provider": "claude_agent_sdk",
            "session_id": "sess_001",
            "fork_from_session_id": "sess_000",
            "permission_mode": "acceptEdits",
            "allowed_tools": ["tracker_get", "tracker_log", "tracker_get"],
        }
        with self.assertRaises(ValueError):
            coordination_lambda._validate_provider_session(payload)

        payload.pop("session_id")
        result = coordination_lambda._validate_provider_session(payload)
        self.assertEqual(result["preferred_provider"], "claude_agent_sdk")
        self.assertEqual(result["fork_from_session_id"], "sess_000")
        self.assertEqual(result["permission_mode"], "acceptEdits")
        self.assertEqual(result["allowed_tools"], ["tracker_get", "tracker_log"])

    def test_validate_provider_session_rejects_non_enceladus_tool(self):
        payload = {
            "session_id": "sess_001",
            "allowed_tools": ["tracker_get", "rm_rf_everything"],
        }
        with self.assertRaises(ValueError):
            coordination_lambda._validate_provider_session(payload)

    def test_classify_dispatch_failure_retriable_and_non_retriable(self):
        failure_class, retryable = coordination_lambda._classify_dispatch_failure(
            RuntimeError("Connection timed out while sending command")
        )
        self.assertEqual(failure_class, "network_timeout")
        self.assertTrue(retryable)

        failure_class, retryable = coordination_lambda._classify_dispatch_failure(
            RuntimeError("Access denied from provider key check")
        )
        self.assertEqual(failure_class, "auth_invalid")
        self.assertFalse(retryable)

    def test_retry_backoff_seconds_sequence(self):
        self.assertEqual(coordination_lambda._retry_backoff_seconds(1), 10)
        self.assertEqual(coordination_lambda._retry_backoff_seconds(2), 60)
        self.assertEqual(coordination_lambda._retry_backoff_seconds(3), 300)
        self.assertEqual(coordination_lambda._retry_backoff_seconds(4), 300)

    def test_build_ssm_commands_codex_app_server(self):
        request = {
            "request_id": "CRQ-APP001",
            "project_id": "devops",
            "feature_id": "DVP-FTR-999",
            "provider_session": {
                "thread_id": "thread-abc",
                "fork_from_thread_id": "",
                "model": "gpt-5-codex",
                "provider_session_id": "psn-abc",
            },
        }
        commands = coordination_lambda._build_ssm_commands(
            request,
            "codex_app_server",
            "test app-server prompt",
        )
        blob = "\n".join(commands)
        self.assertIn("launch_devops_codex_app_server.sh", blob)
        self.assertIn("COORDINATION_PROVIDER_THREAD_ID=", blob)
        self.assertIn("COORDINATION_PROVIDER_SESSION_ID=", blob)

    def test_build_secret_fetch_commands_emit_structured_error_with_secret_arn(self):
        commands = coordination_lambda._build_secret_fetch_commands(
            provider_label="openai",
            secret_id="devops/coordination/openai/api-key",
            exported_var="CODEX_API_KEY",
            exit_code=18,
        )
        blob = "\n".join(commands)
        self.assertIn("COORD_PREFLIGHT_TS", blob)
        self.assertIn("secretsmanager describe-secret", blob)
        self.assertIn("\\\"secret_arn\\\":\\\"$COORD_SECRET_ARN\\\"", blob)
        self.assertIn("\\\"timestamp\\\":\\\"$COORD_PREFLIGHT_TS\\\"", blob)

    @patch.object(coordination_lambda, "_get_secretsmanager")
    def test_provider_secret_status_marks_expired_from_rotation_due_tag(self, mock_get_secretsmanager):
        class _SecretsClient:
            def describe_secret(self, SecretId):
                _ = SecretId
                return {
                    "ARN": "arn:aws:secretsmanager:us-west-2:356364570033:secret:devops/coordination/openai/api-key",
                    "Tags": [
                        {"Key": "rotation_policy", "Value": "90d"},
                        {"Key": "next_rotation_due", "Value": "2000-01-01T00:00:00Z"},
                    ],
                }

        mock_get_secretsmanager.return_value = _SecretsClient()

        out = coordination_lambda._provider_secret_status(
            "openai_codex",
            "devops/coordination/openai/api-key",
        )
        self.assertEqual(out["secret_status"], "expired")
        self.assertTrue(out["rotation_warning"])
        self.assertIsNotNone(out["secret_arn"])

    def test_extract_provider_api_key_supports_json_secret_payloads(self):
        openai_secret = '{"api_key":"sk-test-openai"}'
        anthropic_secret = '{"anthropic_api_key":"sk-ant-test"}'
        self.assertEqual(
            coordination_lambda._extract_provider_api_key("openai", openai_secret),
            "sk-test-openai",
        )
        self.assertEqual(
            coordination_lambda._extract_provider_api_key("anthropic", anthropic_secret),
            "sk-ant-test",
        )

    @patch.object(coordination_lambda, "_provider_preflight_fetch_and_probe")
    def test_lambda_provider_preflight_aggregates_results(self, mock_provider_preflight):
        mock_provider_preflight.side_effect = [
            {"provider": "openai", "ok": True},
            {"provider": "anthropic", "ok": False},
        ]
        out = coordination_lambda._lambda_provider_preflight("preflight", timeout_seconds=5)
        self.assertFalse(out["passed"])
        self.assertEqual(len(out["results"]), 2)
        self.assertEqual(out["timeout_seconds"], 5)


# ---------------------------------------------------------------------------
# Intake Debounce Tests (DVP-TSK-251)
# ---------------------------------------------------------------------------


class IntakeDebounceExtractRecordIdsTests(unittest.TestCase):
    """Tests for _extract_record_ids_from_body and _extract_record_ids_from_request."""

    def test_extract_from_body_related_record_ids(self):
        body = {"related_record_ids": ["DVP-TSK-100", "dvp-iss-200", " DVP-FTR-001 "]}
        ids = coordination_lambda._extract_record_ids_from_body(body)
        self.assertEqual(ids, {"DVP-TSK-100", "DVP-ISS-200", "DVP-FTR-001"})

    def test_extract_from_body_outcomes_text(self):
        body = {
            "outcomes": [
                "Implement the feature described in DVP-TSK-150",
                "Fix the bug DVP-ISS-042 and close DVP-ISS-043",
            ]
        }
        ids = coordination_lambda._extract_record_ids_from_body(body)
        self.assertIn("DVP-TSK-150", ids)
        self.assertIn("DVP-ISS-042", ids)
        self.assertIn("DVP-ISS-043", ids)

    def test_extract_from_body_constraints_json(self):
        body = {
            "constraints": {
                "depends_on": "DVP-TSK-099",
                "note": "Must finish DVP-FTR-010 first",
            }
        }
        ids = coordination_lambda._extract_record_ids_from_body(body)
        self.assertIn("DVP-TSK-099", ids)
        self.assertIn("DVP-FTR-010", ids)

    def test_extract_from_body_empty(self):
        body = {}
        ids = coordination_lambda._extract_record_ids_from_body(body)
        self.assertEqual(ids, set())

    def test_extract_from_body_no_matching_ids(self):
        body = {
            "related_record_ids": [],
            "outcomes": ["Just do general cleanup"],
            "constraints": {"priority": "high"},
        }
        ids = coordination_lambda._extract_record_ids_from_body(body)
        self.assertEqual(ids, set())

    def test_extract_from_body_child_ids(self):
        """Record IDs with child suffixes like DVP-TSK-100-0A should be captured."""
        body = {"related_record_ids": ["DVP-TSK-100-0A", "DVP-ISS-200-1B"]}
        ids = coordination_lambda._extract_record_ids_from_body(body)
        self.assertIn("DVP-TSK-100-0A", ids)
        self.assertIn("DVP-ISS-200-1B", ids)

    def test_extract_from_request_includes_feature_and_task_ids(self):
        request = {
            "feature_id": "DVP-FTR-023",
            "task_ids": ["DVP-TSK-100", "DVP-TSK-101"],
            "issue_ids": ["DVP-ISS-050"],
            "related_record_ids": [],
            "outcomes": [],
        }
        ids = coordination_lambda._extract_record_ids_from_request(request)
        self.assertIn("DVP-FTR-023", ids)
        self.assertIn("DVP-TSK-100", ids)
        self.assertIn("DVP-TSK-101", ids)
        self.assertIn("DVP-ISS-050", ids)

    def test_extract_from_request_combines_all_sources(self):
        request = {
            "feature_id": "DVP-FTR-023",
            "task_ids": ["DVP-TSK-100"],
            "issue_ids": [],
            "related_record_ids": ["DVP-ISS-200"],
            "outcomes": ["Fix DVP-TSK-300"],
            "constraints": {"ref": "DVP-FTR-005"},
        }
        ids = coordination_lambda._extract_record_ids_from_request(request)
        self.assertIn("DVP-FTR-023", ids)
        self.assertIn("DVP-TSK-100", ids)
        self.assertIn("DVP-ISS-200", ids)
        self.assertIn("DVP-TSK-300", ids)
        self.assertIn("DVP-FTR-005", ids)

    def test_extract_from_request_empty(self):
        request = {}
        ids = coordination_lambda._extract_record_ids_from_request(request)
        self.assertEqual(ids, set())

    def test_extract_ids_case_insensitive(self):
        """IDs should be uppercased regardless of input case."""
        body = {"related_record_ids": ["dvp-tsk-100", "Dvp-Iss-200"]}
        ids = coordination_lambda._extract_record_ids_from_body(body)
        self.assertIn("DVP-TSK-100", ids)
        self.assertIn("DVP-ISS-200", ids)

    def test_extract_multiple_projects(self):
        """IDs from different 3-letter project prefixes should all be captured."""
        body = {
            "related_record_ids": ["DVP-TSK-100", "MOD-TSK-050", "AGH-FTR-001"]
        }
        ids = coordination_lambda._extract_record_ids_from_body(body)
        self.assertEqual(ids, {"DVP-TSK-100", "MOD-TSK-050", "AGH-FTR-001"})


class IntakeDebounceMergeTests(unittest.TestCase):
    """Tests for _merge_requests."""

    def _make_existing(self, **overrides):
        base = {
            "request_id": "CRQ-EXISTING",
            "initiative_title": "Original Title",
            "outcomes": ["Outcome A"],
            "constraints": {"priority": "high"},
            "related_record_ids": ["DVP-TSK-100"],
            "requestor_session_id": "session-001",
            "source_sessions": [],
            "source_requests": [],
            "state": "intake_received",
            "state_history": [],
            "sync_version": 1,
            "debounce_window_expires_epoch": 0,
        }
        base.update(overrides)
        return base

    def test_merge_titles_concatenated(self):
        existing = self._make_existing(initiative_title="Title A")
        new_body = {"initiative_title": "Title B"}
        merged = coordination_lambda._merge_requests(existing, new_body, "session-002")
        self.assertEqual(merged["initiative_title"], "Title A + Title B")

    def test_merge_titles_same_not_duplicated(self):
        existing = self._make_existing(initiative_title="Same Title")
        new_body = {"initiative_title": "Same Title"}
        merged = coordination_lambda._merge_requests(existing, new_body, "session-002")
        self.assertEqual(merged["initiative_title"], "Same Title")

    def test_merge_outcomes_union_dedup(self):
        existing = self._make_existing(outcomes=["Outcome A", "Outcome B"])
        new_body = {"outcomes": ["Outcome B", "Outcome C"]}
        merged = coordination_lambda._merge_requests(existing, new_body, "session-002")
        self.assertEqual(merged["outcomes"], ["Outcome A", "Outcome B", "Outcome C"])

    def test_merge_constraints_deep_merge(self):
        existing = self._make_existing(
            constraints={"priority": "high", "deadline": "2026-03-01"}
        )
        new_body = {"constraints": {"priority": "critical", "scope": "full"}}
        merged = coordination_lambda._merge_requests(existing, new_body, "session-002")
        self.assertEqual(merged["constraints"]["priority"], "critical")
        self.assertEqual(merged["constraints"]["deadline"], "2026-03-01")
        self.assertEqual(merged["constraints"]["scope"], "full")

    def test_merge_related_record_ids_union(self):
        existing = self._make_existing(
            related_record_ids=["DVP-TSK-100", "DVP-TSK-101"]
        )
        new_body = {"related_record_ids": ["DVP-TSK-101", "DVP-ISS-050"]}
        merged = coordination_lambda._merge_requests(existing, new_body, "session-002")
        self.assertEqual(
            sorted(merged["related_record_ids"]),
            ["DVP-ISS-050", "DVP-TSK-100", "DVP-TSK-101"],
        )

    def test_merge_source_sessions_tracked(self):
        existing = self._make_existing(
            requestor_session_id="session-001",
            source_sessions=[],
        )
        merged = coordination_lambda._merge_requests(existing, {}, "session-002")
        self.assertIn("session-001", merged["source_sessions"])
        self.assertIn("session-002", merged["source_sessions"])

    def test_merge_source_sessions_no_duplicate(self):
        existing = self._make_existing(
            requestor_session_id="session-001",
            source_sessions=["session-001"],
        )
        merged = coordination_lambda._merge_requests(existing, {}, "session-001")
        self.assertEqual(merged["source_sessions"].count("session-001"), 1)

    def test_merge_source_requests_tracked(self):
        existing = self._make_existing(
            request_id="CRQ-EXISTING",
            source_requests=[],
        )
        merged = coordination_lambda._merge_requests(existing, {}, "session-002")
        self.assertIn("CRQ-EXISTING", merged["source_requests"])

    def test_merge_resets_debounce_window(self):
        now_epoch = int(time.time())
        existing = self._make_existing(
            debounce_window_expires_epoch=now_epoch - 10  # expired
        )
        merged = coordination_lambda._merge_requests(existing, {}, "session-002")
        self.assertGreater(
            merged["debounce_window_expires_epoch"], now_epoch
        )

    def test_merge_increments_sync_version(self):
        existing = self._make_existing(sync_version=3)
        merged = coordination_lambda._merge_requests(existing, {}, "session-002")
        self.assertEqual(merged["sync_version"], 4)

    def test_merge_appends_state_history(self):
        existing = self._make_existing(state_history=[])
        merged = coordination_lambda._merge_requests(existing, {"initiative_title": "New"}, "session-002")
        self.assertEqual(len(merged["state_history"]), 1)
        entry = merged["state_history"][0]
        self.assertEqual(entry["from"], "intake_received")
        self.assertEqual(entry["to"], "intake_received")
        self.assertIn("Merged", entry["reason"])

    def test_merge_sets_last_merge_at(self):
        existing = self._make_existing()
        merged = coordination_lambda._merge_requests(existing, {}, "session-002")
        self.assertIn("last_merge_at", merged)
        self.assertTrue(merged["last_merge_at"].endswith("Z"))


class IntakeDebounceStateTests(unittest.TestCase):
    """Tests for intake_received state machine integration."""

    def test_intake_received_in_transitions(self):
        self.assertIn("intake_received", coordination_lambda._TRANSITIONS)

    def test_intake_received_can_transition_to_queued(self):
        self.assertIn("queued", coordination_lambda._TRANSITIONS["intake_received"])

    def test_intake_received_can_transition_to_cancelled(self):
        self.assertIn("cancelled", coordination_lambda._TRANSITIONS["intake_received"])

    def test_intake_received_cannot_transition_to_running(self):
        self.assertNotIn("running", coordination_lambda._TRANSITIONS["intake_received"])

    def test_intake_received_cannot_transition_to_dispatching(self):
        self.assertNotIn("dispatching", coordination_lambda._TRANSITIONS["intake_received"])

    def test_debounce_window_seconds_default(self):
        self.assertEqual(coordination_lambda.DEBOUNCE_WINDOW_SECONDS, 180)


class IntakeDebounceCapabilitiesTests(unittest.TestCase):
    """Tests for intake section in capabilities response."""

    def test_capabilities_includes_intake_section(self):
        result = coordination_lambda._handle_capabilities()
        body = json.loads(result["body"])
        caps = body["capabilities"]
        self.assertIn("intake", caps)

    def test_capabilities_intake_debounce_window(self):
        result = coordination_lambda._handle_capabilities()
        body = json.loads(result["body"])
        intake = body["capabilities"]["intake"]
        self.assertEqual(intake["debounce_window_seconds"], 180)

    def test_capabilities_intake_dedup_by(self):
        result = coordination_lambda._handle_capabilities()
        body = json.loads(result["body"])
        intake = body["capabilities"]["intake"]
        self.assertEqual(intake["dedup_by"], "record_id_overlap")

    def test_capabilities_intake_merge_behavior(self):
        result = coordination_lambda._handle_capabilities()
        body = json.loads(result["body"])
        intake = body["capabilities"]["intake"]
        self.assertIn("merge_behavior", intake)
        mb = intake["merge_behavior"]
        self.assertEqual(mb["initiative_title"], "concatenate_with_plus")
        self.assertEqual(mb["outcomes"], "union_dedup")
        self.assertEqual(mb["constraints"], "deep_merge_latest_wins")
        self.assertEqual(mb["related_record_ids"], "union_set")

    def test_capabilities_intake_promotion(self):
        result = coordination_lambda._handle_capabilities()
        body = json.loads(result["body"])
        intake = body["capabilities"]["intake"]
        self.assertEqual(intake["promotion"], "on_read")

    def test_capabilities_include_reliability_controls(self):
        result = coordination_lambda._handle_capabilities()
        body = json.loads(result["body"])
        controls = body["capabilities"]["reliability_controls"]
        self.assertEqual(controls["max_dispatch_attempts"], coordination_lambda.MAX_DISPATCH_ATTEMPTS)
        self.assertEqual(controls["retry_backoff_seconds"], [10, 60, 300])
        self.assertIn("network_timeout", controls["retriable_failure_classes"])
        self.assertIn("auth_invalid", controls["non_retriable_failure_classes"])

    def test_capabilities_include_provider_rotation_metadata(self):
        fake_readiness = {
            "openai_codex": {
                "secret_status": "active",
                "secret_ref_configured": True,
                "secret_ref": "devops/coordination/openai/api-key",
                "rotation_policy": "90d",
                "last_rotated": "2026-02-19T17:30:00Z",
                "next_rotation_due": "2026-05-20T00:00:00Z",
                "days_until_rotation_due": 89,
                "rotation_warning": False,
            },
            "claude_agent_sdk": {
                "secret_status": "active",
                "secret_ref_configured": True,
                "secret_ref": "devops/coordination/anthropic/api-key",
                "rotation_policy": "90d",
                "last_rotated": "2026-02-19T17:30:00Z",
                "next_rotation_due": "2026-05-20T00:00:00Z",
                "days_until_rotation_due": 89,
                "rotation_warning": False,
            },
        }
        with patch.object(coordination_lambda, "_provider_secret_readiness", return_value=fake_readiness):
            result = coordination_lambda._handle_capabilities()
        body = json.loads(result["body"])
        providers = body["capabilities"]["providers"]
        self.assertEqual(providers["openai_codex"]["rotation_policy"], "90d")
        self.assertEqual(
            providers["openai_codex"]["default_model"],
            coordination_lambda.DEFAULT_OPENAI_CODEX_MODEL,
        )
        self.assertEqual(providers["claude_agent_sdk"]["secret_ref"], "devops/coordination/anthropic/api-key")
        self.assertEqual(
            providers["claude_agent_sdk"]["default_model"],
            coordination_lambda.DEFAULT_CLAUDE_AGENT_MODEL,
        )


class WorkerRuntimeHardeningTests(unittest.TestCase):
    def test_build_ssm_commands_includes_mcp_connectivity_retry(self):
        request = {
            "request_id": "CRQ-ABC123",
            "project_id": "devops",
            "feature_id": "DVP-FTR-999",
        }
        commands = coordination_lambda._build_ssm_commands(request, "preflight", None)
        blob = "\n".join(commands)
        self.assertIn("MCP_CONN_OK=0", blob)
        self.assertIn("for MCP_BACKOFF in 10 30 60; do", blob)
        self.assertIn("Enceladus MCP connection health", blob)

    def test_build_result_payload_failure_has_recent_worklogs(self):
        request = {
            "feature_id": "DVP-FTR-023",
            "task_ids": ["DVP-TSK-170", "DVP-TSK-169"],
            "issue_ids": ["DVP-ISS-016"],
        }
        for idx in range(7):
            coordination_lambda._append_dispatch_worklog(
                request,
                dispatch_id=f"d-{idx}",
                provider="openai_codex",
                execution_mode="codex_full_auto",
                outcome_state="running",
                summary=f"worklog-{idx}",
            )

        payload = coordination_lambda._build_result_payload(
            request,
            state="failed",
            summary="timeout while running",
            execution_id="exec-1",
            provider="openai_codex",
            details={},
            feed_updates={},
            reason="timeout",
        )

        self.assertEqual(payload["reason"], "timeout")
        self.assertEqual(len(payload["last_worklogs"]), 5)
        self.assertEqual(payload["last_worklogs"][-1]["dispatch_id"], "d-6")
        self.assertEqual(
            payload["feed_updates"]["items_modified"],
            ["DVP-FTR-023", "DVP-TSK-170", "DVP-TSK-169", "DVP-ISS-016"],
        )

    def test_is_timeout_failure_variants(self):
        self.assertTrue(coordination_lambda._is_timeout_failure("timedout", "", ""))
        self.assertTrue(coordination_lambda._is_timeout_failure("", "Command timed out", ""))
        self.assertTrue(coordination_lambda._is_timeout_failure("", "", "runtime timeout occurred"))
        self.assertFalse(coordination_lambda._is_timeout_failure("failed", "generic failure", "unknown"))

    def test_related_records_mutated_detects_changes(self):
        before = {
            "JAP-TASK-412": {
                "status": "open",
                "updated_at": "2026-02-20T00:00:00Z",
                "sync_version": 1,
                "history_len": 2,
            }
        }
        after = {
            "JAP-TASK-412": {
                "status": "in-progress",
                "updated_at": "2026-02-20T00:05:00Z",
                "sync_version": 2,
                "history_len": 3,
            }
        }
        mutated, changed = coordination_lambda._related_records_mutated(before, after)
        self.assertTrue(mutated)
        self.assertEqual(changed, ["JAP-TASK-412"])


class DispatchPlanLifecycleTests(unittest.TestCase):
    def test_promote_expired_intake_requests_generates_dispatch_plan(self):
        now_epoch = int(time.time())
        request_id = "CRQ-PLANPROMO1"
        intake_item = {
            "request_id": request_id,
            "project_id": "enceladus",
            "state": "intake_received",
            "state_history": [
                {
                    "timestamp": "2026-02-24T00:00:00Z",
                    "from": None,
                    "to": "intake_received",
                    "reason": "created",
                }
            ],
            "debounce_window_expires_epoch": now_epoch - 5,
            "updated_epoch": now_epoch - 30,
            "updated_at": "2026-02-24T00:00:00Z",
            "sync_version": 1,
            "dispatch_outcomes": {},
        }

        class _FakeDdb:
            def query(self, **_kwargs):
                return {"Items": [coordination_lambda._serialize(intake_item)["M"]]}

        generated_plan = {
            "plan_id": "plan-promoted-1",
            "dispatches": [
                {
                    "dispatch_id": "dsp-plan-promoted-1",
                    "sequence_order": 0,
                    "provider": "openai_codex",
                    "execution_mode": "codex_full_auto",
                    "outcomes": ["Outcome A"],
                }
            ],
        }
        updated_items = []

        with patch.object(coordination_lambda, "_get_ddb", return_value=_FakeDdb()),              patch.object(coordination_lambda, "_generate_dispatch_plan_for_request", return_value=generated_plan),              patch.object(coordination_lambda, "_update_request", side_effect=lambda item: updated_items.append(dict(item))):
            promoted = coordination_lambda._promote_expired_intake_requests("enceladus")

        self.assertEqual(promoted, [request_id])
        self.assertGreaterEqual(len(updated_items), 1)
        final = updated_items[-1]
        self.assertEqual(final.get("state"), "queued")
        self.assertEqual(final.get("dispatch_plan"), generated_plan)
        self.assertEqual((final.get("dispatch_plan") or {}).get("dispatches", [])[0]["dispatch_id"], "dsp-plan-promoted-1")

    def test_dispatch_uses_dispatch_plan_entry_execution_mode_and_dispatch_id(self):
        request = {
            "request_id": "CRQ-PLAN-DISPATCH",
            "project_id": "enceladus",
            "state": "queued",
            "dispatch_attempts": 0,
            "execution_mode": "preflight",
            "provider_session": {
                "preferred_provider": "openai_codex",
                "model": "gpt-4o-mini",
            },
            "dispatch_plan": {
                "dispatches": [
                    {
                        "dispatch_id": "dsp-plan-route-1",
                        "sequence_order": 0,
                        "provider": "openai_codex",
                        "execution_mode": "codex_app_server",
                        "provider_config": {
                            "model": "gpt-5.1-codex-max",
                            "thread_id": "thread-plan-1",
                        },
                    }
                ]
            },
            "dispatch_outcomes": {},
            "task_ids": [],
            "feature_id": None,
            "issue_ids": [],
        }
        updated_items = []
        event = {
            "body": json.dumps(
                {
                    "prompt": "route by plan",
                }
            )
        }

        with patch.object(coordination_lambda, "_get_request", return_value=request),              patch.object(coordination_lambda, "_acquire_dispatch_lock", return_value=True),              patch.object(coordination_lambda, "_lambda_provider_preflight", return_value={"passed": True, "results": []}),              patch.object(
                 coordination_lambda,
                 "_dispatch_openai_codex_api",
                 return_value={
                     "dispatch_id": "dsp-plan-route-1",
                     "execution_id": "resp-plan-route-1",
                     "execution_mode": "codex_app_server",
                     "provider": "openai_codex",
                     "transport": "openai_responses_api",
                     "api_endpoint": "https://api.openai.com/v1/responses",
                     "sent_at": "2026-02-24T00:00:00Z",
                     "completed_at": "2026-02-24T00:00:02Z",
                     "status": "succeeded",
                     "provider_result": {
                         "session_id": "conv-plan-route-1",
                         "thread_id": "thread-plan-1",
                         "provider_session_id": "resp-plan-route-1",
                         "model": "gpt-5.1-codex-max",
                         "response_status": "completed",
                         "summary": "plan route ok",
                         "usage": {"input_tokens": 9, "output_tokens": 6},
                         "completed_at": "2026-02-24T00:00:02Z",
                     },
                 },
             ) as mock_direct_dispatch,              patch.object(coordination_lambda, "_send_dispatch") as mock_send_dispatch,              patch.object(coordination_lambda, "_find_active_host_dispatch") as mock_find_host_dispatch,              patch.object(coordination_lambda, "_finalize_tracker_from_request"),              patch.object(coordination_lambda, "_update_request", side_effect=lambda item: updated_items.append(dict(item))):
            resp = coordination_lambda._handle_dispatch_request(event, "CRQ-PLAN-DISPATCH")

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        mock_direct_dispatch.assert_called_once()
        _args, kwargs = mock_direct_dispatch.call_args
        self.assertEqual(kwargs["dispatch_id"], "dsp-plan-route-1")
        self.assertEqual(kwargs["execution_mode"], "codex_app_server")
        routed_request = kwargs["request"]
        routed_provider_session = routed_request.get("provider_session") or {}
        self.assertEqual(routed_provider_session.get("thread_id"), "thread-plan-1")
        self.assertEqual(routed_provider_session.get("model"), "gpt-5.1-codex-max")
        mock_send_dispatch.assert_not_called()
        mock_find_host_dispatch.assert_not_called()
        self.assertGreaterEqual(len(updated_items), 1)
        final = updated_items[-1]
        self.assertEqual(final.get("state"), "succeeded")
        self.assertEqual((final.get("dispatch") or {}).get("dispatch_id"), "dsp-plan-route-1")

    def test_callback_uses_dispatch_plan_execution_mode_for_worklog(self):
        request = {
            "request_id": "CRQ-PLAN-CALLBACK",
            "project_id": "enceladus",
            "state": "running",
            "callback_token": "cb-plan-token",
            "callback_token_expires_epoch": int(time.time()) + 3600,
            "dispatch_plan": {
                "dispatches": [
                    {
                        "dispatch_id": "dsp-plan-callback-1",
                        "sequence_order": 0,
                        "provider": "openai_codex",
                        "execution_mode": "codex_full_auto",
                    }
                ]
            },
            "dispatch_outcomes": {},
        }
        updated_items = []
        event = {
            "headers": {"x-coordination-callback-token": "cb-plan-token"},
            "body": json.dumps(
                {
                    "provider": "openai_codex",
                    "dispatch_id": "dsp-plan-callback-1",
                    "state": "succeeded",
                    "execution_id": "exe-plan-cb-1",
                    "summary": "callback complete",
                }
            ),
        }

        with patch.object(coordination_lambda, "_get_request", return_value=request),              patch.object(coordination_lambda, "_finalize_tracker_from_request"),              patch.object(coordination_lambda, "_emit_callback_event"),              patch.object(coordination_lambda, "_update_request", side_effect=lambda item: updated_items.append(dict(item))):
            resp = coordination_lambda._handle_callback(event, "CRQ-PLAN-CALLBACK")

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertEqual((body.get("plan_status") or {}).get("completed"), 1)
        self.assertEqual((body.get("plan_status") or {}).get("total"), 1)

        self.assertGreaterEqual(len(updated_items), 1)
        final = updated_items[-1]
        last_worklog = (final.get("dispatch_worklogs") or [])[-1]
        self.assertEqual(last_worklog.get("dispatch_id"), "dsp-plan-callback-1")
        self.assertEqual(last_worklog.get("execution_mode"), "codex_full_auto")

    def test_normalize_anthropic_batch_result_item_succeeded(self):
        item = {
            "custom_id": "DSP-BATCH-001",
            "result": {
                "type": "succeeded",
                "message": {
                    "id": "msg_batch_1",
                    "model": "claude-sonnet-4-6",
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 120, "output_tokens": 30},
                    "content": [{"type": "text", "text": "Batch dispatch complete"}],
                },
            },
        }
        out = coordination_lambda._normalize_anthropic_batch_result_item(
            item,
            default_model="claude-sonnet-4-6",
            batch_id="batch_123",
        )

        self.assertEqual(out["provider"], "claude_agent_sdk")
        self.assertEqual(out["state"], "succeeded")
        self.assertEqual(out["dispatch_id"], "DSP-BATCH-001")
        self.assertEqual(out["execution_id"], "msg_batch_1")
        self.assertIn("Batch dispatch complete", out["summary"])
        self.assertEqual(out["details"]["batch_id"], "batch_123")
        self.assertEqual(out["details"]["batch_result_type"], "succeeded")
        self.assertEqual(out["details"]["model"], "claude-sonnet-4-6")
        self.assertEqual(out["details"]["usage"]["input_tokens"], 120)

    def test_normalize_anthropic_batch_result_item_errored(self):
        item = {
            "custom_id": "DSP-BATCH-002",
            "result": {
                "type": "errored",
                "error": {
                    "type": "invalid_request_error",
                    "message": "prompt too long",
                },
            },
        }
        out = coordination_lambda._normalize_anthropic_batch_result_item(
            item,
            default_model="claude-sonnet-4-6",
            batch_id="batch_123",
        )

        self.assertEqual(out["state"], "failed")
        self.assertEqual(out["dispatch_id"], "DSP-BATCH-002")
        self.assertIn("invalid_request_error", out["summary"])
        self.assertEqual(out["details"]["error_type"], "invalid_request_error")
        self.assertEqual(out["details"]["batch_result_type"], "errored")

    def test_handle_anthropic_batch_results_callback_fans_out_and_aggregates(self):
        request = {
            "request_id": "CRQ-BATCH-001",
            "project_id": "enceladus",
            "state": "running",
            "callback_token": "cb-batch-token",
            "callback_token_expires_epoch": int(time.time()) + 3600,
            "provider_session": {"model": "claude-sonnet-4-6"},
            "batch_context": {"batch_id": "batch_123"},
            "dispatch_plan": {
                "dispatches": [
                    {"dispatch_id": "DSP-BATCH-001"},
                    {"dispatch_id": "DSP-BATCH-002"},
                ]
            },
            "dispatch_outcomes": {},
        }
        latest_request = dict(request)
        updated_items = []
        callback_events = []

        event = {
            "headers": {"x-coordination-callback-token": "cb-batch-token"},
            "body": json.dumps(
                {
                    "batch_id": "batch_123",
                    "results": [
                        {
                            "custom_id": "DSP-BATCH-001",
                            "result": {
                                "type": "succeeded",
                                "message": {
                                    "id": "msg_batch_1",
                                    "model": "claude-sonnet-4-6",
                                    "usage": {"input_tokens": 100, "output_tokens": 40},
                                    "content": [{"type": "text", "text": "first ok"}],
                                },
                            },
                        },
                        {
                            "custom_id": "DSP-BATCH-002",
                            "result": {
                                "type": "errored",
                                "error": {
                                    "type": "invalid_request_error",
                                    "message": "bad input",
                                },
                            },
                        },
                    ],
                }
            ),
        }

        def _fake_callback(cb_event, cb_request_id):
            callback_events.append(cb_event)
            self.assertEqual(cb_request_id, "CRQ-BATCH-001")
            return {"statusCode": 200, "body": json.dumps({"success": True})}

        def _fake_update(item):
            updated_items.append(dict(item))

        with patch.object(coordination_lambda, "_get_request", side_effect=[request, latest_request]), \
             patch.object(coordination_lambda, "_handle_callback", side_effect=_fake_callback), \
             patch.object(coordination_lambda, "_update_request", side_effect=_fake_update):
            resp = coordination_lambda._handle_anthropic_batch_results_callback(
                event,
                "CRQ-BATCH-001",
            )

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertEqual(body["processed"], 2)
        self.assertEqual(body["batch_metrics"]["succeeded_count"], 1)
        self.assertEqual(body["batch_metrics"]["failed_count"], 1)
        self.assertEqual(body["batch_metrics"]["aggregate_state"], "partial")
        self.assertGreater(body["batch_metrics"]["total_cost_usd"], 0)
        self.assertEqual(len(callback_events), 2)

        first_payload = json.loads(callback_events[0]["body"])
        second_payload = json.loads(callback_events[1]["body"])
        self.assertEqual(first_payload["dispatch_id"], "DSP-BATCH-001")
        self.assertEqual(second_payload["dispatch_id"], "DSP-BATCH-002")
        self.assertEqual(first_payload["provider"], "claude_agent_sdk")
        self.assertEqual(second_payload["provider"], "claude_agent_sdk")

        self.assertGreaterEqual(len(updated_items), 1)
        final = updated_items[-1]
        self.assertEqual(
            ((final.get("batch_context") or {}).get("results_metrics") or {}).get("aggregate_state"),
            "partial",
        )


class SessionBridgeIntegrationTests(unittest.TestCase):
    def test_dispatch_codex_full_auto_routes_to_direct_api(self):
        request = {
            "request_id": "CRQ-CODEX-DIRECT",
            "project_id": "devops",
            "state": "queued",
            "dispatch_attempts": 0,
            "provider_session": {
                "preferred_provider": "openai_codex",
                "model": "gpt-5.1-codex-max",
            },
            "task_ids": [],
            "feature_id": None,
            "issue_ids": [],
        }
        updated_items = []
        event = {
            "body": json.dumps(
                {
                    "execution_mode": "codex_full_auto",
                    "dispatch_id": "DSP-CODEX01",
                    "prompt": "Say direct api ok",
                }
            )
        }

        with patch.object(coordination_lambda, "_get_request", return_value=request), \
             patch.object(coordination_lambda, "_acquire_dispatch_lock", return_value=True), \
             patch.object(coordination_lambda, "_lambda_provider_preflight", return_value={"passed": True, "results": []}), \
             patch.object(
                 coordination_lambda,
                 "_dispatch_openai_codex_api",
                 return_value={
                     "dispatch_id": "DSP-CODEX01",
                     "execution_id": "resp-direct-1",
                     "execution_mode": "codex_full_auto",
                     "provider": "openai_codex",
                     "transport": "openai_responses_api",
                     "api_endpoint": "https://api.openai.com/v1/responses",
                     "sent_at": "2026-02-20T00:00:00Z",
                     "completed_at": "2026-02-20T00:00:02Z",
                     "status": "succeeded",
                     "provider_result": {
                         "session_id": "conv-direct-1",
                         "thread_id": "conv-direct-1",
                         "provider_session_id": "resp-direct-1",
                         "model": "gpt-5.1-codex-max",
                         "response_status": "completed",
                         "summary": "direct api ok",
                         "usage": {"input_tokens": 9, "output_tokens": 6},
                         "completed_at": "2026-02-20T00:00:02Z",
                     },
                 },
             ) as mock_direct_dispatch, \
             patch.object(coordination_lambda, "_send_dispatch") as mock_send_dispatch, \
             patch.object(coordination_lambda, "_find_active_host_dispatch") as mock_find_host_dispatch, \
             patch.object(coordination_lambda, "_finalize_tracker_from_request"), \
             patch.object(coordination_lambda, "_update_request", side_effect=lambda item: updated_items.append(dict(item))):
            resp = coordination_lambda._handle_dispatch_request(event, "CRQ-CODEX-DIRECT")

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertGreaterEqual(len(updated_items), 1)
        final = updated_items[-1]
        self.assertEqual(final.get("state"), "succeeded")
        self.assertEqual((final.get("result") or {}).get("provider"), "openai_codex")
        mock_direct_dispatch.assert_called_once()
        mock_send_dispatch.assert_not_called()
        mock_find_host_dispatch.assert_not_called()

    def test_dispatch_codex_noop_without_related_mutations_is_failed(self):
        request = {
            "request_id": "CRQ-CODEX-NOOP",
            "project_id": "jobapps",
            "state": "queued",
            "dispatch_attempts": 0,
            "provider_session": {
                "preferred_provider": "openai_codex",
                "model": "gpt-5.1-codex-max",
            },
            "related_record_ids": ["JAP-TASK-412", "JAP-TASK-413"],
            "task_ids": [],
            "feature_id": None,
            "issue_ids": [],
        }
        updated_items = []
        event = {
            "body": json.dumps(
                {
                    "execution_mode": "codex_full_auto",
                    "dispatch_id": "DSP-CODEX-NOOP",
                    "prompt": "Implement related tasks",
                }
            )
        }
        snapshots = {
            "JAP-TASK-412": {
                "status": "open",
                "updated_at": "2026-02-20T00:00:00Z",
                "sync_version": 1,
                "history_len": 2,
            },
            "JAP-TASK-413": {
                "status": "open",
                "updated_at": "2026-02-20T00:00:00Z",
                "sync_version": 1,
                "history_len": 2,
            },
        }

        with patch.object(coordination_lambda, "_get_request", return_value=request), \
             patch.object(coordination_lambda, "_acquire_dispatch_lock", return_value=True), \
             patch.object(coordination_lambda, "_lambda_provider_preflight", return_value={"passed": True, "results": []}), \
             patch.object(coordination_lambda, "_collect_tracker_snapshots", side_effect=[dict(snapshots), dict(snapshots)]), \
             patch.object(
                 coordination_lambda,
                 "_dispatch_openai_codex_api",
                 return_value={
                     "dispatch_id": "DSP-CODEX-NOOP",
                     "execution_id": "resp-noop-1",
                     "execution_mode": "codex_full_auto",
                     "provider": "openai_codex",
                     "transport": "openai_responses_api",
                     "api_endpoint": "https://api.openai.com/v1/responses",
                     "sent_at": "2026-02-20T00:00:00Z",
                     "completed_at": "2026-02-20T00:00:02Z",
                     "status": "succeeded",
                     "provider_result": {
                         "session_id": "conv-noop-1",
                         "thread_id": "conv-noop-1",
                         "provider_session_id": "resp-noop-1",
                         "model": "gpt-5.1-codex-max",
                         "response_status": "completed",
                         "summary": "plan only",
                         "usage": {"input_tokens": 9, "output_tokens": 6},
                         "completed_at": "2026-02-20T00:00:02Z",
                     },
                 },
             ) as mock_direct_dispatch, \
             patch.object(coordination_lambda, "_send_dispatch") as mock_send_dispatch, \
             patch.object(coordination_lambda, "_find_active_host_dispatch") as mock_find_host_dispatch, \
             patch.object(coordination_lambda, "_finalize_tracker_from_request"), \
             patch.object(coordination_lambda, "_update_request", side_effect=lambda item: updated_items.append(dict(item))):
            resp = coordination_lambda._handle_dispatch_request(event, "CRQ-CODEX-NOOP")

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertFalse(body["success"])
        self.assertGreaterEqual(len(updated_items), 1)
        final = updated_items[-1]
        self.assertEqual(final.get("state"), "failed")
        provider_result = ((final.get("result") or {}).get("details") or {}).get("provider_result") or {}
        guard = provider_result.get("related_record_mutation_guard") or {}
        self.assertTrue(guard.get("required"))
        self.assertFalse(guard.get("mutated"))
        self.assertEqual(provider_result.get("failure_class"), "no_effect")
        mock_direct_dispatch.assert_called_once()
        mock_send_dispatch.assert_not_called()
        mock_find_host_dispatch.assert_not_called()

    def test_dispatch_codex_allow_noop_success_bypasses_mutation_guard(self):
        request = {
            "request_id": "CRQ-CODEX-NOOP-ALLOWED",
            "project_id": "jobapps",
            "state": "queued",
            "dispatch_attempts": 0,
            "provider_session": {
                "preferred_provider": "openai_codex",
                "model": "gpt-5.1-codex-max",
            },
            "constraints": {"allow_noop_success": True},
            "related_record_ids": ["JAP-TASK-412"],
            "task_ids": [],
            "feature_id": None,
            "issue_ids": [],
        }
        updated_items = []
        event = {
            "body": json.dumps(
                {
                    "execution_mode": "codex_full_auto",
                    "dispatch_id": "DSP-CODEX-NOOP-ALLOWED",
                    "prompt": "plan only",
                }
            )
        }

        with patch.object(coordination_lambda, "_get_request", return_value=request), \
             patch.object(coordination_lambda, "_acquire_dispatch_lock", return_value=True), \
             patch.object(coordination_lambda, "_lambda_provider_preflight", return_value={"passed": True, "results": []}), \
             patch.object(coordination_lambda, "_collect_tracker_snapshots") as mock_collect_snapshots, \
             patch.object(
                 coordination_lambda,
                 "_dispatch_openai_codex_api",
                 return_value={
                     "dispatch_id": "DSP-CODEX-NOOP-ALLOWED",
                     "execution_id": "resp-noop-allowed",
                     "execution_mode": "codex_full_auto",
                     "provider": "openai_codex",
                     "transport": "openai_responses_api",
                     "api_endpoint": "https://api.openai.com/v1/responses",
                     "sent_at": "2026-02-20T00:00:00Z",
                     "completed_at": "2026-02-20T00:00:02Z",
                     "status": "succeeded",
                     "provider_result": {
                         "session_id": "conv-noop-allowed",
                         "thread_id": "conv-noop-allowed",
                         "provider_session_id": "resp-noop-allowed",
                         "model": "gpt-5.1-codex-max",
                         "response_status": "completed",
                         "summary": "plan only",
                         "usage": {"input_tokens": 9, "output_tokens": 6},
                         "completed_at": "2026-02-20T00:00:02Z",
                     },
                 },
             ), \
             patch.object(coordination_lambda, "_send_dispatch"), \
             patch.object(coordination_lambda, "_find_active_host_dispatch"), \
             patch.object(coordination_lambda, "_finalize_tracker_from_request"), \
             patch.object(coordination_lambda, "_update_request", side_effect=lambda item: updated_items.append(dict(item))):
            resp = coordination_lambda._handle_dispatch_request(event, "CRQ-CODEX-NOOP-ALLOWED")

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertGreaterEqual(len(updated_items), 1)
        final = updated_items[-1]
        self.assertEqual(final.get("state"), "succeeded")
        mock_collect_snapshots.assert_not_called()

    def test_dispatch_persists_mcp_metadata(self):
        request = {
            "request_id": "CRQ-244DISP",
            "project_id": "devops",
            "state": "queued",
            "dispatch_attempts": 0,
            "provider_session": {"model": "gpt-5-codex"},
            "task_ids": [],
            "feature_id": None,
        }
        updated_items = []

        event = {
            "body": json.dumps(
                {
                    "execution_mode": "codex_app_server",
                    "prompt": "dispatch smoke",
                }
            )
        }

        with patch.object(coordination_lambda, "_get_request", return_value=request), \
             patch.object(coordination_lambda, "_acquire_dispatch_lock", return_value=True), \
             patch.object(coordination_lambda, "_lambda_provider_preflight", return_value={"passed": True, "results": []}), \
             patch.object(
                 coordination_lambda,
                 "_dispatch_openai_codex_api",
                 return_value={
                     "dispatch_id": "DSP-244",
                     "execution_id": "resp-244",
                     "execution_mode": "codex_app_server",
                     "provider": "openai_codex",
                     "transport": "openai_responses_api",
                     "api_endpoint": "https://api.openai.com/v1/responses",
                     "sent_at": "2026-02-20T00:00:00Z",
                     "completed_at": "2026-02-20T00:00:02Z",
                     "status": "succeeded",
                     "provider_result": {
                         "provider": "openai_codex",
                         "session_id": "conv-244",
                         "thread_id": "conv-244",
                         "provider_session_id": "resp-244",
                         "model": "gpt-5.1-codex-max",
                         "response_status": "completed",
                         "summary": "dispatch smoke complete",
                         "request_id": "req-openai-244",
                         "usage": {"input_tokens": 12, "output_tokens": 9},
                         "completed_at": "2026-02-20T00:00:02Z",
                     },
                 },
             ), \
             patch.object(coordination_lambda, "_send_dispatch") as mock_send_dispatch, \
             patch.object(coordination_lambda, "_find_active_host_dispatch") as mock_find_host_dispatch, \
             patch.object(coordination_lambda, "_finalize_tracker_from_request"), \
             patch.object(coordination_lambda, "_append_tracker_history"), \
             patch.object(coordination_lambda, "_set_tracker_status"), \
             patch.object(coordination_lambda, "_update_request", side_effect=lambda item: updated_items.append(dict(item))):
            resp = coordination_lambda._handle_dispatch_request(event, "CRQ-244DISP")

        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertEqual(resp["statusCode"], 200)
        self.assertGreaterEqual(len(updated_items), 1)
        final = updated_items[-1]
        self.assertEqual(final.get("state"), "succeeded")
        self.assertEqual((final.get("result") or {}).get("provider"), "openai_codex")
        self.assertIn("mcp", final)
        self.assertIn("last_dispatch", final["mcp"])
        self.assertEqual(final["mcp"]["last_dispatch"]["capability"], "coordination.request.dispatch")
        self.assertIn("governance_hash", final["mcp"]["last_dispatch"])
        mock_send_dispatch.assert_not_called()
        mock_find_host_dispatch.assert_not_called()

    def test_dispatch_blocks_when_lambda_provider_preflight_fails(self):
        request = {
            "request_id": "CRQ-244PREFLIGHTFAIL",
            "project_id": "devops",
            "state": "queued",
            "dispatch_attempts": 0,
            "provider_session": {"model": "gpt-5-codex"},
            "task_ids": [],
            "feature_id": None,
        }
        event = {"body": json.dumps({"execution_mode": "codex_app_server", "prompt": "dispatch smoke"})}
        preflight = {
            "passed": False,
            "results": [
                {
                    "provider": "openai",
                    "secret_ref": "devops/coordination/openai/api-key",
                    "secret_arn": "arn:aws:secretsmanager:us-west-2:356364570033:secret:devops/coordination/openai/api-key",
                    "failure_reason": "provider_health_failed:http_401",
                    "checked_at": "2026-02-20T01:00:00Z",
                    "ok": False,
                }
            ],
        }
        with patch.object(coordination_lambda, "_get_request", return_value=request), \
             patch.object(coordination_lambda, "_lambda_provider_preflight", return_value=preflight), \
             patch.object(coordination_lambda, "_send_dispatch") as mock_send_dispatch:
            resp = coordination_lambda._handle_dispatch_request(event, "CRQ-244PREFLIGHTFAIL")
        self.assertEqual(resp["statusCode"], 409)
        body = json.loads(resp["body"])
        self.assertFalse(body["success"])
        self.assertEqual(body["provider"], "openai")
        self.assertIn("secret_arn", body)
        self.assertIn("failure_reason", body)
        self.assertEqual(body["timestamp"], "2026-02-20T01:00:00Z")
        mock_send_dispatch.assert_not_called()

    def test_dispatch_claude_sdk_routes_to_direct_api(self):
        request = {
            "request_id": "CRQ-CLAUDE-DIRECT",
            "project_id": "devops",
            "state": "queued",
            "dispatch_attempts": 0,
            "provider_session": {
                "preferred_provider": "claude_agent_sdk",
                "model": "claude-sonnet-4-6",
                "permission_mode": "acceptEdits",
            },
            "task_ids": [],
            "feature_id": None,
            "issue_ids": [],
        }
        updated_items = []
        event = {
            "body": json.dumps(
                {
                    "execution_mode": "claude_agent_sdk",
                    "dispatch_id": "DSP-CLAUDE01",
                    "prompt": "Say direct api ok",
                }
            )
        }

        with patch.object(coordination_lambda, "_get_request", return_value=request), \
             patch.object(coordination_lambda, "_acquire_dispatch_lock", return_value=True), \
             patch.object(coordination_lambda, "_lambda_provider_preflight", return_value={"passed": True, "results": []}), \
             patch.object(
                 coordination_lambda,
                 "_dispatch_claude_api",
                 return_value={
                     "dispatch_id": "DSP-CLAUDE01",
                     "execution_id": "msg-direct-1",
                     "execution_mode": "claude_agent_sdk",
                     "provider": "claude_agent_sdk",
                     "transport": "anthropic_messages_api",
                     "api_endpoint": "https://api.anthropic.com/v1/messages",
                     "sent_at": "2026-02-20T00:00:00Z",
                     "completed_at": "2026-02-20T00:00:02Z",
                     "status": "succeeded",
                     "provider_result": {
                         "session_id": "msg-direct-1",
                         "model": "claude-sonnet-4-6",
                         "permission_mode": "acceptEdits",
                         "allowed_tools": ["projects_get"],
                         "summary": "direct api ok",
                         "stop_reason": "end_turn",
                         "usage": {"input_tokens": 11, "output_tokens": 7},
                         "completed_at": "2026-02-20T00:00:02Z",
                     },
                 },
             ) as mock_direct_dispatch, \
             patch.object(coordination_lambda, "_send_dispatch") as mock_send_dispatch, \
             patch.object(coordination_lambda, "_find_active_host_dispatch") as mock_find_host_dispatch, \
             patch.object(coordination_lambda, "_finalize_tracker_from_request"), \
             patch.object(coordination_lambda, "_update_request", side_effect=lambda item: updated_items.append(dict(item))):
            resp = coordination_lambda._handle_dispatch_request(event, "CRQ-CLAUDE-DIRECT")

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertGreaterEqual(len(updated_items), 1)
        final = updated_items[-1]
        self.assertEqual(final.get("state"), "succeeded")
        self.assertEqual((final.get("result") or {}).get("provider"), "claude_agent_sdk")
        self.assertEqual((final.get("provider_session") or {}).get("session_id"), "msg-direct-1")
        mock_direct_dispatch.assert_called_once()
        mock_send_dispatch.assert_not_called()
        mock_find_host_dispatch.assert_not_called()

    def test_refresh_from_ssm_sets_codex_provider_session_fields(self):
        request = {
            "request_id": "CRQ-244REFRESH",
            "project_id": "devops",
            "state": "running",
            "dispatch": {
                "command_id": "cmd-refresh",
                "execution_mode": "codex_app_server",
            },
            "provider_session": {
                "model": "gpt-5-codex",
            },
        }

        stdout_payload = (
            'COORDINATION_APP_SERVER_RESULT={"provider":"openai_codex","provider_session_id":"psn-smoke",'
            '"thread_id":"thread-smoke","turn_id":"turn-smoke","execution_id":"exe-smoke",'
            '"turn_status":"completed","completed_at":"2026-02-20T00:00:00Z"}'
        )

        class _FakeSsm:
            def get_command_invocation(self, **_kwargs):
                return {
                    "Status": "Success",
                    "StatusDetails": "Success",
                    "StandardOutputContent": stdout_payload,
                    "StandardErrorContent": "",
                }

        with patch.object(coordination_lambda, "_get_ssm", return_value=_FakeSsm()), \
             patch.object(coordination_lambda, "_update_request"), \
             patch.object(coordination_lambda, "_finalize_tracker_from_request"):
            out = coordination_lambda._refresh_request_from_ssm(request)

        ps = out.get("provider_session") or {}
        self.assertEqual(ps.get("provider_session_id"), "psn-smoke")
        self.assertEqual(ps.get("thread_id"), "thread-smoke")
        self.assertEqual(ps.get("turn_id"), "turn-smoke")
        self.assertEqual(ps.get("execution_id"), "exe-smoke")

    def test_redact_session_archive_content_masks_common_secret_patterns(self):
        aws_key_like = "AKIA" + "ABCDEFGHIJKLMNOP"
        pem_block = "-----BEGIN " + "PRIVATE KEY-----\nabc\n-----END " + "PRIVATE KEY-----"
        sample = (
            f"{aws_key_like} and bearer sk-test-token-1234567890 "
            "API_KEY=my-secret-value\n"
            f"{pem_block}"
        )
        redacted, hits = coordination_lambda._redact_session_archive_content(sample)
        self.assertNotIn(aws_key_like, redacted)
        self.assertNotIn("my-secret-value", redacted)
        self.assertNotIn("PRIVATE KEY-----", redacted)
        self.assertIn("[REDACTED:aws_access_key_id]", redacted)
        self.assertIn("[REDACTED:bearer_token]", redacted)
        self.assertIn("[REDACTED:secret_assignment]", redacted)
        self.assertIn("[REDACTED:pem_private_key_block]", redacted)
        self.assertGreaterEqual(len(hits), 3)

    def test_write_session_archive_records_retries_and_succeeds(self):
        attempts = {"count": 0}

        class _FakeS3:
            def put_object(self, **_kwargs):
                attempts["count"] += 1
                if attempts["count"] < 3:
                    raise coordination_lambda.ClientError(
                        {"Error": {"Code": "SlowDown", "Message": "retry"}},
                        "PutObject",
                    )
                return {"ETag": "ok"}

        request = {"request_id": "CRQ-ARCHIVE-1"}
        with patch.object(coordination_lambda, "_get_s3", return_value=_FakeS3()):
            result = coordination_lambda._write_session_archive_records(
                request=request,
                session_id="session-abc",
                instance_id="i-123",
                dispatch_id="DSP-1",
                prompt_text="hello",
                response_text="world",
                token_count=42,
            )

        self.assertTrue(result["archived"])
        self.assertEqual(attempts["count"], 3)
        self.assertIn("/session-abc/", result["key"])
        self.assertEqual(result["records"], 2)

    def test_write_session_archive_records_buffers_on_retry_exhaustion(self):
        class _FakeS3:
            def put_object(self, **_kwargs):
                raise coordination_lambda.ClientError(
                    {"Error": {"Code": "ServiceUnavailable", "Message": "down"}},
                    "PutObject",
                )

        request = {"request_id": "CRQ-ARCHIVE-2"}
        buffered_exists = False
        with tempfile.TemporaryDirectory() as tmpdir:
            original_dir = coordination_lambda.COORDINATION_SESSION_ARCHIVE_BUFFER_DIR
            coordination_lambda.COORDINATION_SESSION_ARCHIVE_BUFFER_DIR = tmpdir
            try:
                with patch.object(coordination_lambda, "_get_s3", return_value=_FakeS3()):
                    result = coordination_lambda._write_session_archive_records(
                        request=request,
                        session_id="session-buffer",
                        instance_id="i-999",
                        dispatch_id="DSP-BUF",
                        prompt_text="prompt",
                        response_text="response",
                    )
                buffered_exists = pathlib.Path(result["buffered_path"]).exists()
            finally:
                coordination_lambda.COORDINATION_SESSION_ARCHIVE_BUFFER_DIR = original_dir

        self.assertFalse(result["archived"])
        self.assertIn("buffered_path", result)
        self.assertTrue(buffered_exists)

    def test_refresh_from_ssm_includes_session_archive_result_for_codex_modes(self):
        request = {
            "request_id": "CRQ-ARCHIVE-3",
            "project_id": "devops",
            "state": "running",
            "dispatch": {
                "command_id": "cmd-archive",
                "execution_mode": "codex_full_auto",
                "dispatch_id": "DSP-ARCHIVE",
                "instance_id": "i-archive",
                "prompt_submitted": "prompt from dispatch",
            },
        }

        class _FakeSsm:
            def get_command_invocation(self, **_kwargs):
                return {
                    "Status": "Success",
                    "StatusDetails": "Success",
                    "StandardOutputContent": "assistant output",
                    "StandardErrorContent": "",
                }

        with patch.object(coordination_lambda, "_get_ssm", return_value=_FakeSsm()), \
             patch.object(coordination_lambda, "_derive_session_archive_payload", return_value={"archived": True, "key": "k"}), \
             patch.object(coordination_lambda, "_update_request"), \
             patch.object(coordination_lambda, "_finalize_tracker_from_request"):
            out = coordination_lambda._refresh_request_from_ssm(request)

        archive = (((out.get("result") or {}).get("details") or {}).get("session_archive") or {})
        self.assertTrue(archive.get("archived"))

    def test_refresh_from_ssm_keeps_running_for_inprogress_status(self):
        request = {
            "request_id": "CRQ-244RUN",
            "project_id": "devops",
            "state": "running",
            "dispatch": {
                "command_id": "cmd-inprogress",
                "execution_mode": "preflight",
            },
        }

        class _FakeSsm:
            def get_command_invocation(self, **_kwargs):
                return {
                    "Status": "InProgress",
                    "StatusDetails": "InProgress",
                    "StandardOutputContent": "",
                    "StandardErrorContent": "",
                }

        with patch.object(coordination_lambda, "_get_ssm", return_value=_FakeSsm()), \
             patch.object(coordination_lambda, "_update_request") as mock_update, \
             patch.object(coordination_lambda, "_finalize_tracker_from_request") as mock_finalize:
            out = coordination_lambda._refresh_request_from_ssm(request)

        self.assertEqual(out.get("state"), "running")
        self.assertEqual((out.get("dispatch") or {}).get("last_ssm_status"), "inprogress")
        mock_update.assert_called_once()
        mock_finalize.assert_not_called()

    def test_callback_persists_mcp_metadata(self):
        request = {
            "request_id": "CRQ-244CB",
            "project_id": "devops",
            "state": "running",
            "callback_token": "cb-token",
            "callback_token_expires_epoch": int(time.time()) + 3600,
            "dispatch_plan": {},
            "dispatch_outcomes": {},
        }
        updated_items = []
        event = {
            "headers": {"x-coordination-callback-token": "cb-token"},
            "body": json.dumps(
                {
                    "provider": "openai_codex",
                    "state": "succeeded",
                    "execution_id": "exe-cb-1",
                    "details": {
                        "provider_session_id": "psn-cb-1",
                        "thread_id": "thread-cb-1",
                        "turn_id": "turn-cb-1",
                        "turn_status": "completed",
                        "model": "gpt-5-codex",
                    },
                }
            ),
        }

        with patch.object(coordination_lambda, "_get_request", return_value=request), \
             patch.object(coordination_lambda, "_finalize_tracker_from_request"), \
             patch.object(coordination_lambda, "_emit_callback_event"), \
             patch.object(coordination_lambda, "_update_request", side_effect=lambda item: updated_items.append(dict(item))):
            resp = coordination_lambda._handle_callback(event, "CRQ-244CB")

        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertGreaterEqual(len(updated_items), 1)
        final = updated_items[-1]
        self.assertIn("mcp", final)
        self.assertIn("last_callback", final["mcp"])
        self.assertEqual(final["mcp"]["last_callback"]["capability"], "coordination.request.callback")
        self.assertIn("governance_hash", final["mcp"]["last_callback"])
        ps = final.get("provider_session") or {}
        self.assertEqual(ps.get("provider_session_id"), "psn-cb-1")
        self.assertEqual(ps.get("thread_id"), "thread-cb-1")
        self.assertEqual(ps.get("turn_id"), "turn-cb-1")
        self.assertEqual(ps.get("execution_id"), "exe-cb-1")
        self.assertEqual(ps.get("turn_status"), "completed")


class FeedSubscriptionGuardTests(unittest.TestCase):
    def test_feed_subscriptions_enabled_caches_missing_table(self):
        original = coordination_lambda._feed_subscriptions_table_available
        coordination_lambda._feed_subscriptions_table_available = None

        class _FakeDdb:
            def __init__(self):
                self.describe_calls = 0

            def describe_table(self, **_kwargs):
                self.describe_calls += 1
                raise coordination_lambda.ClientError(
                    {"Error": {"Code": "ResourceNotFoundException", "Message": "missing"}},
                    "DescribeTable",
                )

        fake_ddb = _FakeDdb()
        try:
            with patch.object(coordination_lambda, "_get_ddb", return_value=fake_ddb):
                self.assertFalse(coordination_lambda._feed_subscriptions_enabled())
                self.assertFalse(coordination_lambda._feed_subscriptions_enabled())
            self.assertEqual(fake_ddb.describe_calls, 1)
        finally:
            coordination_lambda._feed_subscriptions_table_available = original

    def test_cancel_linked_subscriptions_skips_when_feed_table_unavailable(self):
        class _FakeDdb:
            def scan(self, **_kwargs):
                raise AssertionError("scan should not be called when feed table is unavailable")

        with patch.object(coordination_lambda, "_feed_subscriptions_enabled", return_value=False), \
             patch.object(coordination_lambda, "_get_ddb", return_value=_FakeDdb()):
            cancelled = coordination_lambda._cancel_coordination_linked_subscriptions(
                "CRQ-TEST",
                terminal_state="failed",
            )
        self.assertEqual(cancelled, 0)

    def test_publish_feed_push_updates_skips_when_feed_table_unavailable(self):
        class _FakeDdb:
            def scan(self, **_kwargs):
                raise AssertionError("scan should not be called when feed table is unavailable")

        with patch.object(coordination_lambda, "_feed_subscriptions_enabled", return_value=False), \
             patch.object(coordination_lambda, "_get_ddb", return_value=_FakeDdb()):
            coordination_lambda._publish_feed_push_updates(
                project_id="devops",
                coordination_request_id="CRQ-TEST",
                state="failed",
                summary="no-op",
                item_ids=["DVP-TSK-1"],
            )

    def test_feed_subscriptions_enabled_handles_access_denied(self):
        original = coordination_lambda._feed_subscriptions_table_available
        coordination_lambda._feed_subscriptions_table_available = None

        class _FakeDdb:
            def __init__(self):
                self.describe_calls = 0

            def describe_table(self, **_kwargs):
                self.describe_calls += 1
                raise coordination_lambda.ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    "DescribeTable",
                )

        fake_ddb = _FakeDdb()
        try:
            with patch.object(coordination_lambda, "_get_ddb", return_value=fake_ddb):
                self.assertFalse(coordination_lambda._feed_subscriptions_enabled())
                self.assertFalse(coordination_lambda._feed_subscriptions_enabled())
            self.assertEqual(fake_ddb.describe_calls, 1)
        finally:
            coordination_lambda._feed_subscriptions_table_available = original


class AnthropicEnhancementsTests(unittest.TestCase):
    """Tests for DVP-TSK-357/358/359/360/361/362/363 Anthropic API enhancements."""

    # --- DVP-TSK-362: API version upgrade ---
    def test_api_version_is_2025(self):
        self.assertEqual(coordination_lambda.ANTHROPIC_API_VERSION, "2023-06-01")

    # --- DVP-TSK-358: Model routing ---
    def test_resolve_claude_model_explicit_override(self):
        result = coordination_lambda._resolve_claude_model({"model": "claude-opus-4-6"})
        self.assertEqual(result, "claude-opus-4-6")

    def test_resolve_claude_model_simple_routes_to_haiku(self):
        result = coordination_lambda._resolve_claude_model({"task_complexity": "simple"})
        self.assertEqual(result, "claude-haiku-4-5-20251001")

    def test_resolve_claude_model_standard_routes_to_sonnet(self):
        result = coordination_lambda._resolve_claude_model({"task_complexity": "standard"})
        self.assertEqual(result, "claude-sonnet-4-6")

    def test_resolve_claude_model_complex_routes_to_opus(self):
        result = coordination_lambda._resolve_claude_model({"task_complexity": "complex"})
        self.assertEqual(result, "claude-opus-4-6")

    def test_resolve_claude_model_critical_routes_to_opus(self):
        result = coordination_lambda._resolve_claude_model({"task_complexity": "critical"})
        self.assertEqual(result, "claude-opus-4-6")

    def test_resolve_claude_model_default_is_standard(self):
        result = coordination_lambda._resolve_claude_model({})
        self.assertEqual(result, "claude-sonnet-4-6")

    def test_resolve_claude_model_explicit_overrides_complexity(self):
        result = coordination_lambda._resolve_claude_model({
            "model": "claude-haiku-4-5-20251001",
            "task_complexity": "critical",
        })
        self.assertEqual(result, "claude-haiku-4-5-20251001")

    # --- DVP-TSK-359: Extended thinking ---
    def test_build_thinking_param_disabled(self):
        result = coordination_lambda._build_claude_thinking_param({}, "claude-sonnet-4-6")
        self.assertIsNone(result)

    def test_build_thinking_param_false(self):
        result = coordination_lambda._build_claude_thinking_param({"thinking": False}, "claude-sonnet-4-6")
        self.assertIsNone(result)

    def test_build_thinking_param_true_non_adaptive(self):
        result = coordination_lambda._build_claude_thinking_param({"thinking": True}, "claude-sonnet-4-6")
        self.assertEqual(result["type"], "enabled")
        self.assertEqual(result["budget_tokens"], coordination_lambda.CLAUDE_THINKING_BUDGET_DEFAULT)

    def test_build_thinking_param_opus_adaptive(self):
        result = coordination_lambda._build_claude_thinking_param({"thinking": True}, "claude-opus-4-6")
        self.assertEqual(result["type"], "adaptive")
        self.assertNotIn("budget_tokens", result)

    def test_build_thinking_param_custom_budget(self):
        result = coordination_lambda._build_claude_thinking_param(
            {"thinking": {"budget_tokens": 4096}}, "claude-sonnet-4-6"
        )
        self.assertEqual(result["budget_tokens"], 4096)

    def test_build_thinking_param_clamps_budget_min(self):
        result = coordination_lambda._build_claude_thinking_param(
            {"thinking": {"budget_tokens": 100}}, "claude-sonnet-4-6"
        )
        self.assertEqual(result["budget_tokens"], coordination_lambda.CLAUDE_THINKING_BUDGET_MIN)

    def test_build_thinking_param_clamps_budget_max(self):
        result = coordination_lambda._build_claude_thinking_param(
            {"thinking": {"budget_tokens": 999999}}, "claude-sonnet-4-6"
        )
        self.assertEqual(result["budget_tokens"], coordination_lambda.CLAUDE_THINKING_BUDGET_MAX)

    # --- DVP-TSK-363: Cost attribution ---
    def test_calculate_cost_sonnet(self):
        usage = {"input_tokens": 1000, "output_tokens": 500}
        cost = coordination_lambda._calculate_claude_cost(usage, "claude-sonnet-4-6")
        self.assertAlmostEqual(cost["input_cost_usd"], 0.003, places=6)
        self.assertAlmostEqual(cost["output_cost_usd"], 0.0075, places=6)
        self.assertGreater(cost["total_cost_usd"], 0)

    def test_calculate_cost_with_cache(self):
        usage = {
            "input_tokens": 200,
            "output_tokens": 100,
            "cache_creation_input_tokens": 5000,
            "cache_read_input_tokens": 10000,
        }
        cost = coordination_lambda._calculate_claude_cost(usage, "claude-sonnet-4-6")
        self.assertGreater(cost["cache_write_cost_usd"], 0)
        self.assertGreater(cost["cache_read_cost_usd"], 0)
        self.assertGreater(cost["cache_hit_ratio"], 0.5)

    def test_calculate_cost_unknown_model_uses_default(self):
        usage = {"input_tokens": 1000, "output_tokens": 500}
        cost = coordination_lambda._calculate_claude_cost(usage, "unknown-model-99")
        self.assertGreater(cost["total_cost_usd"], 0)

    # --- DVP-TSK-357: System prompt extraction ---
    def test_extract_text_response_with_thinking_blocks(self):
        payload = {
            "content": [
                {"type": "thinking", "thinking": "Let me think about this..."},
                {"type": "text", "text": "Here is my answer"},
            ]
        }
        result = coordination_lambda._extract_claude_text_response(payload)
        self.assertEqual(result, "Here is my answer")

    def test_extract_thinking_response(self):
        payload = {
            "content": [
                {"type": "thinking", "thinking": "Step 1: analyze\nStep 2: conclude"},
                {"type": "text", "text": "Final answer"},
            ]
        }
        result = coordination_lambda._extract_claude_thinking_response(payload)
        self.assertIn("Step 1: analyze", result)

    def test_extract_thinking_response_none_when_no_thinking(self):
        payload = {"content": [{"type": "text", "text": "No thinking"}]}
        result = coordination_lambda._extract_claude_thinking_response(payload)
        self.assertEqual(result, "")

    # --- DVP-TSK-360: SSE stream parsing ---
    def test_parse_sse_stream_text_response(self):
        events = [
            b'event: message_start\n',
            b'data: {"type":"message_start","message":{"id":"msg_123","model":"claude-sonnet-4-6","usage":{"input_tokens":10}}}\n',
            b'\n',
            b'event: content_block_start\n',
            b'data: {"type":"content_block_start","content_block":{"type":"text","text":""}}\n',
            b'\n',
            b'event: content_block_delta\n',
            b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}\n',
            b'\n',
            b'event: content_block_delta\n',
            b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":" world"}}\n',
            b'\n',
            b'event: content_block_stop\n',
            b'data: {"type":"content_block_stop"}\n',
            b'\n',
            b'event: message_delta\n',
            b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}\n',
            b'\n',
            b'event: message_stop\n',
            b'data: {"type":"message_stop"}\n',
        ]
        result = coordination_lambda._parse_sse_stream(iter(events))
        self.assertEqual(len(result["content"]), 1)
        self.assertEqual(result["content"][0]["text"], "Hello world")
        self.assertEqual(result["stop_reason"], "end_turn")

    def test_parse_sse_stream_with_thinking(self):
        events = [
            b'event: message_start\n',
            b'data: {"type":"message_start","message":{"id":"msg_456","model":"claude-opus-4-6","usage":{"input_tokens":20}}}\n',
            b'\n',
            b'event: content_block_start\n',
            b'data: {"type":"content_block_start","content_block":{"type":"thinking","thinking":""}}\n',
            b'\n',
            b'event: content_block_delta\n',
            b'data: {"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"Analyzing..."}}\n',
            b'\n',
            b'event: content_block_stop\n',
            b'data: {"type":"content_block_stop"}\n',
            b'\n',
            b'event: content_block_start\n',
            b'data: {"type":"content_block_start","content_block":{"type":"text","text":""}}\n',
            b'\n',
            b'event: content_block_delta\n',
            b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Result"}}\n',
            b'\n',
            b'event: content_block_stop\n',
            b'data: {"type":"content_block_stop"}\n',
            b'\n',
            b'event: message_delta\n',
            b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":10}}\n',
            b'\n',
            b'event: message_stop\n',
            b'data: {"type":"message_stop"}\n',
        ]
        result = coordination_lambda._parse_sse_stream(iter(events))
        self.assertEqual(len(result["content"]), 2)
        self.assertEqual(result["content"][0]["type"], "thinking")
        self.assertEqual(result["content"][0]["thinking"], "Analyzing...")
        self.assertEqual(result["content"][1]["type"], "text")
        self.assertEqual(result["content"][1]["text"], "Result")

    # --- Validate provider_session new fields ---
    def test_validate_provider_session_accepts_system_prompt(self):
        result = coordination_lambda._validate_provider_session({
            "system_prompt": "You are a helpful agent.",
        })
        self.assertEqual(result["system_prompt"], "You are a helpful agent.")

    def test_validate_provider_session_accepts_task_complexity(self):
        result = coordination_lambda._validate_provider_session({
            "task_complexity": "complex",
        })
        self.assertEqual(result["task_complexity"], "complex")

    def test_validate_provider_session_rejects_invalid_task_complexity(self):
        with self.assertRaises(ValueError):
            coordination_lambda._validate_provider_session({
                "task_complexity": "mega",
            })

    def test_validate_provider_session_accepts_thinking_bool(self):
        result = coordination_lambda._validate_provider_session({
            "thinking": True,
        })
        self.assertTrue(result["thinking"])

    def test_validate_provider_session_accepts_thinking_dict(self):
        result = coordination_lambda._validate_provider_session({
            "thinking": {"budget_tokens": 4096},
        })
        self.assertEqual(result["thinking"]["budget_tokens"], 4096)

    def test_validate_provider_session_rejects_thinking_invalid_budget(self):
        with self.assertRaises(ValueError):
            coordination_lambda._validate_provider_session({
                "thinking": {"budget_tokens": 100},
            })

    def test_validate_provider_session_accepts_stream(self):
        result = coordination_lambda._validate_provider_session({
            "stream": True,
        })
        self.assertTrue(result["stream"])

    def test_validate_provider_session_rejects_stream_non_bool(self):
        with self.assertRaises(ValueError):
            coordination_lambda._validate_provider_session({
                "stream": "yes",
            })

    # --- Full dispatch integration with new features ---
    @patch.object(coordination_lambda, "_count_claude_tokens", return_value=500)
    @patch.object(coordination_lambda, "_fetch_provider_api_key", return_value="sk-ant-test")
    @patch.object(coordination_lambda.urllib.request, "urlopen")
    def test_dispatch_with_system_prompt_and_caching(self, mock_urlopen, _mock_key, _mock_count):
        class _FakeResponse:
            status = 200
            headers = {"request-id": "req-cache-test"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return json.dumps({
                    "id": "msg_cache_123",
                    "model": "claude-sonnet-4-6",
                    "stop_reason": "end_turn",
                    "usage": {
                        "input_tokens": 50,
                        "output_tokens": 30,
                        "cache_creation_input_tokens": 200,
                        "cache_read_input_tokens": 0,
                    },
                    "content": [{"type": "text", "text": "cached response"}],
                }).encode("utf-8")

        mock_urlopen.return_value = _FakeResponse()
        result = coordination_lambda._dispatch_claude_api(
            request={
                "request_id": "CRQ-CACHE",
                "project_id": "devops",
                "provider_session": {
                    "system_prompt": "You are a coordination agent.",
                },
            },
            prompt="Test caching",
            dispatch_id="DSP-CACHE",
        )

        self.assertEqual(result["status"], "succeeded")
        pr = result["provider_result"]
        self.assertTrue(pr["features_used"]["system_prompt"])
        self.assertTrue(pr["features_used"]["prompt_caching"])
        self.assertEqual(pr["features_used"]["cache_ttl"], "1h")
        self.assertIn("cost_attribution", pr)
        self.assertGreater(pr["cost_attribution"]["cache_write_cost_usd"], 0)

        # Verify system prompt with cache_control in request body
        called_req = mock_urlopen.call_args.args[0]
        body = json.loads(called_req.data.decode("utf-8"))
        self.assertIn("system", body)
        self.assertEqual(body["system"][0]["cache_control"]["ttl"], "1h")

    @patch.object(coordination_lambda, "_count_claude_tokens", return_value=500)
    @patch.object(coordination_lambda, "_fetch_provider_api_key", return_value="sk-ant-test")
    @patch.object(coordination_lambda.urllib.request, "urlopen")
    def test_dispatch_with_model_routing_simple(self, mock_urlopen, _mock_key, _mock_count):
        class _FakeResponse:
            status = 200
            headers = {"request-id": "req-route-test"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return json.dumps({
                    "id": "msg_route_123",
                    "model": "claude-haiku-4-5-20251001",
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                    "content": [{"type": "text", "text": "routed to haiku"}],
                }).encode("utf-8")

        mock_urlopen.return_value = _FakeResponse()
        result = coordination_lambda._dispatch_claude_api(
            request={
                "request_id": "CRQ-ROUTE",
                "project_id": "devops",
                "provider_session": {"task_complexity": "simple"},
            },
            prompt="Simple task",
            dispatch_id="DSP-ROUTE",
        )

        pr = result["provider_result"]
        self.assertEqual(pr["model_routing"]["task_complexity"], "simple")
        self.assertEqual(pr["model_routing"]["resolved_model"], "claude-haiku-4-5-20251001")
        self.assertEqual(pr["model_routing"]["reason"], "task_complexity=simple")

        called_req = mock_urlopen.call_args.args[0]
        body = json.loads(called_req.data.decode("utf-8"))
        self.assertEqual(body["model"], "claude-haiku-4-5-20251001")

    @patch.object(coordination_lambda, "_count_claude_tokens", return_value=500)
    @patch.object(coordination_lambda, "_fetch_provider_api_key", return_value="sk-ant-test")
    @patch.object(coordination_lambda.urllib.request, "urlopen")
    def test_dispatch_with_thinking_enabled(self, mock_urlopen, _mock_key, _mock_count):
        class _FakeResponse:
            status = 200
            headers = {"request-id": "req-think-test"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return json.dumps({
                    "id": "msg_think_123",
                    "model": "claude-sonnet-4-6",
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 30, "output_tokens": 150},
                    "content": [
                        {"type": "thinking", "thinking": "Analyzing the problem step by step..."},
                        {"type": "text", "text": "Here is the answer"},
                    ],
                }).encode("utf-8")

        mock_urlopen.return_value = _FakeResponse()
        result = coordination_lambda._dispatch_claude_api(
            request={
                "request_id": "CRQ-THINK",
                "project_id": "devops",
                "provider_session": {"thinking": True},
            },
            prompt="Complex analysis",
            dispatch_id="DSP-THINK",
        )

        pr = result["provider_result"]
        self.assertTrue(pr["features_used"]["extended_thinking"])
        self.assertEqual(pr["summary"], "Here is the answer")
        self.assertIn("Analyzing the problem", pr["thinking_summary"])

        called_req = mock_urlopen.call_args.args[0]
        body = json.loads(called_req.data.decode("utf-8"))
        self.assertIn("thinking", body)
        self.assertEqual(body["thinking"]["type"], "enabled")

    @patch.object(coordination_lambda, "_count_claude_tokens", return_value=250000)
    @patch.object(coordination_lambda, "_fetch_provider_api_key", return_value="sk-ant-test")
    def test_dispatch_rejects_context_overflow(self, _mock_key, _mock_count):
        with self.assertRaises(RuntimeError) as ctx:
            coordination_lambda._dispatch_claude_api(
                request={
                    "request_id": "CRQ-OVERFLOW",
                    "project_id": "devops",
                    "provider_session": {},
                },
                prompt="Very long prompt",
                dispatch_id="DSP-OVERFLOW",
            )
        self.assertIn("exceed model context window", str(ctx.exception))

    # --- Capabilities endpoint enhancements ---
    @patch.object(coordination_lambda, "_provider_secret_readiness")
    def test_capabilities_include_anthropic_features(self, mock_secrets):
        mock_secrets.return_value = {
            "openai_codex": {"secret_status": "active", "secret_ref_configured": True, "secret_ref": "", "secret_arn": "", "rotation_policy": "", "last_rotated": "", "next_rotation_due": "", "days_until_rotation_due": 0, "rotation_warning": False},
            "claude_agent_sdk": {"secret_status": "active", "secret_ref_configured": True, "secret_ref": "", "secret_arn": "", "rotation_policy": "", "last_rotated": "", "next_rotation_due": "", "days_until_rotation_due": 0, "rotation_warning": False},
        }
        resp = coordination_lambda._handle_capabilities()
        body = json.loads(resp["body"])
        claude = body["capabilities"]["providers"]["claude_agent_sdk"]

        self.assertEqual(claude["api_version"], "2023-06-01")
        self.assertIn("model_routing", claude)
        self.assertIn("simple", claude["model_routing"]["task_complexities"])
        self.assertIn("features", claude)
        self.assertTrue(claude["features"]["system_prompt"])
        self.assertTrue(claude["features"]["prompt_caching"]["supported"])
        self.assertTrue(claude["features"]["extended_thinking"]["supported"])
        self.assertTrue(claude["features"]["streaming"])
        self.assertTrue(claude["features"]["token_counting"])
        self.assertTrue(claude["features"]["cost_attribution"])


if __name__ == "__main__":
    unittest.main()
