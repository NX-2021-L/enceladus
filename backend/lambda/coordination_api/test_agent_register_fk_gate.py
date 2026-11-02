"""ENC-TSK-R81-0A / ENC-FTR-146 AC-4/AC-5: fail-closed agent.register / agent.claim FK gate
over the agent-type directory, plus closed surface/runtime enums over the W0.6 normal form."""
import json
import os
import sys
import unittest
from unittest import mock

import boto3
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config  # noqa: E402
import agent_id_alloc as alloc  # noqa: E402

# Fixture: the 26 live ACTIVE agent-type rows (prod agent-types scan 2026-11-02).
LIVE_AGENT_TYPES = [
    ("ENC-AGT-001", "claude.ai-webui", "claude-sonnet-4-6"),
    ("ENC-AGT-002", "Claude Code CLI", "claude-opus-4-8"),
    ("ENC-AGT-003", "cursor-cloud-agent", "claude-opus-4-8"),
    ("ENC-AGT-004", "claude.ai-webui", "claude-opus-4-8"),
    ("ENC-AGT-005", "claude_code_cli", "claude-sonnet-5"),
    ("ENC-AGT-006", "claude_code_cli", "claude-fable-5"),
    ("ENC-AGT-007", "chatgpt-native-app", "GPT-5.5 Thinking"),
    ("ENC-AGT-008", "codex-terminal", "gpt-5-codex"),
    ("ENC-AGT-009", "claude.ai-webui", "claude-fable-5"),
    ("ENC-AGT-00A", "cowork-desktop", "claude-sonnet-5"),
    ("ENC-AGT-00B", "test", "test"),
    ("ENC-AGT-00C", "eventbridge-scheduler", "lambda-rhythm"),
    ("ENC-AGT-00D", "claude.ai-webui", "claude-sonnet-5"),
    ("ENC-AGT-00E", "devin-webui", "devin"),
    ("ENC-AGT-00F", "claude_code_cli", "claude-opus-5"),
    ("ENC-AGT-00G", "claude.ai-webui", "claude-opus-5"),
    ("ENC-AGT-00H", "claude_code_cli", "claude-fable-5-1"),
    ("ENC-AGT-00I", "claude.ai-webui", "claude-fable-5-1"),
    ("ENC-AGT-00J", "cowork-desktop", "claude-opus-5-5"),
    ("ENC-AGT-00K", "claude_code_cli", "claude-opus-5-5"),
    ("ENC-AGT-00L", "claude.ai-webui", "claude-opus-5-5"),
    ("ENC-AGT-00M", "claude_code_cli", "claude-sonnet-5-5"),
    ("ENC-AGT-00N", "enceladus-recipe-runner", "recipe-runner-v1"),
    ("ENC-AGT-00O", "cowork-desktop", "claude-fable-5-1"),
    ("ENC-AGT-00P", "claude_code_desktop", "claude-opus-5-5"),
    ("ENC-AGT-00Q", "claude_code_desktop", "claude-opus-5"),
]

# Runtime spellings seen on live session rows since 2026-10-01 -> canonical family.
LIVE_RUNTIMES = {
    "claude_code_desktop_subagent": "claude_code_desktop_subagent",
    "claude_code_desktop": "claude_code_desktop",
    "claude-code-desktop": "claude_code_desktop",
    "claude_code_cli": "claude_code_cli",
    "claude-code-cli": "claude_code_cli",
    "claude-code": "claude_code_cli",
    "CLI": "claude_code_cli",
    "Claude Code CLI": "claude_code_cli",
    "claude.ai-webui": "claude_ai_webui",
    "claude_ai_web": "claude_ai_webui",
    "cowork-desktop": "cowork_desktop",
    "recipe_runner": "recipe_runner",
    "cursor-cloud-agent": "cursor_cloud_agent",
    "codex-terminal": "codex_terminal",
    "claude.ai-webui coordination-lead glamcocks totem-genesis": "claude_ai_webui",
    "claude-code-remote (cloud handoff PLN-014 W4)": "claude_code_remote",
    "claude-code-cli-subagent/sonnet-5 dispatch W1 ENC-TSK-M39": "claude_code_cli_subagent",
    "{'surface': 'claude_code_desktop', 'model': 'claude-fable-5-1', 'project_id': 'glamcocks'}": "claude_code_desktop",
    "{'model': 'claude-fable-5-1', 'skill': 'enceladus-agent-webui-alpha', 'surface': 'claude.ai-webui'}": "claude_ai_webui",
}


class RuntimeEnumTest(unittest.TestCase):
    def test_live_runtimes_resolve(self):
        for raw, want in LIVE_RUNTIMES.items():
            self.assertEqual(alloc.resolve_runtime(raw), want, raw)
            self.assertIn(want, alloc.ALLOWED_RUNTIMES)

    def test_mapping_runtime_uses_surface(self):
        self.assertEqual(alloc.resolve_runtime({"surface": "claude_code_desktop"}), "claude_code_desktop")

    def test_unknown_runtime_rejected_with_allowed_set(self):
        for raw in ("", "node", "bogus-runtime", "claude-opus-4-8", '{"host": "x", "cwd": "/y"}'):
            with self.assertRaises(alloc.AgentFieldRejected) as ctx:
                alloc.resolve_runtime(raw)
            self.assertEqual(ctx.exception.field, "runtime")
            self.assertEqual(ctx.exception.allowed, sorted(alloc.ALLOWED_RUNTIMES))

    def test_canonical_runtime_is_idempotent(self):
        for r in alloc.ALLOWED_RUNTIMES:
            self.assertEqual(alloc.resolve_runtime(r), r)


class SurfaceEnumTest(unittest.TestCase):
    def test_every_live_surface_allowed(self):
        for _aid, surface, _model in LIVE_AGENT_TYPES:
            self.assertIn(alloc.validate_surface(surface), alloc.ALLOWED_SURFACES, surface)

    def test_unknown_surface_rejected(self):
        with self.assertRaises(alloc.AgentFieldRejected) as ctx:
            alloc.validate_surface("my-homegrown-surface")
        self.assertEqual(ctx.exception.field, "surface")
        self.assertIn("claude_code_cli", ctx.exception.allowed)


@mock_aws
class FkGateTest(unittest.TestCase):
    def setUp(self):
        self.ddb = boto3.client("dynamodb", region_name="us-west-2")
        self.ddb.create_table(
            TableName=config.AGENT_TYPES_TABLE,
            KeySchema=[{"AttributeName": "agent_type_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "agent_type_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        for aid, surface, model in LIVE_AGENT_TYPES:
            self.ddb.put_item(TableName=config.AGENT_TYPES_TABLE, Item={
                "agent_type_id": {"S": aid}, "surface": {"S": surface},
                "model": {"S": model}, "status": {"S": "active"}})
        self.ddb.put_item(TableName=config.AGENT_TYPES_TABLE, Item={
            "agent_type_id": {"S": "ENC-AGT-0ZZ"}, "status": {"S": "deprecated"}})
        self.ddb.put_item(TableName=config.AGENT_TYPES_TABLE, Item={
            "agent_type_id": {"S": "counter#ENC-AGT"}, "counter": {"N": "40"}})
        p = mock.patch.object(alloc, "_get_ddb", return_value=self.ddb)
        p.start()
        self.addCleanup(p.stop)

    def test_all_live_ids_pass(self):
        for aid, _s, _m in LIVE_AGENT_TYPES:
            self.assertEqual(alloc.require_active_agent_type(aid)["agent_type_id"], aid)

    def test_rejections(self):
        cases = {
            "claude-code": "not_an_agent_type_id",
            "coord-lead": "not_an_agent_type_id",
            "enc-agt-00k": "not_an_agent_type_id",
            "counter#ENC-AGT": "not_an_agent_type_id",
            "": "not_an_agent_type_id",
            "ENC-AGT-ZZZ": "unknown",
            "ENC-AGT-0ZZ": "inactive",
        }
        for aid, reason in cases.items():
            with self.assertRaises(alloc.AgentFieldRejected) as ctx:
                alloc.require_active_agent_type(aid)
            self.assertEqual(ctx.exception.reason, reason, aid)
            self.assertIn("agent.type.list", str(ctx.exception))


class HandlerGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import lambda_function as lf  # noqa: E402
        except Exception as exc:  # pragma: no cover - baseline collection errors
            raise unittest.SkipTest(f"lambda_function not importable here: {exc}")
        cls.lf = lf

    def setUp(self):
        self.rows = {aid: {"agent_type_id": aid, "surface": s, "model": m, "status": "active"}
                     for aid, s, m in LIVE_AGENT_TYPES}
        self.rows["ENC-AGT-0ZZ"] = {"agent_type_id": "ENC-AGT-0ZZ", "status": "deprecated"}
        p = mock.patch.object(self.lf._agent_id_alloc, "get_agent_type", side_effect=self.rows.get)
        p.start()
        self.addCleanup(p.stop)

    def _register(self, body):
        return self.lf._handle_agent_session_register({"body": json.dumps(body)}, {})

    def _assert_fk_problem(self, resp, aid):
        self.assertEqual(resp["statusCode"], 422)
        self.assertEqual(resp["headers"]["Content-Type"], "application/problem+json")
        body = json.loads(resp["body"])
        self.assertEqual(body["status"], 422)
        self.assertEqual(body["agent_type_id"], aid)
        self.assertIn(aid, body["detail"])
        self.assertEqual(body["see"]["action"], "agent.type.list")
        self.assertTrue(body["type"].endswith("/agent-type-not-active"))
        self.assertFalse(body["success"])

    def test_every_live_id_registers_with_subagent_runtime(self):
        with mock.patch.object(self.lf._agent_id_alloc, "mint_session_id",
                               side_effect=lambda **kw: {"session_id": "ENC-SES-T00", **kw}) as mint:
            for aid, _s, _m in LIVE_AGENT_TYPES:
                resp = self._register({"agent_type_id": aid, "runtime": "claude_code_desktop_subagent",
                                       "parent_session_id": "ENC-SES-0ON"})
                self.assertEqual(resp["statusCode"], 201, aid)
        self.assertEqual(mint.call_count, len(LIVE_AGENT_TYPES))
        self.assertEqual(mint.call_args.kwargs["runtime"], "claude_code_desktop_subagent")

    def test_register_persists_canonical_runtime(self):
        with mock.patch.object(self.lf._agent_id_alloc, "mint_session_id",
                               side_effect=lambda **kw: {"session_id": "ENC-SES-T00", **kw}) as mint:
            resp = self._register({"agent_type_id": "ENC-AGT-00L", "runtime": "claude.ai-webui coordination-lead"})
        self.assertEqual(resp["statusCode"], 201)
        self.assertEqual(mint.call_args.kwargs["runtime"], "claude_ai_webui")

    def test_bogus_and_free_text_ids_rejected_without_mint(self):
        with mock.patch.object(self.lf._agent_id_alloc, "mint_session_id") as mint:
            for aid in ("ENC-AGT-ZZZ", "ENC-AGT-0ZZ", "claude-code", "coord-lead"):
                for dry in (False, True):
                    body = {"agent_type_id": aid, "runtime": "claude_code_cli"}
                    if dry:
                        body["dry_run"] = True
                    self._assert_fk_problem(self._register(body), aid)
        mint.assert_not_called()

    def test_unknown_runtime_rejected_with_allowed_set(self):
        with mock.patch.object(self.lf._agent_id_alloc, "mint_session_id") as mint:
            resp = self._register({"agent_type_id": "ENC-AGT-00K", "runtime": "bogus-runtime"})
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["field"], "runtime")
        self.assertIn("claude_code_desktop_subagent", body["allowed"])
        mint.assert_not_called()

    def test_dry_run_valid_does_not_mint(self):
        with mock.patch.object(self.lf._agent_id_alloc, "mint_session_id") as mint:
            resp = self._register({"agent_type_id": "ENC-AGT-00K", "runtime": "claude_code_desktop_subagent",
                                   "dry_run": True})
        self.assertEqual(resp["statusCode"], 200)
        self.assertTrue(json.loads(resp["body"])["dry_run"])
        mint.assert_not_called()

    def _claim(self, body):
        return self.lf._handle_agent_session_claim({"body": json.dumps(body)}, {})

    def test_claim_pre_gate_session_without_expected_id_still_works(self):
        item = {"session_id": "ENC-SES-OLD", "agent_type_id": "claude-code", "status": "claimed"}
        with mock.patch.object(self.lf._agent_id_alloc, "claim_session", return_value=item), \
                mock.patch.object(self.lf._agent_id_alloc, "mint_sci",
                                  return_value={"token_id": "SCI-x", "issued_at": "t"}):
            resp = self._claim({"session_id": "ENC-SES-OLD"})
        self.assertEqual(resp["statusCode"], 200)

    def test_claim_rejects_bogus_expected_id(self):
        with mock.patch.object(self.lf._agent_id_alloc, "claim_session") as claim:
            resp = self._claim({"session_id": "ENC-SES-001", "expected_agent_type_id": "ENC-AGT-ZZZ"})
        self._assert_fk_problem(resp, "ENC-AGT-ZZZ")
        claim.assert_not_called()

    def test_type_register_rejects_unknown_surface(self):
        resp = self.lf._handle_agent_type_register(
            {"body": json.dumps({"surface": "homegrown", "model": "m", "cost_tier": "standard"})}, {})
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(json.loads(resp["body"])["field"], "surface")


if __name__ == "__main__":
    unittest.main()
