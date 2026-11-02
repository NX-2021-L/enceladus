"""ENC-TSK-R80-0F / ENC-FTR-146 AC-1..AC-3: agent surface/model/runtime normal form,
variant resolution in find_agent_type / agent.type.register, and full-table pagination."""
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

canon = alloc.canonicalize_agent_type_fields


class NormalFormTest(unittest.TestCase):
    def test_live_surface_spellings_are_stable(self):
        # Spellings already stored on live rows are their own canonical form.
        for s in (
            "claude_code_cli", "claude_code_desktop", "claude.ai-webui", "cowork-desktop",
            "codex-terminal", "cursor-cloud-agent", "devin-webui", "chatgpt-native-app",
            "eventbridge-scheduler", "enceladus-recipe-runner", "test",
        ):
            self.assertEqual(canon(s, "m")["surface"], s, s)

    def test_surface_variants_collapse(self):
        for v in ("Claude Code CLI", " claude-code-cli ", "CLAUDE_CODE_CLI", "claude-code", "claude code", "CLI", "cli"):
            self.assertEqual(canon(v, "m")["surface"], "claude_code_cli", v)
        for v in ("Claude.ai WebUI", "claude_ai_webui", "CLAUDE.AI-WEBUI"):
            self.assertEqual(canon(v, "m")["surface"], "claude.ai-webui", v)
        self.assertEqual(canon("Cowork Desktop", "m")["surface"], "cowork-desktop")

    def test_unknown_surface_becomes_snake_key(self):
        self.assertEqual(canon("My New  Surface!", "m")["surface"], "my_new_surface")

    def test_model_normal_form(self):
        self.assertEqual(canon("s", "claude-opus-5-5")["model"], "claude-opus-5-5")
        self.assertEqual(canon("s", "Claude Opus 5.5")["model"], "claude-opus-5-5")
        self.assertEqual(canon("s", "claude_sonnet_5")["model"], "claude-sonnet-5")
        self.assertEqual(canon("s", "GPT-5.5 Thinking")["model"], "gpt-5.5-thinking")
        self.assertEqual(canon("s", "gpt-5-codex")["model"], "gpt-5-codex")

    def test_runtime_normal_form(self):
        for v in ("claude_code_cli", "claude-code-cli", "CLI", "cli", "claude-code", "Claude Code"):
            self.assertEqual(canon("s", "m", v)["runtime"], "claude_code_cli", v)
        self.assertEqual(canon("s", "m", "claude_code_desktop_subagent")["runtime"], "claude_code_desktop_subagent")
        self.assertEqual(canon("s", "m")["runtime"], "")

    def test_empty_and_none(self):
        self.assertEqual(canon(None, "  "), {"surface": "", "model": "", "runtime": ""})

    def test_idempotent(self):
        for s, m, r in (("Claude Code CLI", "Claude Opus 4.8", "CLI"), ("My New Surface", "GPT-5.5 Thinking", "x y")):
            once = canon(s, m, r)
            self.assertEqual(canon(once["surface"], once["model"], once["runtime"]), once)


@mock_aws
class FindAgentTypeVariantTest(unittest.TestCase):
    def setUp(self):
        self.ddb = boto3.client("dynamodb", region_name="us-west-2")
        self.ddb.create_table(
            TableName=config.AGENT_TYPES_TABLE,
            AttributeDefinitions=[{"AttributeName": "agent_type_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "agent_type_id", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
        )
        p = mock.patch.object(alloc, "_get_ddb", return_value=self.ddb)
        p.start()
        self.addCleanup(p.stop)

    def _mint(self, surface, model):
        return alloc.mint_agent_type_id(surface=surface, model=model, cost_tier="premium")

    def test_variant_resolves_to_existing_legacy_row(self):
        # Mirrors live ENC-AGT-002: surface stored as "Claude Code CLI".
        legacy = self._mint("Claude Code CLI", "claude-opus-4-8")
        found = alloc.find_agent_type(surface="claude_code_cli", model="claude-opus-4-8")
        self.assertEqual(found["agent_type_id"], legacy["agent_type_id"])
        found2 = alloc.find_agent_type(surface=" claude-code-cli", model="Claude Opus 4.8")
        self.assertEqual(found2["agent_type_id"], legacy["agent_type_id"])

    def test_prefers_canonical_spelling_then_lowest_id(self):
        a = self._mint("Claude Code CLI", "claude-opus-5-5")
        b = self._mint("claude_code_cli", "claude-opus-5-5")
        found = alloc.find_agent_type(surface="CLAUDE-CODE-CLI", model="claude-opus-5-5")
        self.assertEqual(found["agent_type_id"], b["agent_type_id"])
        self.assertNotEqual(a["agent_type_id"], b["agent_type_id"])

    def test_distinct_model_is_not_a_match(self):
        self._mint("claude_code_cli", "claude-opus-5-5")
        self.assertIsNone(alloc.find_agent_type(surface="claude_code_cli", model="claude-opus-5"))

    def test_counter_rows_excluded(self):
        self._mint("s", "m")  # creates counter#ENC-AGT row
        self.assertIsNone(alloc.find_agent_type(surface="counter#ENC-AGT", model=""))


class FindAgentTypePaginationTest(unittest.TestCase):
    """The match lives on the LAST page; a first-page-only scan would miss it."""

    def test_reads_all_pages(self):
        def item(i, surface):
            return {
                "agent_type_id": {"S": f"ENC-AGT-{i:03d}"},
                "surface": {"S": surface},
                "model": {"S": "claude-opus-5-5"},
                "status": {"S": "active"},
            }

        pages = [
            {"Items": [item(1, "codex-terminal")], "LastEvaluatedKey": {"agent_type_id": {"S": "ENC-AGT-001"}}},
            {"Items": [item(2, "devin-webui")], "LastEvaluatedKey": {"agent_type_id": {"S": "ENC-AGT-002"}}},
            {"Items": [item(3, "Claude Code CLI")]},
        ]
        fake = mock.Mock()
        fake.scan.side_effect = pages
        with mock.patch.object(alloc, "_get_ddb", return_value=fake):
            found = alloc.find_agent_type(surface="claude_code_cli", model="claude-opus-5-5")
        self.assertEqual(found["agent_type_id"], "ENC-AGT-003")
        self.assertEqual(fake.scan.call_count, 3)
        # Continuation key is threaded through.
        self.assertEqual(fake.scan.call_args_list[1].kwargs["ExclusiveStartKey"], {"agent_type_id": {"S": "ENC-AGT-001"}})
        self.assertEqual(fake.scan.call_args_list[2].kwargs["ExclusiveStartKey"], {"agent_type_id": {"S": "ENC-AGT-002"}})


class RegisterHandlerVariantTest(unittest.TestCase):
    """agent.type.register resolves a spelling variant to the existing type, no new mint."""

    @classmethod
    def setUpClass(cls):
        try:
            import lambda_function as lf  # noqa: E402
        except Exception as exc:  # pragma: no cover - baseline collection errors
            raise unittest.SkipTest(f"lambda_function not importable here: {exc}")
        cls.lf = lf

    def _call(self, body):
        return self.lf._handle_agent_type_register({"body": json.dumps(body)}, {})

    def test_variant_returns_existing_without_minting(self):
        existing = {"agent_type_id": "ENC-AGT-002", "surface": "Claude Code CLI", "model": "claude-opus-4-8"}
        with mock.patch.object(self.lf._agent_id_alloc, "find_agent_type", return_value=existing) as fat, \
                mock.patch.object(self.lf._agent_id_alloc, "mint_agent_type_id") as mint:
            resp = self._call({"surface": "claude-code-cli", "model": "Claude Opus 4.8", "cost_tier": "premium", "runtime": "CLI"})
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertFalse(body["created"])
        self.assertEqual(body["agent_type"]["agent_type_id"], "ENC-AGT-002")
        self.assertEqual(body["normal_form"], {"surface": "claude_code_cli", "model": "claude-opus-4-8", "runtime": "claude_code_cli"})
        fat.assert_called_once_with(surface="claude_code_cli", model="claude-opus-4-8")
        mint.assert_not_called()

    def test_new_type_is_minted_with_canonical_values(self):
        minted = {"agent_type_id": "ENC-AGT-0R0"}
        with mock.patch.object(self.lf._agent_id_alloc, "find_agent_type", return_value=None), \
                mock.patch.object(self.lf._agent_id_alloc, "mint_agent_type_id", return_value=minted) as mint:
            resp = self._call({"surface": "Claude Code CLI", "model": "Claude-Opus-5.5", "cost_tier": "premium"})
        self.assertEqual(resp["statusCode"], 201)
        kw = mint.call_args.kwargs
        self.assertEqual((kw["surface"], kw["model"]), ("claude_code_cli", "claude-opus-5-5"))


if __name__ == "__main__":
    unittest.main()


def test_sns_anomaly_responder_surface_is_allowed():
    """ENC-TSK-R82-0A: the Lambda responder surface passes the closed surface enum."""
    from agent_id_alloc import canonicalize_surface, validate_surface
    assert canonicalize_surface("sns-anomaly-responder") == "sns-anomaly-responder"
    assert validate_surface("sns-anomaly-responder") == "sns-anomaly-responder"
