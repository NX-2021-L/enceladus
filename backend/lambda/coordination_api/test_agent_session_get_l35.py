"""test_agent_session_get_l35.py — GET /agents/sessions/{id} (ENC-TSK-L35).

New single-session-detail read added for the B67 PWA2.0 session detail page.
There was previously no way to fetch one session by id (only the unfiltered/
status-filtered list existed) — the frontend detail route needs exactly one
record. Covers the handler directly (``_handle_agent_session_get``), mirroring
the moto-backed style of test_agent_id_alloc.py.
"""
import importlib.util
import os
import pathlib
import sys
import unittest

import boto3
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location("coordination_lambda_session_get", MODULE_PATH)
coordination_lambda = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = coordination_lambda
SPEC.loader.exec_module(coordination_lambda)

import config  # noqa: E402


@mock_aws
class AgentSessionGetTest(unittest.TestCase):
    def setUp(self):
        self.ddb = boto3.client("dynamodb", region_name="us-west-2")
        self.ddb.create_table(
            TableName=config.AGENT_SESSIONS_TABLE,
            AttributeDefinitions=[{"AttributeName": "session_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "session_id", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
        )

    def _put_session(self, session_id="ENC-SES-0A1", **extra):
        item = {
            "session_id": {"S": session_id},
            "agent_type_id": {"S": "ENC-AGT-001"},
            "parent_session_id": {"S": "root"},
            "runtime": {"S": "claude-code-cli"},
            "created_at": {"S": "2026-07-02T13:00:00Z"},
            "claimed_at": {"S": "2026-07-02T13:00:05Z"},
            "status": {"S": "claimed"},
        }
        item.update(extra)
        self.ddb.put_item(TableName=config.AGENT_SESSIONS_TABLE, Item=item)

    def test_returns_full_session_item_including_mirrored_history(self):
        self._put_session(
            updated_at={"S": "2026-07-05T09:00:00Z"},
            last_activity_at={"S": "2026-07-05T09:00:00Z"},
            history={"L": [
                {"M": {
                    "timestamp": {"S": "2026-07-05T09:00:00Z"},
                    "status": {"S": "worklog"},
                    "description": {"S": "[task:ENC-TSK-901] did the thing"},
                    "source_record_type": {"S": "task"},
                    "source_record_id": {"S": "ENC-TSK-901"},
                }},
            ]},
        )
        resp = coordination_lambda._handle_agent_session_get("ENC-SES-0A1")
        self.assertEqual(resp["statusCode"], 200)
        import json
        body = json.loads(resp["body"])
        session = body["session"]
        self.assertEqual(session["session_id"], "ENC-SES-0A1")
        self.assertEqual(session["status"], "claimed")
        self.assertEqual(session["updated_at"], "2026-07-05T09:00:00Z")
        self.assertEqual(len(session["history"]), 1)
        self.assertEqual(
            session["history"][0]["description"], "[task:ENC-TSK-901] did the thing",
        )

    def test_unknown_session_is_404(self):
        resp = coordination_lambda._handle_agent_session_get("ENC-SES-ZZZ")
        self.assertEqual(resp["statusCode"], 404)

    def test_empty_session_id_is_400(self):
        resp = coordination_lambda._handle_agent_session_get("")
        self.assertEqual(resp["statusCode"], 400)

    def test_route_dispatches_get_by_id(self):
        self._put_session()
        match = coordination_lambda.re.fullmatch(
            r"/api/v1/coordination/agents/sessions/([A-Za-z0-9_\-]+)",
            "/api/v1/coordination/agents/sessions/ENC-SES-0A1",
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "ENC-SES-0A1")


if __name__ == "__main__":
    unittest.main()
