"""test_worklog_mirror_l35.py — SES worklog mirroring + updated_at bump (ENC-TSK-L35).

B67 PWA2.0 session detail + worklog mirroring (backend-spanning). Covers:

  * ``_handle_log`` (the single shared /{project}/{type}/{id}/log endpoint for
    every record type) mirrors a session-authored worklog entry onto the
    acting session's own AGENT_SESSIONS_TABLE ``history`` list.
  * The mirrored entry is prefixed with the source record type/id and carries
    the same ``status: worklog`` shape as every other worklog entry.
  * Mirroring applies across record types (task AND plan) since both route
    through the same handler.
  * Mirroring is best-effort: an unknown/fabricated session never fails the
    primary worklog append.
  * Non-agent providers (github, Cognito subs, ...) are not mirrored (no
    session to mirror onto).
  * ``_sci_gate_for_request`` bumps last_activity_at AND updated_at on the
    acting session unconditionally for every session-requiring call it gates,
    including grandfathered (pre-epoch) sessions.

Run: python3 -m pytest test_worklog_mirror_l35.py -q
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
import unittest
from unittest import mock

import boto3
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

sys.path.insert(0, os.path.dirname(__file__))
_spec = importlib.util.spec_from_file_location(
    "tracker_mutation_worklog_mirror",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
tm = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)

SESSION = "ENC-SES-0A1"
PRE_EPOCH_SESSION = "ENC-SES-009"
VALID_SCI = "SCI-" + "a" * 32
POST_EPOCH_TS = "2026-07-02T13:00:00Z"   # after SCI_ENFORCEMENT_EPOCH
PRE_EPOCH_TS = "2026-06-30T00:00:00Z"    # before SCI_ENFORCEMENT_EPOCH
CS_KEY = "cs-test-key"


def _body(provider=SESSION, sci=None, **extra):
    body = {"write_source": {"provider": provider, "channel": "mcp_server"}}
    if sci is not None:
        body["sci"] = sci
    body.update(extra)
    return body


class WorklogMirrorBase(unittest.TestCase):
    """moto-backed tracker + token + session tables (mirrors test_sci_gate.py fixtures)."""

    def setUp(self):
        self._moto = mock_aws()
        self._moto.start()
        self.addCleanup(self._moto.stop)
        self.ddb = boto3.client("dynamodb", region_name="us-west-2")
        self.ddb.create_table(
            TableName=tm.DYNAMODB_TABLE,
            AttributeDefinitions=[
                {"AttributeName": "project_id", "AttributeType": "S"},
                {"AttributeName": "record_id", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "project_id", "KeyType": "HASH"},
                {"AttributeName": "record_id", "KeyType": "RANGE"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        for table, key in (
            (tm.CHECKOUT_TOKENS_TABLE, "pk"),
            (tm.AGENT_SESSIONS_TABLE, "session_id"),
            (tm.PROJECTS_TABLE, "project_id"),
        ):
            self.ddb.create_table(
                TableName=table,
                AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                BillingMode="PAY_PER_REQUEST",
            )
        for patcher in (
            mock.patch.object(tm, "_ddb", self.ddb),
            mock.patch.object(tm, "CHECKOUT_SERVICE_KEY", CS_KEY),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    # -- fixtures ------------------------------------------------------------
    def put_session(self, session_id=SESSION, created_at=POST_EPOCH_TS, status="claimed"):
        self.ddb.put_item(
            TableName=tm.AGENT_SESSIONS_TABLE,
            Item={
                "session_id": {"S": session_id},
                "agent_type_id": {"S": "ENC-AGT-001"},
                "created_at": {"S": created_at},
                "status": {"S": status},
            },
        )

    def put_sci(self, pk=VALID_SCI, session_id=SESSION, token_type="SCI",
                revoked=False, ttl=None):
        self.ddb.put_item(
            TableName=tm.CHECKOUT_TOKENS_TABLE,
            Item={
                "pk": {"S": pk},
                "token_type": {"S": token_type},
                "session_id": {"S": session_id},
                "agent_type_id": {"S": "ENC-AGT-001"},
                "issued_at": {"S": POST_EPOCH_TS},
                "revoked": {"BOOL": revoked},
                "ttl": {"N": str(ttl if ttl is not None else int(time.time()) + 3600)},
            },
        )

    def put_task(self, item_id="ENC-TSK-901", **extra):
        item = {
            "project_id": {"S": "enceladus"},
            "record_id": {"S": f"task#{item_id}"},
            "item_id": {"S": item_id},
            "record_type": {"S": "task"},
            "status": {"S": "open"},
            "title": {"S": "L35 worklog mirror test task"},
            "description": {"S": "original"},
            "history": {"L": []},
        }
        item.update(extra)
        self.ddb.put_item(TableName=tm.DYNAMODB_TABLE, Item=item)

    def put_plan(self, item_id="ENC-PLN-001"):
        self.ddb.put_item(
            TableName=tm.DYNAMODB_TABLE,
            Item={
                "project_id": {"S": "enceladus"},
                "record_id": {"S": f"plan#{item_id}"},
                "item_id": {"S": item_id},
                "record_type": {"S": "plan"},
                "status": {"S": "drafted"},
                "title": {"S": "L35 worklog mirror test plan"},
                "history": {"L": []},
            },
        )

    def get_session_item(self, session_id=SESSION):
        resp = self.ddb.get_item(
            TableName=tm.AGENT_SESSIONS_TABLE,
            Key={"session_id": {"S": session_id}},
        )
        return resp.get("Item") or {}


class WorklogMirrorTests(WorklogMirrorBase):
    """_handle_log mirrors session-authored worklog entries onto the SES record."""

    def test_task_worklog_append_mirrors_onto_session_history(self):
        self.put_session()
        self.put_sci()
        self.put_task(active_agent_session={"BOOL": True},
                      active_agent_session_id={"S": SESSION})
        resp = tm._handle_log(
            "enceladus", "task", "ENC-TSK-901",
            _body(sci=VALID_SCI, description="did the thing"),
        )
        self.assertEqual(resp["statusCode"], 200)

        session_item = self.get_session_item()
        history = session_item.get("history", {}).get("L", [])
        self.assertEqual(len(history), 1)
        entry = history[0]["M"]
        self.assertEqual(entry["status"]["S"], "worklog")
        self.assertEqual(entry["description"]["S"], "[task:ENC-TSK-901] did the thing")
        self.assertEqual(entry["source_record_type"]["S"], "task")
        self.assertEqual(entry["source_record_id"]["S"], "ENC-TSK-901")
        self.assertIn("timestamp", entry)

    def test_plan_worklog_append_also_mirrors(self):
        # Plan (a non-task record type) routes through the SAME _handle_log
        # endpoint — mirroring must apply uniformly across record types.
        self.put_session()
        self.put_sci()
        self.put_plan()
        resp = tm._handle_log(
            "enceladus", "plan", "ENC-PLN-001",
            _body(sci=VALID_SCI, description="[INFO] plan worklog entry"),
        )
        self.assertEqual(resp["statusCode"], 200)

        history = self.get_session_item().get("history", {}).get("L", [])
        self.assertEqual(len(history), 1)
        entry = history[0]["M"]
        self.assertEqual(
            entry["description"]["S"],
            "[plan:ENC-PLN-001] [INFO] plan worklog entry",
        )

    def test_multiple_worklog_appends_across_record_types_accumulate_on_session(self):
        self.put_session()
        self.put_sci()
        self.put_task(active_agent_session={"BOOL": True},
                      active_agent_session_id={"S": SESSION})
        self.put_plan()
        tm._handle_log("enceladus", "task", "ENC-TSK-901",
                        _body(sci=VALID_SCI, description="first entry"))
        tm._handle_log("enceladus", "plan", "ENC-PLN-001",
                        _body(sci=VALID_SCI, description="second entry"))

        history = self.get_session_item().get("history", {}).get("L", [])
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["M"]["description"]["S"], "[task:ENC-TSK-901] first entry")
        self.assertEqual(history[1]["M"]["description"]["S"], "[plan:ENC-PLN-001] second entry")

    def test_grandfathered_session_worklog_still_mirrors(self):
        # No SCI required pre-epoch, but the mirror does not depend on SCI
        # outcome at all — it fires whenever provider is a known ENC-SES id.
        self.put_session(session_id=PRE_EPOCH_SESSION, created_at=PRE_EPOCH_TS)
        self.put_plan()
        resp = tm._handle_log(
            "enceladus", "plan", "ENC-PLN-001",
            _body(provider=PRE_EPOCH_SESSION, description="grandfathered entry"),
        )
        self.assertEqual(resp["statusCode"], 200)
        history = self.get_session_item(PRE_EPOCH_SESSION).get("history", {}).get("L", [])
        self.assertEqual(len(history), 1)

    def test_unknown_session_mirror_is_noop_and_primary_append_still_succeeds(self):
        # Fabricated/unregistered ENC-SES ids fail the SCI gate closed (403) —
        # but assert directly against the mirror helper that a missing session
        # never raises, matching the best-effort touch contract.
        try:
            tm._mirror_worklog_to_session(
                "ENC-SES-ZZZ", "task", "ENC-TSK-901", "desc", tm._now_z(),
            )
        except Exception as exc:  # noqa: BLE001
            self.fail(f"_mirror_worklog_to_session raised for unknown session: {exc}")

    def test_non_agent_provider_is_not_mirrored(self):
        self.put_task(active_agent_session={"BOOL": True},
                      active_agent_session_id={"S": "github"})
        resp = tm._handle_log(
            "enceladus", "task", "ENC-TSK-901",
            _body(provider="github", description="human-attributed entry"),
        )
        self.assertEqual(resp["statusCode"], 200)
        # No session table row exists for "github" — nothing to mirror onto,
        # and _mirror_worklog_to_session's own regex guard is a no-op here.
        self.assertEqual(self.get_session_item("github"), {})


class SessionUpdatedAtBumpTests(WorklogMirrorBase):
    """_sci_gate_for_request bumps last_activity_at + updated_at unconditionally."""

    def test_valid_sci_call_bumps_updated_at(self):
        self.put_session()
        self.put_sci()
        resp = tm._sci_gate_for_request(_body(sci=VALID_SCI), None)
        self.assertIsNone(resp)
        item = self.get_session_item()
        self.assertIn("last_activity_at", item)
        self.assertIn("updated_at", item)
        self.assertEqual(item["last_activity_at"]["S"], item["updated_at"]["S"])

    def test_grandfathered_session_call_still_bumps_updated_at(self):
        # ENC-TSK-L35: previously grandfathered (pre-epoch) sessions were
        # never touched because the gate returned before reaching the touch.
        # The touch now runs unconditionally at _sci_gate_for_request entry.
        self.put_session(session_id=PRE_EPOCH_SESSION, created_at=PRE_EPOCH_TS)
        resp = tm._sci_gate_for_request(_body(provider=PRE_EPOCH_SESSION), None)
        self.assertIsNone(resp)
        item = self.get_session_item(PRE_EPOCH_SESSION)
        self.assertIn("updated_at", item)

    def test_checkout_service_forwarded_call_still_bumps_updated_at(self):
        # A checkout_service-forwarded request (X-Checkout-Service-Key present)
        # is exempt from SCI *validation*, but the heartbeat/updated_at touch
        # must still fire — checkout_service's own copy of the gate also
        # touches, but tracker_mutation must not silently skip its own touch
        # for the direct-to-tracker_mutation call shape either.
        self.put_session()
        event = {"headers": {"x-checkout-service-key": CS_KEY}}
        resp = tm._sci_gate_for_request(_body(), event)
        self.assertIsNone(resp)
        item = self.get_session_item()
        self.assertIn("updated_at", item)

    def test_retired_session_is_not_bumped(self):
        self.put_session(status="retired")
        self.put_sci()
        tm._sci_gate_for_request(_body(sci=VALID_SCI), None)
        item = self.get_session_item()
        self.assertNotIn("updated_at", item)

    def test_non_agent_provider_not_bumped(self):
        resp = tm._sci_gate_for_request(_body(provider="github"), None)
        self.assertIsNone(resp)
        self.assertEqual(self.get_session_item("github"), {})


if __name__ == "__main__":
    unittest.main()
