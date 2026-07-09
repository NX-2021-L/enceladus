"""test_sci_gate.py — SCI enforcement gate in tracker_mutation (ENC-ISS-441 Ph3 / ENC-TSK-J93).

Agent-origin mutations (write_source.provider = minted ENC-SES-NNN id) must
present a valid Session Claim ID (`sci`, minted by coordination_api agent.claim,
ENC-TSK-J92). Covers:

  * All six rejection modes: missing_sci / unknown_sci / wrong_token_type /
    revoked_sci / expired_sci / session_mismatch — each a 403 naming the mode.
  * unknown_session fails closed (fabricated ENC-SES ids cannot bypass).
  * Grandfathered pre-epoch sessions pass without an sci.
  * Non-ENC-SES providers (github, system:arc-walker, Cognito subs) pass untouched.
  * X-Checkout-Service-Key requests are exempt (the ENC-FTR-037 chain runs the
    identical gate at the checkout_service edge and does not forward sci).
  * Valid SCI passes real moto-backed mutations (tracker.set field update,
    worklog append, record create) and touches agent-sessions.last_activity_at.
  * Retired-session touch is a silent no-op that never fails the mutation.

Run: python3 -m pytest test_sci_gate.py -q
"""

from __future__ import annotations

import importlib.util
import json
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
    "tracker_mutation_sci",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
tm = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)

SESSION = "ENC-SES-0A1"
OTHER_SESSION = "ENC-SES-0B2"
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


class TrackerSciGateBase(unittest.TestCase):
    """moto-backed tracker + token + session + projects tables.

    moto is started in setUp (not via a class decorator) so the mock covers the
    inherited fixture and every subclass test method uniformly.
    CHECKOUT_SERVICE_KEY is patched non-empty so the FTR-037-style exemption is
    header-gated instead of rollout-permissive.
    """

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
            "title": {"S": "SCI gate test task"},
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
                "title": {"S": "SCI gate test plan"},
                "history": {"L": []},
            },
        )

    def put_project(self, project_id="enceladus", prefix="ENC"):
        self.ddb.put_item(
            TableName=tm.PROJECTS_TABLE,
            Item={"project_id": {"S": project_id}, "prefix": {"S": prefix}},
        )

    def get_record(self, record_id="task#ENC-TSK-901"):
        resp = self.ddb.get_item(
            TableName=tm.DYNAMODB_TABLE,
            Key={"project_id": {"S": "enceladus"}, "record_id": {"S": record_id}},
        )
        return resp.get("Item") or {}

    def get_session_item(self, session_id=SESSION):
        resp = self.ddb.get_item(
            TableName=tm.AGENT_SESSIONS_TABLE,
            Key={"session_id": {"S": session_id}},
        )
        return resp.get("Item") or {}

    # -- assertions ----------------------------------------------------------
    def assert_sci_403(self, resp, failure_mode):
        self.assertIsNotNone(resp, "expected a 403 rejection, got pass-through")
        self.assertEqual(resp["statusCode"], 403)
        body = json.loads(resp["body"])
        self.assertEqual(body.get("sci_failure_mode"), failure_mode)
        self.assertIn("agent.claim", body.get("error", ""))
        self.assertIn("ENC-ISS-441", body.get("error", ""))


class ValidateSciGateRejectionTests(TrackerSciGateBase):
    """The six rejection modes + fail-closed unknown session (ENC-TSK-J93)."""

    def test_missing_sci_rejected(self):
        self.put_session()
        for empty in (None, "", "   "):
            self.assert_sci_403(tm._validate_sci_gate(SESSION, empty), "missing_sci")

    def test_malformed_sci_rejected_as_unknown(self):
        self.put_session()
        self.assert_sci_403(tm._validate_sci_gate(SESSION, "SCI-not-hex"), "unknown_sci")

    def test_unrecognized_sci_rejected(self):
        self.put_session()
        self.assert_sci_403(
            tm._validate_sci_gate(SESSION, "SCI-" + "f" * 32), "unknown_sci")

    def test_wrong_token_type_rejected(self):
        self.put_session()
        self.put_sci(token_type="CCI")
        self.assert_sci_403(tm._validate_sci_gate(SESSION, VALID_SCI), "wrong_token_type")

    def test_revoked_sci_rejected(self):
        self.put_session()
        self.put_sci(revoked=True)
        self.assert_sci_403(tm._validate_sci_gate(SESSION, VALID_SCI), "revoked_sci")

    def test_expired_sci_rejected(self):
        # DynamoDB native TTL may lag deletion — the gate must enforce expiry itself.
        self.put_session()
        self.put_sci(ttl=int(time.time()) - 10)
        self.assert_sci_403(tm._validate_sci_gate(SESSION, VALID_SCI), "expired_sci")

    def test_session_mismatch_rejected(self):
        self.put_session()
        self.put_sci(session_id=OTHER_SESSION)
        self.assert_sci_403(tm._validate_sci_gate(SESSION, VALID_SCI), "session_mismatch")

    def test_unknown_session_fails_closed(self):
        # Fabricated ENC-SES id, even with a well-formed token, must not bypass.
        self.put_sci(session_id="ENC-SES-ZZZ")
        self.assert_sci_403(
            tm._validate_sci_gate("ENC-SES-ZZZ", VALID_SCI), "unknown_session")


class GateScopeTests(TrackerSciGateBase):
    """_sci_gate_for_request scoping: identity match + checkout-service exemption."""

    def test_non_agent_providers_pass_untouched(self):
        # Legacy/system/Cognito identities are out of gate scope — no session
        # lookup, no sci required, request proceeds unchanged.
        for provider in (
            "github", "system:arc-walker", "user", "coordination_dispatch",
            "1234abcd-cognito-sub", "io", "",
        ):
            body = _body(provider=provider)
            self.assertIsNone(tm._sci_gate_for_request(body, None),
                              f"provider {provider!r} was gated")

    def test_agent_origin_without_sci_rejected(self):
        self.put_session()
        self.assert_sci_403(tm._sci_gate_for_request(_body(), None), "missing_sci")

    def test_checkout_service_key_request_is_exempt(self):
        # checkout_service runs the identical gate at its own edge and the
        # ENC-FTR-037 chain does not forward sci — the presented key exempts.
        event = {"headers": {"x-checkout-service-key": CS_KEY}}
        self.assertIsNone(tm._sci_gate_for_request(_body(), event))

    def test_wrong_checkout_service_key_is_not_exempt(self):
        self.put_session()
        event = {"headers": {"x-checkout-service-key": "not-the-key"}}
        self.assert_sci_403(tm._sci_gate_for_request(_body(), event), "missing_sci")


class MutationPathTests(TrackerSciGateBase):
    """Full moto-backed mutation paths through the gated handlers."""

    def test_update_field_rejected_without_sci_and_record_unchanged(self):
        self.put_session()
        self.put_task()
        resp = tm._handle_update_field(
            "enceladus", "task", "ENC-TSK-901",
            _body(field="description", value="mutated"),
        )
        self.assert_sci_403(resp, "missing_sci")
        self.assertEqual(self.get_record()["description"]["S"], "original")

    def test_update_field_with_valid_sci_succeeds_and_touches_heartbeat(self):
        self.put_session()
        self.put_sci()
        self.put_task()
        resp = tm._handle_update_field(
            "enceladus", "task", "ENC-TSK-901",
            _body(sci=VALID_SCI, field="description", value="mutated"),
        )
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(self.get_record()["description"]["S"], "mutated")
        item = self.get_session_item()
        self.assertIn("last_activity_at", item)
        self.assertRegex(
            item["last_activity_at"]["S"],
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
        )

    def test_update_field_grandfathered_session_passes_without_sci(self):
        self.put_session(session_id=PRE_EPOCH_SESSION, created_at=PRE_EPOCH_TS)
        self.put_task()
        resp = tm._handle_update_field(
            "enceladus", "task", "ENC-TSK-901",
            _body(provider=PRE_EPOCH_SESSION, field="description", value="mutated"),
        )
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(self.get_record()["description"]["S"], "mutated")

    def test_retired_session_touch_is_noop_and_mutation_still_succeeds(self):
        self.put_session(status="retired")
        self.put_sci()
        self.put_task()
        resp = tm._handle_update_field(
            "enceladus", "task", "ENC-TSK-901",
            _body(sci=VALID_SCI, field="description", value="mutated"),
        )
        self.assertEqual(resp["statusCode"], 200)
        self.assertNotIn("last_activity_at", self.get_session_item())

    def test_unknown_session_fails_closed_on_update(self):
        self.put_sci(session_id="ENC-SES-XX9")
        self.put_task()
        resp = tm._handle_update_field(
            "enceladus", "task", "ENC-TSK-901",
            _body(provider="ENC-SES-XX9", sci=VALID_SCI, field="description", value="x"),
        )
        self.assert_sci_403(resp, "unknown_session")

    def test_log_append_gated_and_passes_with_valid_sci(self):
        # Non-task records accept direct agent worklogs (no checkout needed) —
        # the SCI gate still applies to the ENC-SES identity.
        self.put_session()
        self.put_plan()
        resp = tm._handle_log(
            "enceladus", "plan", "ENC-PLN-001",
            _body(description="[INFO] direct agent worklog"),
        )
        self.assert_sci_403(resp, "missing_sci")

        self.put_sci()
        resp = tm._handle_log(
            "enceladus", "plan", "ENC-PLN-001",
            _body(sci=VALID_SCI, description="[INFO] direct agent worklog"),
        )
        self.assertEqual(resp["statusCode"], 200)
        self.assertIn("last_activity_at", self.get_session_item())

    def test_create_record_gated_and_passes_with_valid_sci(self):
        self.put_session()
        self.put_project()
        resp = tm._handle_create_record(
            "enceladus", "task", _body(title="SCI gate create test"),
        )
        self.assert_sci_403(resp, "missing_sci")

        self.put_sci()
        resp = tm._handle_create_record(
            "enceladus", "task",
            _body(
                sci=VALID_SCI,
                title="SCI gate create test",
                acceptance_criteria=["record is created via a valid SCI"],
            ),
        )
        self.assertIn(resp["statusCode"], (200, 201))
        self.assertIn("last_activity_at", self.get_session_item())

    def test_checkout_chain_via_service_key_still_works_without_sci(self):
        # checkout_service -> tracker_mutation POST .../checkout presents
        # X-Checkout-Service-Key and an ENC-SES provider but no sci (the gate
        # already ran at the checkout_service edge). Must not regress.
        self.put_session()
        self.put_task()
        event = {"headers": {"x-checkout-service-key": CS_KEY}}
        resp = tm._handle_checkout(
            "enceladus", "task", "ENC-TSK-901", _body(), event=event,
        )
        self.assertEqual(resp["statusCode"], 200)
        record = self.get_record()
        self.assertEqual(record["active_agent_session_id"]["S"], SESSION)


if __name__ == "__main__":
    unittest.main()
