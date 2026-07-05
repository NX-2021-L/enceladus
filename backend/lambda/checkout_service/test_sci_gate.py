"""test_sci_gate.py — SCI enforcement gate in checkout_service (ENC-ISS-441 Ph3 / ENC-TSK-J93).

Agent-origin mutations (provider = minted ENC-SES-NNN id) through the checkout
service must present a valid Session Claim ID (`sci`, minted by coordination_api
agent.claim, ENC-TSK-J92). Covers:

  * All six rejection modes: missing_sci / unknown_sci / wrong_token_type /
    revoked_sci / expired_sci / session_mismatch — each a 403 naming the mode.
  * unknown_session fails closed (fabricated ENC-SES ids cannot bypass).
  * Grandfathered pre-epoch sessions pass without an sci.
  * Non-ENC-SES providers (github, system:arc-walker, PWA users) pass untouched.
  * Valid SCI passes and touches agent-sessions.last_activity_at (J83 pattern).
  * Retired-session touch is a silent no-op that never fails the mutation.
  * The gate fires in _handle_checkout / _handle_advance / _handle_log BEFORE
    any tracker state is read or written.

Run: python3 -m pytest test_sci_gate.py -q
"""

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
_SPEC = importlib.util.spec_from_file_location(
    "checkout_lambda_sci",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
checkout_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = checkout_lambda
_SPEC.loader.exec_module(checkout_lambda)

SESSION = "ENC-SES-0A1"
OTHER_SESSION = "ENC-SES-0B2"
PRE_EPOCH_SESSION = "ENC-SES-009"
VALID_SCI = "SCI-" + "a" * 32
POST_EPOCH_TS = "2026-07-02T13:00:00Z"   # after SCI_ENFORCEMENT_EPOCH
PRE_EPOCH_TS = "2026-06-30T00:00:00Z"    # before SCI_ENFORCEMENT_EPOCH


class SciGateBase(unittest.TestCase):
    """Creates the moto-backed token + session tables and patches the module client.

    moto is started in setUp (not via a class decorator) so the mock covers the
    inherited fixture and every subclass test method uniformly.
    """

    def setUp(self):
        self._moto = mock_aws()
        self._moto.start()
        self.addCleanup(self._moto.stop)
        self.ddb = boto3.client("dynamodb", region_name="us-west-2")
        self.ddb.create_table(
            TableName=checkout_lambda.CHECKOUT_TOKENS_TABLE,
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
        )
        self.ddb.create_table(
            TableName=checkout_lambda.AGENT_SESSIONS_TABLE,
            AttributeDefinitions=[{"AttributeName": "session_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "session_id", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
        )
        patcher = mock.patch.object(checkout_lambda, "_ddb", self.ddb)
        patcher.start()
        self.addCleanup(patcher.stop)

    # -- fixtures ------------------------------------------------------------
    def put_session(self, session_id=SESSION, created_at=POST_EPOCH_TS, status="claimed"):
        self.ddb.put_item(
            TableName=checkout_lambda.AGENT_SESSIONS_TABLE,
            Item={
                "session_id": {"S": session_id},
                "agent_type_id": {"S": "ENC-AGT-001"},
                "created_at": {"S": created_at},
                "status": {"S": status},
            },
        )

    def put_sci(self, pk=VALID_SCI, session_id=SESSION, token_type="SCI",
                revoked=False, ttl=None):
        item = {
            "pk": {"S": pk},
            "token_type": {"S": token_type},
            "session_id": {"S": session_id},
            "agent_type_id": {"S": "ENC-AGT-001"},
            "issued_at": {"S": POST_EPOCH_TS},
            "revoked": {"BOOL": revoked},
            "ttl": {"N": str(ttl if ttl is not None else int(time.time()) + 3600)},
        }
        self.ddb.put_item(TableName=checkout_lambda.CHECKOUT_TOKENS_TABLE, Item=item)

    def get_session_item(self, session_id=SESSION):
        resp = self.ddb.get_item(
            TableName=checkout_lambda.AGENT_SESSIONS_TABLE,
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


class ValidateSciGateRejectionTests(SciGateBase):
    """The six rejection modes + fail-closed unknown session (ENC-TSK-J93)."""

    def test_missing_sci_rejected(self):
        self.put_session()
        for empty in (None, "", "   "):
            resp = checkout_lambda._validate_sci_gate(SESSION, empty)
            self.assert_sci_403(resp, "missing_sci")

    def test_malformed_sci_rejected_as_unknown(self):
        self.put_session()
        resp = checkout_lambda._validate_sci_gate(SESSION, "SCI-not-hex")
        self.assert_sci_403(resp, "unknown_sci")

    def test_unrecognized_sci_rejected(self):
        self.put_session()
        resp = checkout_lambda._validate_sci_gate(SESSION, "SCI-" + "f" * 32)
        self.assert_sci_403(resp, "unknown_sci")

    def test_wrong_token_type_rejected(self):
        self.put_session()
        self.put_sci(token_type="CAI")
        resp = checkout_lambda._validate_sci_gate(SESSION, VALID_SCI)
        self.assert_sci_403(resp, "wrong_token_type")

    def test_revoked_sci_rejected(self):
        self.put_session()
        self.put_sci(revoked=True)
        resp = checkout_lambda._validate_sci_gate(SESSION, VALID_SCI)
        self.assert_sci_403(resp, "revoked_sci")

    def test_expired_sci_rejected(self):
        # DynamoDB native TTL may lag deletion — the gate must enforce expiry itself.
        self.put_session()
        self.put_sci(ttl=int(time.time()) - 10)
        resp = checkout_lambda._validate_sci_gate(SESSION, VALID_SCI)
        self.assert_sci_403(resp, "expired_sci")

    def test_session_mismatch_rejected(self):
        self.put_session()
        self.put_sci(session_id=OTHER_SESSION)
        resp = checkout_lambda._validate_sci_gate(SESSION, VALID_SCI)
        self.assert_sci_403(resp, "session_mismatch")

    def test_unknown_session_fails_closed(self):
        # Fabricated ENC-SES id, even with a well-formed token, must not bypass.
        self.put_sci(session_id="ENC-SES-ZZZ")
        resp = checkout_lambda._validate_sci_gate("ENC-SES-ZZZ", VALID_SCI)
        self.assert_sci_403(resp, "unknown_session")


class ValidateSciGatePassTests(SciGateBase):
    def test_grandfathered_pre_epoch_session_passes_without_sci(self):
        self.put_session(session_id=PRE_EPOCH_SESSION, created_at=PRE_EPOCH_TS)
        resp = checkout_lambda._validate_sci_gate(PRE_EPOCH_SESSION, None)
        self.assertIsNone(resp)
        # Token validation is skipped entirely (no SCI required), but ENC-TSK-L35
        # makes the heartbeat/updated_at touch unconditional — it now runs before
        # the grandfather short-circuit, so a grandfathered session IS still
        # touched on this session-requiring call.
        item = self.get_session_item(PRE_EPOCH_SESSION)
        self.assertIn("last_activity_at", item)
        self.assertIn("updated_at", item)

    def test_valid_sci_passes_and_touches_last_activity_at(self):
        self.put_session()
        self.put_sci()
        resp = checkout_lambda._validate_sci_gate(SESSION, VALID_SCI)
        self.assertIsNone(resp)
        item = self.get_session_item()
        self.assertIn("last_activity_at", item)
        self.assertRegex(item["last_activity_at"]["S"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_retired_session_touch_is_noop_and_does_not_fail(self):
        # Conditional touch swallows ConditionalCheckFailedException — retired
        # sessions just don't get touched; the mutation proceeds.
        self.put_session(status="retired")
        self.put_sci()
        resp = checkout_lambda._validate_sci_gate(SESSION, VALID_SCI)
        self.assertIsNone(resp)
        self.assertNotIn("last_activity_at", self.get_session_item())


class HandlerGateWiringTests(SciGateBase):
    """The gate fires at the top of checkout/advance/log, before any tracker I/O."""

    def test_checkout_handler_rejects_before_any_state_write(self):
        self.put_session()
        with mock.patch.object(checkout_lambda, "_get_task") as get_task, \
                mock.patch.object(checkout_lambda, "_checkout_task") as co_task:
            resp = checkout_lambda._handle_checkout(
                "enceladus", "ENC-TSK-901", {"active_agent_session_id": SESSION},
            )
        self.assert_sci_403(resp, "missing_sci")
        get_task.assert_not_called()
        co_task.assert_not_called()

    def test_advance_handler_rejects_before_task_fetch(self):
        self.put_session()
        with mock.patch.object(checkout_lambda, "_get_task") as get_task:
            resp = checkout_lambda._handle_advance(
                "enceladus", "ENC-TSK-901",
                {"target_status": "coding-complete", "provider": SESSION},
            )
        self.assert_sci_403(resp, "missing_sci")
        get_task.assert_not_called()

    def test_log_handler_rejects_before_task_fetch(self):
        self.put_session()
        with mock.patch.object(checkout_lambda, "_get_task") as get_task:
            resp = checkout_lambda._handle_log(
                "enceladus", "ENC-TSK-901",
                {"description": "[INFO] test entry", "provider": SESSION},
            )
        self.assert_sci_403(resp, "missing_sci")
        get_task.assert_not_called()

    def test_non_agent_providers_pass_untouched(self):
        # Legacy / system / PWA identities are out of gate scope — the handler
        # proceeds to normal task validation (here: a mocked 404 lookup),
        # proving the gate did not 403 them and no session lookup occurred.
        for provider in ("github", "system:arc-walker", "user", "coordination_dispatch"):
            with mock.patch.object(
                checkout_lambda, "_get_task", return_value=(404, {"error": "nope"}),
            ):
                resp = checkout_lambda._handle_advance(
                    "enceladus", "ENC-TSK-901",
                    {"target_status": "coding-complete", "provider": provider},
                )
            self.assertEqual(resp["statusCode"], 404, f"provider {provider} was gated")

    def test_valid_sci_allows_checkout_and_touches_heartbeat(self):
        self.put_session()
        self.put_sci()
        task = {
            "record_id": "task#ENC-TSK-901", "status": "open",
            "components": [], "transition_type": "github_pr_deploy",
            "checkout_count": 1,
        }
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)), \
                mock.patch.object(checkout_lambda, "_checkout_task",
                                  return_value=(200, {"governance_hash": "gh"})), \
                mock.patch.object(checkout_lambda, "_set_task_field",
                                  return_value=(200, {})):
            resp = checkout_lambda._handle_checkout(
                "enceladus", "ENC-TSK-901",
                {"active_agent_session_id": SESSION, "sci": VALID_SCI},
            )
        self.assertEqual(resp["statusCode"], 200)
        self.assertIn("last_activity_at", self.get_session_item())


if __name__ == "__main__":
    unittest.main()
