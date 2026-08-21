"""test_stale_holder_recovery.py — governed stale-holder checkout recovery
(ENC-TSK-O37 / ENC-ISS-597).

POST .../task/{id}/recover authorizes a THIRD PARTY to clear someone else's
checkout only when the current holder's agent session is server-verified
TERMINAL: absent, already 'retired', or past the SCI TTL by idle-reference
timestamp even though no sweep has run yet. A LIVE holder must still reject
third-party recovery — this is a narrow recovery path, not a blanket
force-release. Every successful third-party recovery writes an audit worklog
naming the prior holder BEFORE the checkout clears.

Covers:
  * _session_terminal_state: absent / retired / sci_ttl_elapsed / live.
  * _handle_release_recover: terminal-holder recovery succeeds + audits.
  * _handle_release_recover: live-holder recovery is rejected (409), no
    worklog written, no release attempted.
  * _handle_release_recover: absent-session (never registered / hard-deleted
    holder) recovery succeeds.
  * Self-recovery (caller == holder) is treated as an ordinary release, no
    terminality check, no audit worklog.
  * The caller itself must be an authenticated, SCI-valid agent session.
  * A non-agent holder (github, coordination_dispatch, ...) is out of scope
    and rejected rather than silently released.
  * Not-checked-out task is a 400, not a false "recovered".

Run: python3 -m pytest test_stale_holder_recovery.py -q
"""

import importlib.util
import json
import os
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import boto3
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))
_SPEC = importlib.util.spec_from_file_location(
    "checkout_lambda_recovery",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
checkout_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = checkout_lambda
_SPEC.loader.exec_module(checkout_lambda)

CALLER = "ENC-SES-0C1"
HOLDER = "ENC-SES-0D2"
VALID_SCI = "SCI-" + "b" * 32
NOW_TS = "2026-08-21T12:00:00Z"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class RecoveryBase(unittest.TestCase):
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

    def put_session(self, session_id, status="claimed", created_at=NOW_TS,
                     claimed_at="", last_activity_at=""):
        item = {
            "session_id": {"S": session_id},
            "agent_type_id": {"S": "ENC-AGT-001"},
            "created_at": {"S": created_at},
            "status": {"S": status},
        }
        if claimed_at:
            item["claimed_at"] = {"S": claimed_at}
        if last_activity_at:
            item["last_activity_at"] = {"S": last_activity_at}
        self.ddb.put_item(TableName=checkout_lambda.AGENT_SESSIONS_TABLE, Item=item)

    def put_sci(self, session_id=CALLER, pk=VALID_SCI, revoked=False, ttl=None):
        self.ddb.put_item(
            TableName=checkout_lambda.CHECKOUT_TOKENS_TABLE,
            Item={
                "pk": {"S": pk},
                "token_type": {"S": "SCI"},
                "session_id": {"S": session_id},
                "agent_type_id": {"S": "ENC-AGT-001"},
                "issued_at": {"S": NOW_TS},
                "revoked": {"BOOL": revoked},
                "ttl": {"N": str(ttl if ttl is not None else int(time.time()) + 3600)},
            },
        )

    def checked_out_task(self, holder=HOLDER, **overrides):
        task = {
            "record_id": "task#ENC-TSK-999",
            "active_agent_session": True,
            "active_agent_session_id": holder,
            "status": "in-progress",
        }
        task.update(overrides)
        return task


class SessionTerminalStateTests(RecoveryBase):
    """Pure _session_terminal_state logic — no HTTP envelope."""

    def test_absent_session_is_terminal(self):
        is_terminal, reason = checkout_lambda._session_terminal_state(None)
        self.assertTrue(is_terminal)
        self.assertEqual(reason, "absent")

    def test_retired_status_is_terminal(self):
        session = {"status": "retired", "created_at": NOW_TS,
                   "claimed_at": "", "last_activity_at": ""}
        is_terminal, reason = checkout_lambda._session_terminal_state(session)
        self.assertTrue(is_terminal)
        self.assertEqual(reason, "retired")

    def test_live_recent_session_is_not_terminal(self):
        recent = _iso(datetime.now(timezone.utc) - timedelta(minutes=5))
        session = {"status": "claimed", "created_at": recent,
                   "claimed_at": recent, "last_activity_at": recent}
        is_terminal, reason = checkout_lambda._session_terminal_state(session)
        self.assertFalse(is_terminal)
        self.assertEqual(reason, "live")

    def test_sci_ttl_elapsed_without_sweep_is_terminal(self):
        # Still 'claimed' (sweep hasn't run) but last activity is > 86400s ago.
        stale = _iso(datetime.now(timezone.utc) - timedelta(seconds=90000))
        session = {"status": "claimed", "created_at": stale,
                   "claimed_at": stale, "last_activity_at": stale}
        is_terminal, reason = checkout_lambda._session_terminal_state(session)
        self.assertTrue(is_terminal)
        self.assertEqual(reason, "sci_ttl_elapsed")

    def test_last_activity_at_takes_precedence_over_stale_created_at(self):
        # created_at is ancient but last_activity_at is recent (heartbeat) —
        # must NOT be flagged terminal, matching agent_id_alloc._idle_reference.
        ancient = _iso(datetime.now(timezone.utc) - timedelta(days=30))
        recent = _iso(datetime.now(timezone.utc) - timedelta(minutes=1))
        session = {"status": "claimed", "created_at": ancient,
                   "claimed_at": "", "last_activity_at": recent}
        is_terminal, reason = checkout_lambda._session_terminal_state(session)
        self.assertFalse(is_terminal)
        self.assertEqual(reason, "live")


class HandleReleaseRecoverTests(RecoveryBase):
    """HTTP-level _handle_release_recover behavior."""

    def _valid_caller(self):
        self.put_session(CALLER, status="claimed", created_at=NOW_TS,
                          last_activity_at=NOW_TS)
        self.put_sci()

    def test_terminal_holder_recovery_succeeds_with_audit(self):
        self._valid_caller()
        self.put_session(HOLDER, status="retired")
        task = self.checked_out_task()
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)), \
                mock.patch.object(checkout_lambda, "_log_task",
                                  return_value=(200, {})) as log_task, \
                mock.patch.object(checkout_lambda, "_release_task",
                                  return_value=(200, {})) as release_task:
            resp = checkout_lambda._handle_release_recover(
                "enceladus", "ENC-TSK-999",
                {"provider": CALLER, "sci": VALID_SCI},
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["recovered"])
        self.assertEqual(body["prior_holder"], HOLDER)
        self.assertEqual(body["reason"], "retired")
        # Audit worklog written naming the prior holder, BEFORE release.
        log_task.assert_called_once()
        audit_args, audit_kwargs = log_task.call_args
        self.assertIn(HOLDER, audit_args[2])
        self.assertIn("RECOVERY", audit_args[2])
        self.assertEqual(audit_kwargs.get("provider"), CALLER)
        release_task.assert_called_once_with("enceladus", "ENC-TSK-999", provider=CALLER)

    def test_absent_holder_session_recovery_succeeds(self):
        self._valid_caller()
        # No put_session(HOLDER) at all — the holder session record is absent.
        task = self.checked_out_task()
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)), \
                mock.patch.object(checkout_lambda, "_log_task", return_value=(200, {})), \
                mock.patch.object(checkout_lambda, "_release_task",
                                  return_value=(200, {})) as release_task:
            resp = checkout_lambda._handle_release_recover(
                "enceladus", "ENC-TSK-999",
                {"provider": CALLER, "sci": VALID_SCI},
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["recovered"])
        self.assertEqual(body["reason"], "absent")
        release_task.assert_called_once()

    def test_live_holder_recovery_rejected(self):
        self._valid_caller()
        recent = _iso(datetime.now(timezone.utc) - timedelta(minutes=2))
        self.put_session(HOLDER, status="claimed", created_at=recent,
                          last_activity_at=recent)
        task = self.checked_out_task()
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)), \
                mock.patch.object(checkout_lambda, "_log_task") as log_task, \
                mock.patch.object(checkout_lambda, "_release_task") as release_task:
            resp = checkout_lambda._handle_release_recover(
                "enceladus", "ENC-TSK-999",
                {"provider": CALLER, "sci": VALID_SCI},
            )
        self.assertEqual(resp["statusCode"], 409)
        body = json.loads(resp["body"])
        self.assertEqual(body.get("holder"), HOLDER)
        self.assertEqual(body.get("holder_state"), "live")
        # No blanket force-release: neither the audit worklog nor the release
        # call may fire when the holder is live.
        log_task.assert_not_called()
        release_task.assert_not_called()

    def test_self_recovery_is_ordinary_release_no_terminality_check(self):
        self._valid_caller()
        task = self.checked_out_task(holder=CALLER)
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)), \
                mock.patch.object(checkout_lambda, "_get_agent_session") as get_session, \
                mock.patch.object(checkout_lambda, "_log_task") as log_task, \
                mock.patch.object(checkout_lambda, "_release_task",
                                  return_value=(200, {})) as release_task:
            resp = checkout_lambda._handle_release_recover(
                "enceladus", "ENC-TSK-999",
                {"provider": CALLER, "sci": VALID_SCI},
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertFalse(body["recovered"])
        self.assertEqual(body["reason"], "self_release")
        # _get_agent_session is called exactly once (the SCI gate's mandatory
        # lookup of the caller's own session) — no SEPARATE holder-terminality
        # lookup runs, since holder == caller short-circuits before that check.
        get_session.assert_called_once_with(CALLER)
        log_task.assert_not_called()
        release_task.assert_called_once_with("enceladus", "ENC-TSK-999", provider=CALLER)

    def test_caller_without_valid_sci_is_rejected(self):
        self.put_session(CALLER, status="claimed", created_at=NOW_TS)
        # No SCI minted for CALLER.
        with mock.patch.object(checkout_lambda, "_get_task") as get_task:
            resp = checkout_lambda._handle_release_recover(
                "enceladus", "ENC-TSK-999",
                {"provider": CALLER},
            )
        self.assertEqual(resp["statusCode"], 403)
        body = json.loads(resp["body"])
        self.assertEqual(body.get("sci_failure_mode"), "missing_sci")
        get_task.assert_not_called()

    def test_missing_provider_rejected(self):
        resp = checkout_lambda._handle_release_recover(
            "enceladus", "ENC-TSK-999", {},
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_non_agent_holder_out_of_scope(self):
        self._valid_caller()
        task = self.checked_out_task(holder="coordination_dispatch")
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)), \
                mock.patch.object(checkout_lambda, "_log_task") as log_task, \
                mock.patch.object(checkout_lambda, "_release_task") as release_task:
            resp = checkout_lambda._handle_release_recover(
                "enceladus", "ENC-TSK-999",
                {"provider": CALLER, "sci": VALID_SCI},
            )
        self.assertEqual(resp["statusCode"], 409)
        log_task.assert_not_called()
        release_task.assert_not_called()

    def test_not_checked_out_task_is_400(self):
        self._valid_caller()
        task = {"record_id": "task#ENC-TSK-999", "active_agent_session": False,
                "active_agent_session_id": "", "status": "open"}
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)), \
                mock.patch.object(checkout_lambda, "_release_task") as release_task:
            resp = checkout_lambda._handle_release_recover(
                "enceladus", "ENC-TSK-999",
                {"provider": CALLER, "sci": VALID_SCI},
            )
        self.assertEqual(resp["statusCode"], 400)
        release_task.assert_not_called()


class RoutingWiringTests(RecoveryBase):
    def test_recover_route_dispatches_to_handler(self):
        event = {
            "requestContext": {"http": {"method": "POST", "path":
                                         "/api/v1/checkout/enceladus/task/ENC-TSK-999/recover"}},
            "headers": {"x-internal-api-key": os.environ.get("INTERNAL_API_KEY", "")},
            "body": json.dumps({"provider": CALLER, "sci": VALID_SCI}),
        }
        with mock.patch.object(checkout_lambda, "_is_authenticated", return_value=True), \
                mock.patch.object(checkout_lambda, "_handle_release_recover",
                                  return_value={"statusCode": 200, "body": "{}"}) as handler:
            checkout_lambda.lambda_handler(event, None)
        handler.assert_called_once_with("enceladus", "ENC-TSK-999",
                                         {"provider": CALLER, "sci": VALID_SCI})

    def test_recover_route_rejects_get(self):
        event = {
            "requestContext": {"http": {"method": "GET", "path":
                                         "/api/v1/checkout/enceladus/task/ENC-TSK-999/recover"}},
            "body": "",
        }
        with mock.patch.object(checkout_lambda, "_is_authenticated", return_value=True):
            resp = checkout_lambda.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 405)


if __name__ == "__main__":
    unittest.main()
