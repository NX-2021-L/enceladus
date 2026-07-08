"""ENC-TSK-J70 (ENC-FTR-121 Ph3): escalation approval surface tests.

Covers the §6 non-delegable approval invariant (internal-key / managed-token
credentials get 403 on every escalation route — mirroring ENC-TSK-J57's
test_internal_key_returns_403), the requested→approved|denied|
denied_with_guidance decision writes with their race guard, approve driving
the ENC-TSK-J69 applier (with the fail-soft approved-but-unapplied path), and
the §5.7 render_diff fresh-delta + drift-flag semantics.
"""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))
import importlib.util

_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda_j70",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
coordination_lambda = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = coordination_lambda
_SPEC.loader.exec_module(coordination_lambda)

INTERNAL_CLAIMS = {"auth_mode": "internal-key"}
MANAGED_CLAIMS = {"auth_mode": "managed-token"}

# ENC-TSK-M12 / ENC-ISS-501: the escalation decision gate now requires a
# structurally human Cognito ID token — token_use=id, aud on the human
# app-client allowlist, non-machine email domain. The test human client id is
# injected via ESCALATION_HUMAN_CLIENT_IDS (read per-call by the module).
TEST_HUMAN_CLIENT_ID = "test-pwa-client-id"
os.environ.setdefault("ESCALATION_HUMAN_CLIENT_IDS", TEST_HUMAN_CLIENT_ID)
COGNITO_CLAIMS = {
    "auth_mode": "cognito",
    "sub": "abc-123",
    "email": "io@jreese.net",
    "cognito:username": "io",
    "token_use": "id",
    "aud": TEST_HUMAN_CLIENT_ID,
}


class _CCFE(Exception):
    def __init__(self):
        super().__init__("conditional check failed")
        self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}


def _escalation_item(status="requested", mutation_type="deploy_arc_change",
                     payload=None, expected_version=""):
    if payload is None:
        payload = {"new_deploy_arc_type": "code_only"}
    item = {
        "project_id": "enceladus",
        "record_id": "escalation#ENC-ESC-001",
        "item_id": "ENC-ESC-001",
        "record_type": "escalation",
        "status": status,
        "mutation_type": mutation_type,
        "target_record_id": "ENC-TSK-J10",
        "payload": json.dumps(payload),
        "justification": "test",
        "requested_by": {"session_id": "ENC-SES-02F"},
        "created_at": "2026-07-02T04:00:00Z",
        "updated_at": "2026-07-02T04:00:00Z",
        "events": [],
    }
    if expected_version:
        item["expected_version"] = expected_version
    return item


def _target_item(status="in-progress", transition_type="github_pr_deploy", sync_version=4):
    return {
        "project_id": "enceladus",
        "record_id": "task#ENC-TSK-J10",
        "item_id": "ENC-TSK-J10",
        "record_type": "task",
        "title": "target task",
        "status": status,
        "transition_type": transition_type,
        "sync_version": sync_version,
        "updated_at": "2026-07-02T03:00:00Z",
    }


def _serialized(item):
    return {k: coordination_lambda._serialize(v) for k, v in item.items()}


def _fake_ddb(escalation=None, target=None, decision_raises=None):
    fake = mock.MagicMock()

    def _get_item(TableName=None, Key=None, **kwargs):
        record_id = (Key or {}).get("record_id", {}).get("S", "")
        if record_id.startswith("escalation#") and escalation is not None:
            return {"Item": _serialized(escalation)}
        if record_id.startswith("task#") and target is not None:
            return {"Item": _serialized(target)}
        return {}

    fake.get_item.side_effect = _get_item
    if decision_raises is not None:
        fake.update_item.side_effect = decision_raises
    return fake


def _decision_event(body=None):
    return {"body": json.dumps(body or {}), "queryStringParameters": None}


class TestNonDelegableGate(unittest.TestCase):
    def test_internal_key_gets_403_on_all_escalation_routes(self):
        for claims in (INTERNAL_CLAIMS, MANAGED_CLAIMS):
            feed = coordination_lambda._handle_escalations_feed({"queryStringParameters": {}}, claims)
            self.assertEqual(403, feed["statusCode"])
            for decision in ("approve", "deny"):
                resp = coordination_lambda._handle_escalation_decision(
                    "enceladus", "ENC-ESC-001", decision, _decision_event(), claims)
                self.assertEqual(403, resp["statusCode"])
                self.assertIn("human-only", json.loads(resp["body"])["error"])


class TestEscalationDecisions(unittest.TestCase):
    def _decide(self, decision, ddb, body=None, apply_result=None, apply_raises=None,
                claims=None, allowlist=None):
        patches = [mock.patch.object(coordination_lambda, "_get_ddb", return_value=ddb)]
        invoke = mock.MagicMock()
        if apply_raises is not None:
            invoke.side_effect = apply_raises
        else:
            invoke.return_value = apply_result or {
                "success": True, "status": "applied",
                "result": {"before": {}, "after": {}}, "_status_code": 200,
            }
        patches.append(mock.patch.object(
            coordination_lambda, "_invoke_tracker_mutation_api", invoke))
        # ENC-TSK-L92: the decider-allowlist check calls S3 in production; tests
        # stub it directly rather than mocking boto3 so intent stays legible.
        # Default allowlist matches COGNITO_CLAIMS's email, preserving every
        # pre-L92 test's original pass-through behavior.
        patches.append(mock.patch.object(
            coordination_lambda, "_load_escalation_approver_allowlist",
            return_value=allowlist if allowlist is not None else {"io@jreese.net"}))
        with patches[0], patches[1], patches[2]:
            resp = coordination_lambda._handle_escalation_decision(
                "enceladus", "ENC-ESC-001", decision,
                _decision_event(body), claims or COGNITO_CLAIMS)
        return resp, ddb, invoke

    def test_approve_happy_path_stamps_identity_and_applies(self):
        resp, ddb, invoke = self._decide(
            "approve", _fake_ddb(escalation=_escalation_item()))
        self.assertEqual(200, resp["statusCode"])
        body = json.loads(resp["body"])
        self.assertTrue(body["applied"])
        self.assertEqual("applied", body["status"])
        self.assertEqual("io@jreese.net", body["approved_by"])

        update = ddb.update_item.call_args.kwargs
        self.assertIn("#st = :requested", update["ConditionExpression"])
        values = update["ExpressionAttributeValues"]
        self.assertEqual("approved", values[":new_status"]["S"])
        approved_by = values[":approved_by"]["M"]
        self.assertEqual("abc-123", approved_by["sub"]["S"])
        self.assertEqual("io@jreese.net", approved_by["email"]["S"])
        event_entry = values[":event"]["L"][0]["M"]
        self.assertEqual("approved", event_entry["event_type"]["S"])

        invoke.assert_called_once()
        args = invoke.call_args.args
        self.assertEqual("POST", args[0])
        self.assertEqual("/api/v1/tracker/enceladus/escalation/ENC-ESC-001/apply", args[1])

    def test_approve_with_apply_failure_is_fail_soft(self):
        resp, _, _ = self._decide(
            "approve", _fake_ddb(escalation=_escalation_item()),
            apply_raises=RuntimeError("AccessDenied on lambda:InvokeFunction"))
        self.assertEqual(200, resp["statusCode"])
        body = json.loads(resp["body"])
        self.assertEqual("approved", body["status"])
        self.assertFalse(body["applied"])
        self.assertIn("AccessDenied", body["apply_error"])
        self.assertIn("/apply", body["retry"])

    def test_approve_with_apply_http_error_reports_error(self):
        resp, _, _ = self._decide(
            "approve", _fake_ddb(escalation=_escalation_item()),
            apply_result={"success": False, "error": "escalation is 'denied'", "_status_code": 409})
        body = json.loads(resp["body"])
        self.assertFalse(body["applied"])
        self.assertIn("denied", body["apply_error"])

    def test_deny_without_note_is_denied(self):
        resp, ddb, invoke = self._decide(
            "deny", _fake_ddb(escalation=_escalation_item()))
        body = json.loads(resp["body"])
        self.assertEqual("denied", body["status"])
        self.assertEqual("io@jreese.net", body["denied_by"])
        invoke.assert_not_called()
        values = ddb.update_item.call_args.kwargs["ExpressionAttributeValues"]
        self.assertEqual("denied", values[":new_status"]["S"])
        self.assertNotIn(":guidance_note", values)

    def test_deny_with_note_is_denied_with_guidance(self):
        resp, ddb, _ = self._decide(
            "deny", _fake_ddb(escalation=_escalation_item()),
            body={"guidance_note": "Open a successor task instead."})
        body = json.loads(resp["body"])
        self.assertEqual("denied_with_guidance", body["status"])
        self.assertEqual("Open a successor task instead.", body["guidance_note"])
        update = ddb.update_item.call_args.kwargs
        values = update["ExpressionAttributeValues"]
        self.assertEqual("denied_with_guidance", values[":new_status"]["S"])
        event_entry = values[":event"]["L"][0]["M"]
        self.assertEqual(
            "Open a successor task instead.", event_entry["guidance_note"]["S"])

    def test_non_requested_escalation_409(self):
        resp, ddb, invoke = self._decide(
            "approve", _fake_ddb(escalation=_escalation_item(status="applied")))
        self.assertEqual(409, resp["statusCode"])
        ddb.update_item.assert_not_called()
        invoke.assert_not_called()

    def test_missing_escalation_404(self):
        resp, _, _ = self._decide("approve", _fake_ddb(escalation=None))
        self.assertEqual(404, resp["statusCode"])

    def test_concurrent_decision_race_409(self):
        resp, _, invoke = self._decide(
            "approve",
            _fake_ddb(escalation=_escalation_item(), decision_raises=_CCFE()))
        self.assertEqual(409, resp["statusCode"])
        self.assertIn("concurrently", json.loads(resp["body"])["error"])
        invoke.assert_not_called()


class TestEscalationApproverAllowlist(unittest.TestCase):
    """ENC-TSK-L92 / ENC-ISS-501: positive allowlist on top of _is_cognito_session.

    _is_cognito_session alone is a fail-open blocklist (excludes only
    auth_mode in {"internal-key", "managed-token"}); it let a non-human
    Cognito-authenticated identity self-approve escalations. These tests
    cover the allowlist gate directly, independent of TestEscalationDecisions'
    default-allowlisted fixture.
    """

    def test_cognito_identity_not_on_allowlist_gets_403(self):
        # Structurally human token shape (id token, human client, human email
        # domain) so the request reaches the allowlist gate itself.
        not_allowlisted_claims = {
            "auth_mode": "cognito", "sub": "someone-else",
            "email": "someone-else@jreese.net",
            "token_use": "id", "aud": TEST_HUMAN_CLIENT_ID,
        }
        resp, ddb, invoke = self._decide_raw(
            "approve", _fake_ddb(escalation=_escalation_item()),
            claims=not_allowlisted_claims, allowlist={"io@jreese.net"})
        self.assertEqual(403, resp["statusCode"])
        self.assertIn("allowlist", json.loads(resp["body"])["error"])
        ddb.update_item.assert_not_called()
        invoke.assert_not_called()

    def test_allowlisted_identity_still_passes(self):
        resp, ddb, invoke = self._decide_raw(
            "approve", _fake_ddb(escalation=_escalation_item()),
            claims=COGNITO_CLAIMS, allowlist={"io@jreese.net"})
        self.assertEqual(200, resp["statusCode"])
        invoke.assert_called_once()

    def test_missing_email_claim_gets_403(self):
        no_email_claims = {
            "auth_mode": "cognito", "sub": "abc-123",
            "token_use": "id", "aud": TEST_HUMAN_CLIENT_ID,
        }
        resp, ddb, invoke = self._decide_raw(
            "approve", _fake_ddb(escalation=_escalation_item()),
            claims=no_email_claims, allowlist={"io@jreese.net"})
        self.assertEqual(403, resp["statusCode"])
        ddb.update_item.assert_not_called()

    def test_parses_real_document_format(self):
        """Regression lock for the S3 doc's actual fenced-yaml list-item shape."""
        doc_body = (
            "# Escalation Approver Allowlist\n\n"
            "Some prose.\n\n"
            "```yaml\n"
            "approvers:\n"
            "  - email: \"ai@jreese.net\"\n"
            "    added_at: \"2026-07-07T12:00:00Z\"\n"
            "    added_by: \"io (ENC-TSK-L92 initial provisioning)\"\n"
            "    notes: \"test\"\n"
            "```\n"
        )
        coordination_lambda._escalation_allowlist_cache["emails"] = None
        coordination_lambda._escalation_allowlist_cache["fetched_at"] = 0.0
        with mock.patch.object(coordination_lambda, "boto3") as fake_boto3:
            fake_body = mock.MagicMock()
            fake_body.read.return_value = doc_body.encode("utf-8")
            fake_boto3.client.return_value.get_object.return_value = {"Body": fake_body}
            emails = coordination_lambda._load_escalation_approver_allowlist()
        self.assertEqual({"ai@jreese.net"}, emails)

    def test_allowlist_fetch_failure_fails_closed(self):
        """S3 GetObject error -> empty allowlist -> everyone denied, not everyone allowed."""
        ddb = _fake_ddb(escalation=_escalation_item())
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=ddb), \
             mock.patch.object(coordination_lambda, "boto3") as fake_boto3:
            fake_boto3.client.return_value.get_object.side_effect = RuntimeError("NoSuchKey")
            coordination_lambda._escalation_allowlist_cache["emails"] = None
            coordination_lambda._escalation_allowlist_cache["fetched_at"] = 0.0
            resp = coordination_lambda._handle_escalation_decision(
                "enceladus", "ENC-ESC-001", "approve", _decision_event(), COGNITO_CLAIMS)
        self.assertEqual(403, resp["statusCode"])
        ddb.update_item.assert_not_called()

    def _decide_raw(self, decision, ddb, claims, allowlist, body=None):
        invoke = mock.MagicMock()
        invoke.return_value = {
            "success": True, "status": "applied",
            "result": {"before": {}, "after": {}}, "_status_code": 200,
        }
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=ddb), \
             mock.patch.object(coordination_lambda, "_invoke_tracker_mutation_api", invoke), \
             mock.patch.object(coordination_lambda, "_load_escalation_approver_allowlist",
                                return_value=allowlist):
            resp = coordination_lambda._handle_escalation_decision(
                "enceladus", "ENC-ESC-001", decision, _decision_event(body), claims)
        return resp, ddb, invoke


class TestHumanPrincipalGate(unittest.TestCase):
    """ENC-TSK-M12 / ENC-ISS-501: structural human-principal enforcement.

    The email allowlist authorizes WHICH identities decide; this gate enforces
    WHAT KIND of token may decide at all. Machine token shapes must be
    rejected 403 even when their email IS on the allowlist -- the allowlist
    must never be the only barrier between a machine principal and an
    escalation approval.
    """

    ALLOWLIST = {"io@jreese.net", "terminal-agent@enceladus.internal"}

    def _decide(self, claims, decision="approve"):
        ddb = _fake_ddb(escalation=_escalation_item())
        invoke = mock.MagicMock()
        invoke.return_value = {
            "success": True, "status": "applied",
            "result": {"before": {}, "after": {}}, "_status_code": 200,
        }
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=ddb), \
             mock.patch.object(coordination_lambda, "_invoke_tracker_mutation_api", invoke), \
             mock.patch.object(coordination_lambda, "_load_escalation_approver_allowlist",
                                return_value=self.ALLOWLIST):
            resp = coordination_lambda._handle_escalation_decision(
                "enceladus", "ENC-ESC-001", decision, _decision_event(), claims)
        return resp, ddb, invoke

    def _assert_machine_rejected(self, claims):
        for decision in ("approve", "deny"):
            resp, ddb, invoke = self._decide(claims, decision=decision)
            self.assertEqual(403, resp["statusCode"])
            self.assertIn("structurally rejected", json.loads(resp["body"])["error"])
            ddb.update_item.assert_not_called()
            invoke.assert_not_called()

    def test_access_token_rejected_even_when_email_allowlisted(self):
        self._assert_machine_rejected({
            "auth_mode": "cognito", "sub": "abc-123", "email": "io@jreese.net",
            "token_use": "access", "client_id": TEST_HUMAN_CLIENT_ID,
            "username": "io",
        })

    def test_client_credentials_m2m_token_rejected(self):
        # client_credentials grant: token_use=access, bare client_id, no email.
        self._assert_machine_rejected({
            "token_use": "access", "client_id": "m2m-agent-client-id",
            "scope": "enceladus/agent.write", "sub": "m2m-client-sub",
        })

    def test_machine_operated_cognito_user_rejected_even_when_allowlisted(self):
        # The observed ENC-ISS-501 attacker shape: a genuine human-pool ID
        # token minted for a machine-operated user. Rejected on email domain
        # even though the email is on the allowlist here.
        self._assert_machine_rejected({
            "auth_mode": "cognito", "sub": "c4b8e478-40e1-70ce-9f5d-caffd3e241df",
            "email": "terminal-agent@enceladus.internal",
            "token_use": "id", "aud": TEST_HUMAN_CLIENT_ID,
        })

    def test_id_token_from_non_human_app_client_rejected(self):
        self._assert_machine_rejected({
            "auth_mode": "cognito", "sub": "abc-123", "email": "io@jreese.net",
            "token_use": "id", "aud": "some-other-app-client",
        })

    def test_legacy_claims_without_token_use_rejected(self):
        self._assert_machine_rejected({
            "auth_mode": "cognito", "sub": "abc-123", "email": "io@jreese.net",
            "aud": TEST_HUMAN_CLIENT_ID,
        })

    def test_no_configured_human_client_fails_closed(self):
        human_claims = dict(COGNITO_CLAIMS)
        with mock.patch.dict(os.environ, {"ESCALATION_HUMAN_CLIENT_IDS": ""}), \
             mock.patch.object(coordination_lambda, "COGNITO_CLIENT_ID", ""):
            resp, ddb, invoke = self._decide(human_claims)
        self.assertEqual(403, resp["statusCode"])
        ddb.update_item.assert_not_called()

    def test_human_id_token_accepted(self):
        resp, ddb, invoke = self._decide(COGNITO_CLAIMS)
        self.assertEqual(200, resp["statusCode"])
        invoke.assert_called_once()

    def test_aud_list_shape_accepted(self):
        claims = dict(COGNITO_CLAIMS)
        claims["aud"] = [TEST_HUMAN_CLIENT_ID]
        resp, ddb, invoke = self._decide(claims)
        self.assertEqual(200, resp["statusCode"])


class TestRenderDiff(unittest.TestCase):
    def test_arc_change_diff_from_live_target(self):
        diff = coordination_lambda._render_escalation_diff(
            _escalation_item(), _target_item())
        self.assertEqual("transition_type", diff["field"])
        self.assertEqual("github_pr_deploy", diff["current"])
        self.assertEqual("code_only", diff["requested"])
        self.assertEqual("in-progress", diff["target_snapshot"]["status"])
        self.assertNotIn("drift", diff)

    def test_override_diff_includes_field_values_delta(self):
        escalation = _escalation_item(
            mutation_type="direct_state_override",
            payload={"target_status": "closed",
                     "field_values": {"live_validation_evidence": "gamma ok"}})
        diff = coordination_lambda._render_escalation_diff(escalation, _target_item())
        self.assertEqual("status", diff["field"])
        self.assertEqual("closed", diff["requested"])
        self.assertEqual(
            "gamma ok", diff["field_values"]["live_validation_evidence"]["requested"])

    def test_drift_detected_when_expected_version_mismatches(self):
        escalation = _escalation_item(expected_version="sync_version:2")
        diff = coordination_lambda._render_escalation_diff(
            escalation, _target_item(sync_version=7))
        self.assertTrue(diff["drift"]["detected"])
        self.assertEqual("7", diff["drift"]["current_sync_version"])

    def test_drift_not_detected_when_expected_version_matches(self):
        escalation = _escalation_item(expected_version="sync_version:4")
        diff = coordination_lambda._render_escalation_diff(
            escalation, _target_item(sync_version=4))
        self.assertFalse(diff["drift"]["detected"])

    def test_missing_target_flagged(self):
        diff = coordination_lambda._render_escalation_diff(_escalation_item(), None)
        self.assertTrue(diff["target_missing"])


class TestEscalationsFeed(unittest.TestCase):
    def test_feed_attaches_fresh_diff_to_pending_and_splits_terminal(self):
        pending = _escalation_item()
        terminal = _escalation_item()
        terminal = dict(terminal, item_id="ENC-ESC-000",
                        record_id="escalation#ENC-ESC-000", status="denied",
                        created_at="2026-07-01T00:00:00Z")
        fake = mock.MagicMock()
        fake.query.return_value = {
            "Items": [_serialized(pending), _serialized(terminal)]}

        def _get_item(TableName=None, Key=None, **kwargs):
            record_id = (Key or {}).get("record_id", {}).get("S", "")
            if record_id.startswith("task#"):
                return {"Item": _serialized(_target_item())}
            return {}

        fake.get_item.side_effect = _get_item
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_escalations_feed(
                {"queryStringParameters": {"project_id": "enceladus"}}, COGNITO_CLAIMS)
        self.assertEqual(200, resp["statusCode"])
        body = json.loads(resp["body"])
        self.assertEqual(1, len(body["pending"]))
        self.assertEqual(1, len(body["terminal"]))
        self.assertEqual("ENC-ESC-001", body["pending"][0]["item_id"])
        self.assertEqual("code_only", body["pending"][0]["diff"]["requested"])
        self.assertNotIn("diff", body["terminal"][0])


if __name__ == "__main__":
    unittest.main()
