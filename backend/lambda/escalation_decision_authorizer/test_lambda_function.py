"""ENC-TSK-L95 / ENC-ISS-501: tests for the standalone escalation-decision authorizer."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

import lambda_function as authz  # noqa: E402


ALLOWLISTED_CLAIMS = {"email": "ai@jreese.net", "sub": "abc-123", "auth_mode": "cognito"}
NOT_ALLOWLISTED_CLAIMS = {
    "email": "terminal-agent@enceladus.internal",
    "sub": "c4b8e478-40e1-70ce-9f5d-caffd3e241df",
    "auth_mode": "cognito",
}
INTERNAL_KEY_CLAIMS = {"auth_mode": "internal-key"}


def _event():
    return {"requestContext": {"requestId": "test-req-1"}, "headers": {}}


class TestEscalationDecisionAuthorizer(unittest.TestCase):
    def setUp(self):
        authz._allowlist_cache["emails"] = None
        authz._allowlist_cache["fetched_at"] = 0.0

    def test_allowlisted_identity_is_authorized(self):
        with mock.patch.object(authz, "_authenticate", return_value=(ALLOWLISTED_CLAIMS, None)), \
             mock.patch.object(authz, "_load_escalation_approver_allowlist", return_value={"ai@jreese.net"}):
            resp = authz.lambda_handler(_event(), None)
        self.assertTrue(resp["isAuthorized"])
        self.assertEqual("ai@jreese.net", resp["context"]["email"])

    def test_non_allowlisted_cognito_identity_is_denied(self):
        with mock.patch.object(authz, "_authenticate", return_value=(NOT_ALLOWLISTED_CLAIMS, None)), \
             mock.patch.object(authz, "_load_escalation_approver_allowlist", return_value={"ai@jreese.net"}):
            resp = authz.lambda_handler(_event(), None)
        self.assertFalse(resp["isAuthorized"])

    def test_internal_key_auth_mode_has_no_email_and_is_denied(self):
        with mock.patch.object(authz, "_authenticate", return_value=(INTERNAL_KEY_CLAIMS, None)), \
             mock.patch.object(authz, "_load_escalation_approver_allowlist", return_value={"ai@jreese.net"}):
            resp = authz.lambda_handler(_event(), None)
        self.assertFalse(resp["isAuthorized"])

    def test_authentication_failure_is_denied(self):
        with mock.patch.object(authz, "_authenticate", return_value=(None, {"statusCode": 401})):
            resp = authz.lambda_handler(_event(), None)
        self.assertFalse(resp["isAuthorized"])

    def test_allowlist_fetch_failure_fails_closed(self):
        with mock.patch.object(authz, "_authenticate", return_value=(ALLOWLISTED_CLAIMS, None)), \
             mock.patch.object(authz, "boto3") as fake_boto3:
            fake_boto3.client.return_value.get_object.side_effect = RuntimeError("boom")
            resp = authz.lambda_handler(_event(), None)
        self.assertFalse(resp["isAuthorized"])

    def test_parses_real_document_format(self):
        doc_body = (
            "# Escalation Approver Allowlist\n\n"
            "```yaml\n"
            "approvers:\n"
            "  - email: \"ai@jreese.net\"\n"
            "    added_at: \"2026-07-07T12:00:00Z\"\n"
            "```\n"
        )
        with mock.patch.object(authz, "boto3") as fake_boto3:
            fake_body = mock.MagicMock()
            fake_body.read.return_value = doc_body.encode("utf-8")
            fake_boto3.client.return_value.get_object.return_value = {"Body": fake_body}
            emails = authz._load_escalation_approver_allowlist()
        self.assertEqual({"ai@jreese.net"}, emails)


if __name__ == "__main__":
    unittest.main()
