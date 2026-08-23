"""ENC-TSK-L95 / ENC-TSK-M12 / ENC-ISS-501: tests for the standalone escalation-decision authorizer."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

# ENC-TSK-M12: the human-principal gate requires a configured human app
# client; injected via env (read per-call by the module).
TEST_HUMAN_CLIENT_ID = "test-pwa-client-id"
os.environ.setdefault("ESCALATION_HUMAN_CLIENT_IDS", TEST_HUMAN_CLIENT_ID)

import lambda_function as authz  # noqa: E402


# ENC-TSK-M12: structurally human token shape -- id token, human app client,
# non-machine email domain.
ALLOWLISTED_CLAIMS = {
    "email": "ai@jreese.net", "sub": "abc-123", "auth_mode": "cognito",
    "token_use": "id", "aud": TEST_HUMAN_CLIENT_ID,
}
NOT_ALLOWLISTED_CLAIMS = {
    "email": "someone-else@jreese.net",
    "sub": "someone-else",
    "auth_mode": "cognito",
    "token_use": "id", "aud": TEST_HUMAN_CLIENT_ID,
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


class TestHumanPrincipalGate(unittest.TestCase):
    """ENC-TSK-M12 / ENC-ISS-501: structural human-principal enforcement.

    Machine token shapes must be denied even when their email IS on the
    allowlist -- the allowlist must never be the only barrier between a
    machine principal and an escalation approval.
    """

    ALLOWLIST = {"ai@jreese.net", "terminal-agent@enceladus.internal"}

    def setUp(self):
        authz._allowlist_cache["emails"] = None
        authz._allowlist_cache["fetched_at"] = 0.0

    def _run(self, claims):
        with mock.patch.object(authz, "_authenticate", return_value=(claims, None)), \
             mock.patch.object(authz, "_load_escalation_approver_allowlist",
                               return_value=self.ALLOWLIST):
            return authz.lambda_handler(_event(), None)

    def test_access_token_denied_even_when_email_allowlisted(self):
        resp = self._run({
            "email": "ai@jreese.net", "sub": "abc-123", "username": "ai",
            "token_use": "access", "client_id": TEST_HUMAN_CLIENT_ID,
        })
        self.assertFalse(resp["isAuthorized"])

    def test_client_credentials_m2m_token_denied(self):
        # client_credentials grant: token_use=access, bare client_id, no email.
        resp = self._run({
            "token_use": "access", "client_id": "m2m-agent-client-id",
            "scope": "enceladus/agent.write", "sub": "m2m-client-sub",
        })
        self.assertFalse(resp["isAuthorized"])

    def test_machine_operated_cognito_user_denied_even_when_allowlisted(self):
        # The observed ENC-ISS-501 attacker shape: a genuine human-pool ID
        # token minted for a machine-operated user, email on the allowlist.
        resp = self._run({
            "email": "terminal-agent@enceladus.internal",
            "sub": "c4b8e478-40e1-70ce-9f5d-caffd3e241df",
            "auth_mode": "cognito",
            "token_use": "id", "aud": TEST_HUMAN_CLIENT_ID,
        })
        self.assertFalse(resp["isAuthorized"])

    def test_id_token_from_non_human_app_client_denied(self):
        resp = self._run({
            "email": "ai@jreese.net", "sub": "abc-123", "auth_mode": "cognito",
            "token_use": "id", "aud": "some-other-app-client",
        })
        self.assertFalse(resp["isAuthorized"])

    def test_legacy_claims_without_token_use_denied(self):
        resp = self._run({
            "email": "ai@jreese.net", "sub": "abc-123", "auth_mode": "cognito",
            "aud": TEST_HUMAN_CLIENT_ID,
        })
        self.assertFalse(resp["isAuthorized"])

    def test_no_configured_human_client_fails_closed(self):
        with mock.patch.dict(os.environ, {"ESCALATION_HUMAN_CLIENT_IDS": "",
                                          "COGNITO_CLIENT_ID": ""}):
            resp = self._run(dict(ALLOWLISTED_CLAIMS))
        self.assertFalse(resp["isAuthorized"])

    def test_human_id_token_accepted(self):
        resp = self._run(dict(ALLOWLISTED_CLAIMS))
        self.assertTrue(resp["isAuthorized"])
        self.assertEqual("ai@jreese.net", resp["context"]["email"])

    def test_aud_list_shape_accepted(self):
        claims = dict(ALLOWLISTED_CLAIMS)
        claims["aud"] = [TEST_HUMAN_CLIENT_ID]
        resp = self._run(claims)
        self.assertTrue(resp["isAuthorized"])


if __name__ == "__main__":
    unittest.main()
