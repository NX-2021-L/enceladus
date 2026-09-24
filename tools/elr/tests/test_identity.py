"""Offline tests for elr_lib.identity (ENC-TSK-P75, T-B2 / FR-B4-4..7).

No network access -- urllib.request.urlopen is mocked via
unittest.mock.patch, exactly as tests/test_transport_internal.py does
(identity.py's register/claim/retire calls go through the SAME
elr_lib.transport.InternalClient.request(), so the same mock target
applies). The credential file and session cache paths are monkeypatched
to a tmp_path for every test that touches them, so no test EVER reads or
writes the real ~/.enceladus/credential.json or ~/.enceladus/session.json
on the machine running the suite.
"""

import io
import json
import os
import stat
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from elr_lib import config as elr_config
from elr_lib import identity as elr_identity
from elr_lib import transport as elr_transport

CREDENTIAL_ID = "CRED-abcdef0123456789abcdef0123456789"
AGENT_TYPE_ID = "ENC-AGT-7"
SESSION_ID = "ENC-SES-42"


class _FakeHttpResponse:
    def __init__(self, status, body):
        self._status = status
        self._body = body

    def getcode(self):
        return self._status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _http_error(code, body_dict):
    return urllib.error.HTTPError(
        url="https://jreese.net/api/v1/coordination/agents/sessions",
        code=code,
        msg="error",
        hdrs=None,
        fp=io.BytesIO(json.dumps(body_dict).encode("utf-8")),
    )


def _register_resp(session_id=SESSION_ID, agent_type_id=AGENT_TYPE_ID, status="allocated"):
    body = {
        "session": {
            "session_id": session_id,
            "agent_type_id": agent_type_id,
            "runtime": "elr",
            "parent_session_id": "root",
            "created_at": "2026-09-16T00:00:00Z",
            "claimed_at": "",
            "status": status,
            "credential_id": CREDENTIAL_ID,
        }
    }
    return _FakeHttpResponse(201, json.dumps(body).encode("utf-8"))


def _claim_resp(session_id=SESSION_ID, sci="SCI-11111111111111111111111111111111", sci_issued_at="2026-09-16T00:00:00Z", sci_ttl_seconds=86400):
    body = {
        "session": {"session_id": session_id, "status": "claimed"},
        "sci": sci,
        "sci_issued_at": sci_issued_at,
        "sci_ttl_seconds": sci_ttl_seconds,
    }
    return _FakeHttpResponse(200, json.dumps(body).encode("utf-8"))


def _retire_resp(session_id=SESSION_ID):
    body = {
        "session": {"session_id": session_id, "status": "retired"},
        "sci_revoked": True,
        "released_task_count": 0,
        "released_tasks": [],
    }
    return _FakeHttpResponse(200, json.dumps(body).encode("utf-8"))


def _sci_required_error(failure_mode):
    remediation = (
        "Obtain a Session Claim ID via coordination agent.claim (register->claim "
        "handshake, ENC-FTR-117 / ENC-ISS-441) and pass it as 'sci' on this request."
    )
    # Mirrors backend/lambda/checkout_service/lambda_function.py's _error():
    # error_envelope.details is ALSO spread onto the top level of the body.
    return _http_error(
        403,
        {
            "success": False,
            "error": f"SCI check failed: {failure_mode}",
            "error_envelope": {
                "code": "SCI_REQUIRED",
                "message": f"SCI check failed: {failure_mode}",
                "details": {"sci_failure_mode": failure_mode, "remediation": remediation},
            },
            "sci_failure_mode": failure_mode,
            "remediation": remediation,
        },
    )


def _credential_json(credential_id=CREDENTIAL_ID, agent_type_id=AGENT_TYPE_ID):
    return json.dumps({"credential_id": credential_id, "agent_type_id": agent_type_id})


def _write_credential_file(path: Path, mode: int, credential_id=CREDENTIAL_ID, agent_type_id=AGENT_TYPE_ID):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_credential_json(credential_id, agent_type_id), encoding="utf-8")
    os.chmod(str(path), mode)


class _TmpPathsMixin:
    """Every test class touching credential/session-cache files gets its
    own tmp_path-backed CREDENTIAL_FILE_PATH / SESSION_CACHE_FILE_PATH so
    the real ~/.enceladus files on the host are never read or written.
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        tmp_root = Path(self._tmpdir.name)
        self._credential_path = tmp_root / "credential.json"
        self._session_cache_path = tmp_root / "session.json"
        self._cred_patcher = patch.object(elr_identity, "CREDENTIAL_FILE_PATH", self._credential_path)
        self._cache_patcher = patch.object(elr_identity, "SESSION_CACHE_FILE_PATH", self._session_cache_path)
        self._cred_patcher.start()
        self._cache_patcher.start()
        self.addCleanup(self._cred_patcher.stop)
        self.addCleanup(self._cache_patcher.stop)
        self.addCleanup(self._tmpdir.cleanup)

    def _clean_env(self, extra=None):
        """A patch.dict(..., clear=True) env containing ONLY what the test
        explicitly asks for -- fully isolated from whatever the host
        shell happens to have set.
        """
        return patch.dict("os.environ", extra or {}, clear=True)


# ---------------------------------------------------------------------------
# AC-1: posture resolution, one class per posture
# ---------------------------------------------------------------------------


class PostureResolutionTests(_TmpPathsMixin, unittest.TestCase):
    def test_unknown_posture_when_nothing_configured(self):
        with self._clean_env():
            identity = elr_identity.resolve_identity()
        self.assertEqual(identity.posture, elr_identity.POSTURE_UNKNOWN)
        self.assertEqual(identity.session_id, "")
        self.assertEqual(identity.sci, "")

    def test_internal_key_posture_with_acs_own_env_name(self):
        with self._clean_env({"ENCELADUS_INTERNAL_API_KEY": "fixture-key"}):
            identity = elr_identity.resolve_identity()
        self.assertEqual(identity.posture, elr_identity.POSTURE_INTERNAL_KEY)

    def test_internal_key_posture_with_existing_env_name(self):
        # config.py's pre-existing chain (checked first) must keep working.
        with self._clean_env({"ENCELADUS_COORDINATION_INTERNAL_API_KEY": "fixture-key"}):
            identity = elr_identity.resolve_identity()
        self.assertEqual(identity.posture, elr_identity.POSTURE_INTERNAL_KEY)

    def test_credential_bound_registers_and_claims(self):
        responses = [_register_resp(), _claim_resp()]
        with self._clean_env({"ENCELADUS_AGENT_CREDENTIAL": _credential_json()}):
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
                identity = elr_identity.resolve_identity()

        self.assertEqual(mock_urlopen.call_count, 2)
        self.assertEqual(identity.posture, elr_identity.POSTURE_CREDENTIAL_BOUND)
        self.assertEqual(identity.session_id, SESSION_ID)
        self.assertTrue(identity.sci)
        self.assertEqual(identity.sci_ttl_seconds, 86400)
        self.assertEqual(identity.agent_type_id, AGENT_TYPE_ID)
        self.assertEqual(identity.credential_id, CREDENTIAL_ID)
        self.assertTrue(identity.registered_this_run)

    def test_credential_bound_register_payload_carries_credential_and_agent_type(self):
        responses = [_register_resp(), _claim_resp()]
        with self._clean_env({"ENCELADUS_AGENT_CREDENTIAL": _credential_json()}):
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
                elr_identity.resolve_identity()

        register_request = mock_urlopen.call_args_list[0][0][0]
        sent = json.loads(register_request.data.decode("utf-8"))
        self.assertEqual(sent["credential_id"], CREDENTIAL_ID)
        self.assertEqual(sent["agent_type_id"], AGENT_TYPE_ID)
        self.assertIn("runtime", sent)

    def test_credential_present_but_register_fails_falls_back_to_internal_key(self):
        responses = [_http_error(400, {"error": "credential_id not found"})]
        with self._clean_env(
            {"ENCELADUS_AGENT_CREDENTIAL": _credential_json(), "ENCELADUS_INTERNAL_API_KEY": "fixture-key"}
        ):
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
                identity = elr_identity.resolve_identity()

        self.assertEqual(identity.posture, elr_identity.POSTURE_INTERNAL_KEY)
        self.assertTrue(any("falling back" in a for a in identity.anomalies))

    def test_credential_present_but_register_fails_falls_back_to_unknown(self):
        responses = [_http_error(400, {"error": "credential_id not found"})]
        with self._clean_env({"ENCELADUS_AGENT_CREDENTIAL": _credential_json()}):
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
                identity = elr_identity.resolve_identity()

        self.assertEqual(identity.posture, elr_identity.POSTURE_UNKNOWN)

    def test_env_credential_takes_priority_over_file(self):
        _write_credential_file(self._credential_path, 0o600, credential_id="CRED-fromfile", agent_type_id="ENC-AGT-file")
        responses = [_register_resp(), _claim_resp()]
        with self._clean_env({"ENCELADUS_AGENT_CREDENTIAL": _credential_json()}):
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
                identity = elr_identity.resolve_identity()

        register_request = mock_urlopen.call_args_list[0][0][0]
        sent = json.loads(register_request.data.decode("utf-8"))
        self.assertEqual(sent["credential_id"], CREDENTIAL_ID)  # env, not the file's CRED-fromfile
        self.assertEqual(identity.credential_id, CREDENTIAL_ID)


# ---------------------------------------------------------------------------
# AC-1: 0600 file-permission refusal
# ---------------------------------------------------------------------------


class CredentialFilePermissionTests(_TmpPathsMixin, unittest.TestCase):
    def test_insecure_permissions_refused_and_falls_through_to_unknown(self):
        _write_credential_file(self._credential_path, 0o644)
        with self._clean_env():
            identity = elr_identity.resolve_identity()

        self.assertEqual(identity.posture, elr_identity.POSTURE_UNKNOWN)
        self.assertTrue(
            any("0600" in a and "chmod 600" in a for a in identity.anomalies),
            msg=f"expected a 0600 remediation anomaly, got {identity.anomalies!r}",
        )

    def test_insecure_permissions_file_is_never_even_opened_for_read(self):
        _write_credential_file(self._credential_path, 0o644)
        # Sabotage the file's readability at the OS level in a way that
        # would raise if anything tried to actually read() its bytes --
        # macOS/POSIX chmod 0o000 makes even the owner's read() fail.
        os.chmod(str(self._credential_path), 0o000)
        try:
            with self._clean_env():
                credential, warnings = elr_identity.load_agent_credential()
        finally:
            os.chmod(str(self._credential_path), 0o600)  # allow tmp cleanup
        self.assertIsNone(credential)
        self.assertTrue(any("0600" in w for w in warnings))

    def test_0600_permissions_are_accepted_and_used(self):
        _write_credential_file(self._credential_path, 0o600)
        responses = [_register_resp(), _claim_resp()]
        with self._clean_env():
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
                identity = elr_identity.resolve_identity()

        self.assertEqual(identity.posture, elr_identity.POSTURE_CREDENTIAL_BOUND)
        self.assertEqual(identity.credential_id, CREDENTIAL_ID)

    def test_missing_file_is_not_an_error(self):
        # self._credential_path deliberately never created.
        with self._clean_env():
            credential, warnings = elr_identity.load_agent_credential()
        self.assertIsNone(credential)
        self.assertEqual(warnings, [])


# ---------------------------------------------------------------------------
# AC-2: sci + write_source carriage on governed writes; local refusal on
# unknown-posture writes; reads always pass through unaffected.
# ---------------------------------------------------------------------------


class GovernedCallCarriageTests(unittest.TestCase):
    def setUp(self):
        self.client = elr_transport.InternalClient(elr_config.InternalProfileConfig(), timeout=5)

    def test_write_carries_sci_and_write_source_provider_when_credential_bound(self):
        identity = elr_identity.IdentityContext(
            posture=elr_identity.POSTURE_CREDENTIAL_BOUND,
            session_id=SESSION_ID,
            sci="SCI-carry-test",
            sci_issued_at="2026-09-16T00:00:00Z",
            sci_ttl_seconds=86400,
            agent_type_id=AGENT_TYPE_ID,
            credential_id=CREDENTIAL_ID,
        )
        fake_resp = _FakeHttpResponse(200, json.dumps({"ok": True}).encode("utf-8"))
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp) as mock_urlopen:
            status, body, meta = elr_identity.governed_call(
                identity, self.client, "POST", "tracker", "/create", payload={"field": "x"}
            )

        self.assertEqual(status, 200)
        self.assertFalse(meta["refused"])
        self.assertFalse(meta["retried"])
        sent_request = mock_urlopen.call_args[0][0]
        sent = json.loads(sent_request.data.decode("utf-8"))
        self.assertEqual(sent["sci"], "SCI-carry-test")
        self.assertEqual(sent["write_source"], {"provider": SESSION_ID})
        self.assertEqual(sent["field"], "x")

    def test_read_never_carries_sci_or_write_source(self):
        identity = elr_identity.IdentityContext(
            posture=elr_identity.POSTURE_CREDENTIAL_BOUND,
            session_id=SESSION_ID,
            sci="SCI-should-not-appear",
            sci_issued_at="2026-09-16T00:00:00Z",
            sci_ttl_seconds=86400,
        )
        fake_resp = _FakeHttpResponse(200, json.dumps({"ok": True}).encode("utf-8"))
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp) as mock_urlopen:
            elr_identity.governed_call(identity, self.client, "GET", "tracker", "/x")

        sent_request = mock_urlopen.call_args[0][0]
        self.assertIsNone(sent_request.data)  # GET: no body at all

    def test_write_refused_locally_when_posture_unknown(self):
        identity = elr_identity.IdentityContext(posture=elr_identity.POSTURE_UNKNOWN)
        with patch("elr_lib.transport.urllib.request.urlopen") as mock_urlopen:
            status, body, meta = elr_identity.governed_call(
                identity, self.client, "POST", "tracker", "/create", payload={"field": "x"}
            )

        mock_urlopen.assert_not_called()
        self.assertTrue(meta["refused"])
        self.assertEqual(meta["refusal_reason"], elr_identity.WRITE_REMEDIATION)
        self.assertEqual(
            meta["refusal_reason"],
            "provision an agent credential (ENC-FTR-074) or set ENCELADUS_INTERNAL_API_KEY",
        )

    def test_read_proceeds_even_when_posture_unknown(self):
        identity = elr_identity.IdentityContext(posture=elr_identity.POSTURE_UNKNOWN)
        fake_resp = _FakeHttpResponse(200, json.dumps({"ok": True}).encode("utf-8"))
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp) as mock_urlopen:
            status, body, meta = elr_identity.governed_call(identity, self.client, "GET", "tracker", "/x")

        mock_urlopen.assert_called_once()
        self.assertEqual(status, 200)
        self.assertFalse(meta["refused"])

    def test_write_refused_locally_when_posture_internal_key_is_not_refused(self):
        # internal-key IS a usable posture for writes (only "unknown" is
        # refused) -- sanity check the refusal is posture-specific.
        identity = elr_identity.IdentityContext(posture=elr_identity.POSTURE_INTERNAL_KEY)
        fake_resp = _FakeHttpResponse(200, json.dumps({"ok": True}).encode("utf-8"))
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp) as mock_urlopen:
            status, body, meta = elr_identity.governed_call(
                identity, self.client, "POST", "tracker", "/create", payload={"field": "x"}
            )
        mock_urlopen.assert_called_once()
        self.assertFalse(meta["refused"])


# ---------------------------------------------------------------------------
# AC-3: re-claim-once-and-retry on 403 SCI_REQUIRED
# ---------------------------------------------------------------------------


class ReclaimOnceTests(unittest.TestCase):
    def setUp(self):
        self.client = elr_transport.InternalClient(elr_config.InternalProfileConfig(), timeout=5)
        self.identity = elr_identity.IdentityContext(
            posture=elr_identity.POSTURE_CREDENTIAL_BOUND,
            session_id=SESSION_ID,
            sci="SCI-original",
            sci_issued_at="2026-09-16T00:00:00Z",
            sci_ttl_seconds=86400,
            agent_type_id=AGENT_TYPE_ID,
            credential_id=CREDENTIAL_ID,
        )

    def test_expired_sci_triggers_exactly_one_reclaim_and_retry(self):
        success = _FakeHttpResponse(200, json.dumps({"ok": True}).encode("utf-8"))
        responses = [_sci_required_error("expired_sci"), _claim_resp(sci="SCI-refreshed"), success]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
            status, body, meta = elr_identity.governed_call(
                self.identity, self.client, "POST", "tracker", "/create", payload={"field": "x"}
            )

        self.assertEqual(mock_urlopen.call_count, 3)
        self.assertEqual(status, 200)
        self.assertTrue(meta["retried"])
        self.assertEqual(self.identity.sci, "SCI-refreshed")
        self.assertEqual(self.identity.reclaim_count, 1)

        # The retried request must carry the REFRESHED sci, not the stale one.
        retry_request = mock_urlopen.call_args_list[2][0][0]
        sent = json.loads(retry_request.data.decode("utf-8"))
        self.assertEqual(sent["sci"], "SCI-refreshed")

    def test_revoked_sci_also_triggers_reclaim(self):
        success = _FakeHttpResponse(200, json.dumps({"ok": True}).encode("utf-8"))
        responses = [_sci_required_error("revoked_sci"), _claim_resp(sci="SCI-refreshed"), success]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
            status, _body, meta = elr_identity.governed_call(
                self.identity, self.client, "PUT", "document", "", payload={"field": "x"}
            )
        self.assertEqual(mock_urlopen.call_count, 3)
        self.assertEqual(status, 200)
        self.assertTrue(meta["retried"])

    def test_non_reclaimable_failure_mode_is_not_retried(self):
        responses = [_sci_required_error("missing_sci")]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
            status, _body, meta = elr_identity.governed_call(
                self.identity, self.client, "POST", "tracker", "/create", payload={"field": "x"}
            )
        self.assertEqual(mock_urlopen.call_count, 1)
        self.assertEqual(status, 403)
        self.assertFalse(meta["retried"])
        self.assertEqual(self.identity.reclaim_count, 0)

    def test_reclaim_is_attempted_at_most_once_even_if_retry_403s_again(self):
        responses = [
            _sci_required_error("expired_sci"),
            _claim_resp(sci="SCI-refreshed"),
            _sci_required_error("expired_sci"),  # retry ALSO 403s -- must not loop
        ]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
            status, _body, meta = elr_identity.governed_call(
                self.identity, self.client, "POST", "tracker", "/create", payload={"field": "x"}
            )
        self.assertEqual(mock_urlopen.call_count, 3)  # NOT 4+ -- exactly one reclaim
        self.assertEqual(status, 403)
        self.assertTrue(meta["retried"])
        self.assertEqual(self.identity.reclaim_count, 1)


# ---------------------------------------------------------------------------
# AC-3: --keep-session caching + reuse, and retire-on-exit
# ---------------------------------------------------------------------------


class KeepSessionCachingTests(_TmpPathsMixin, unittest.TestCase):
    def _credential_bound_identity(self):
        return elr_identity.IdentityContext(
            posture=elr_identity.POSTURE_CREDENTIAL_BOUND,
            session_id=SESSION_ID,
            sci="SCI-cache-me",
            sci_issued_at="2026-09-16T00:00:00Z",
            sci_ttl_seconds=86400,
            agent_type_id=AGENT_TYPE_ID,
            credential_id=CREDENTIAL_ID,
        )

    def test_keep_session_writes_0600_cache_and_skips_retire(self):
        identity = self._credential_bound_identity()
        with patch("elr_lib.transport.urllib.request.urlopen") as mock_urlopen:
            elr_identity.finalize_identity(identity, None, keep_session=True, profile_name="internal", timeout=5)

        mock_urlopen.assert_not_called()  # no retire call
        self.assertTrue(self._session_cache_path.exists())
        mode = stat.S_IMODE(self._session_cache_path.stat().st_mode)
        self.assertEqual(mode, 0o600)
        cached = json.loads(self._session_cache_path.read_text(encoding="utf-8"))
        self.assertEqual(cached["session_id"], SESSION_ID)
        self.assertEqual(cached["sci"], "SCI-cache-me")
        self.assertEqual(cached["credential_id"], CREDENTIAL_ID)

    def test_fresh_cached_session_is_reused_without_reregistering(self):
        identity = self._credential_bound_identity()
        elr_identity._write_session_cache(identity)  # simulate an earlier --keep-session run

        with self._clean_env({"ENCELADUS_AGENT_CREDENTIAL": _credential_json()}):
            with patch("elr_lib.transport.urllib.request.urlopen") as mock_urlopen:
                resolved = elr_identity.resolve_identity()

        mock_urlopen.assert_not_called()  # no register/claim network call
        self.assertEqual(resolved.posture, elr_identity.POSTURE_CREDENTIAL_BOUND)
        self.assertEqual(resolved.session_id, SESSION_ID)
        self.assertEqual(resolved.sci, "SCI-cache-me")
        self.assertFalse(resolved.registered_this_run)

    def test_expired_cached_session_triggers_fresh_register_and_claim(self):
        stale = self._credential_bound_identity()
        stale.sci_issued_at = "2000-01-01T00:00:00Z"  # ancient -- well past any TTL
        elr_identity._write_session_cache(stale)

        responses = [_register_resp(session_id="ENC-SES-FRESH"), _claim_resp(session_id="ENC-SES-FRESH", sci="SCI-fresh")]
        with self._clean_env({"ENCELADUS_AGENT_CREDENTIAL": _credential_json()}):
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
                resolved = elr_identity.resolve_identity()

        self.assertEqual(mock_urlopen.call_count, 2)
        self.assertEqual(resolved.session_id, "ENC-SES-FRESH")
        self.assertTrue(resolved.registered_this_run)

    def test_cache_for_a_different_credential_id_is_not_reused(self):
        stale = self._credential_bound_identity()
        stale.credential_id = "CRED-someone-elses"
        elr_identity._write_session_cache(stale)

        responses = [_register_resp(), _claim_resp()]
        with self._clean_env({"ENCELADUS_AGENT_CREDENTIAL": _credential_json()}):  # CREDENTIAL_ID, not "CRED-someone-elses"
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
                resolved = elr_identity.resolve_identity()

        self.assertEqual(mock_urlopen.call_count, 2)
        self.assertTrue(resolved.registered_this_run)


class RetireOnExitTests(_TmpPathsMixin, unittest.TestCase):
    def test_finalize_retires_session_when_keep_session_is_false(self):
        identity = elr_identity.IdentityContext(
            posture=elr_identity.POSTURE_CREDENTIAL_BOUND,
            session_id=SESSION_ID,
            sci="SCI-to-retire",
            sci_issued_at="2026-09-16T00:00:00Z",
            sci_ttl_seconds=86400,
            agent_type_id=AGENT_TYPE_ID,
            credential_id=CREDENTIAL_ID,
        )
        elr_identity._write_session_cache(identity)
        self.assertTrue(self._session_cache_path.exists())

        client = elr_transport.InternalClient(elr_config.InternalProfileConfig(), timeout=5)
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=_retire_resp()) as mock_urlopen:
            elr_identity.finalize_identity(identity, client, keep_session=False, profile_name="internal", timeout=5)

        mock_urlopen.assert_called_once()
        sent_request = mock_urlopen.call_args[0][0]
        self.assertIn(f"/agents/sessions/{SESSION_ID}/retire", sent_request.full_url)
        # The stale cache must not survive a retire -- it would let a
        # later invocation try to reuse an already-retired session id.
        self.assertFalse(self._session_cache_path.exists())

    def test_finalize_is_a_noop_for_non_credential_bound_posture(self):
        for posture in (elr_identity.POSTURE_INTERNAL_KEY, elr_identity.POSTURE_UNKNOWN):
            identity = elr_identity.IdentityContext(posture=posture)
            with patch("elr_lib.transport.urllib.request.urlopen") as mock_urlopen:
                elr_identity.finalize_identity(identity, None, keep_session=False, profile_name="internal", timeout=5)
            mock_urlopen.assert_not_called()

    def test_finalize_retire_failure_is_recorded_not_raised(self):
        identity = elr_identity.IdentityContext(
            posture=elr_identity.POSTURE_CREDENTIAL_BOUND,
            session_id=SESSION_ID,
            sci="SCI-x",
            sci_issued_at="2026-09-16T00:00:00Z",
            sci_ttl_seconds=86400,
        )
        client = elr_transport.InternalClient(elr_config.InternalProfileConfig(), timeout=5)
        with patch(
            "elr_lib.transport.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            elr_identity.finalize_identity(identity, client, keep_session=False, profile_name="internal", timeout=5)
        self.assertTrue(any("retire-failed" in a for a in identity.anomalies))


if __name__ == "__main__":
    unittest.main()
