"""Offline tests for elr_smoke.py's CLI parser and digest-only output
contract. No network access -- urllib.request.urlopen is mocked.
"""

import contextlib
import io
import json
import unittest
from unittest.mock import patch

import elr_smoke


class AllowAbbrevTests(unittest.TestCase):
    """ALL ELR CLIs must set allow_abbrev=False (per the ELR spec) so a
    partial flag like --prof can never silently match --profile.
    """

    def test_parser_has_allow_abbrev_false(self):
        parser = elr_smoke.build_parser()
        self.assertFalse(parser.allow_abbrev)

    def test_abbreviated_flag_is_rejected(self):
        parser = elr_smoke.build_parser()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(stderr):
                # "--prof" is an unambiguous prefix of "--profile" -- with
                # allow_abbrev=True argparse would accept it silently.
                parser.parse_args(["--prof", "prod"])

    def test_full_flag_name_is_accepted(self):
        # ENC-TSK-P77: --profile is now the ENVIRONMENT profile (elr_lib.profiles),
        # not elr_lib.config's transport profile -- "v4-gamma" is a valid choice.
        parser = elr_smoke.build_parser()
        args = parser.parse_args(["--profile", "v4-gamma", "--timeout", "7"])
        self.assertEqual(args.profile, "v4-gamma")
        self.assertEqual(args.timeout, 7)

    def test_default_profile_is_prod(self):
        parser = elr_smoke.build_parser()
        args = parser.parse_args([])
        self.assertEqual(args.profile, "prod")
        self.assertEqual(args.timeout, 15)
        self.assertFalse(args.all_profiles)

    def test_unsupported_profile_choice_rejected(self):
        parser = elr_smoke.build_parser()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(stderr):
                parser.parse_args(["--profile", "not-a-real-environment"])

    def test_all_profiles_flag_accepted(self):
        parser = elr_smoke.build_parser()
        args = parser.parse_args(["--all-profiles"])
        self.assertTrue(args.all_profiles)


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


class EnvironmentProfileSmokeTests(unittest.TestCase):
    """ENC-TSK-P77 AC-2/AC-4: profile/governance_hash fields (the two
    ENC-TSK-P90 prefix-resolution fields were removed by ENC-TSK-Q10),
    environment selection by flag and env var, and per-profile digest
    emission via --all-profiles (network mocked).
    """

    def _fake_response(self, governance_hash="abc123"):
        body = json.dumps({"dynamodb": "ok", "s3": "ok", "governance_hash": governance_hash}).encode("utf-8")
        return _FakeHttpResponse(200, body)

    def test_run_health_smoke_reports_environment_profile_and_governance_hash(self):
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=self._fake_response()):
            digest = elr_smoke.run_health_smoke("v4-gamma", 5)
        self.assertEqual(digest["profile"], "v4-gamma")
        self.assertEqual(digest["governance_hash"], "abc123")
        # ENC-TSK-Q10: no prefix-resolution fields on any digest -- ELR
        # holds no prefix map, so there is nothing to report.
        self.assertNotIn("prefix_map_source", digest)
        self.assertNotIn("unclassified", digest)

    def test_default_environment_profile_is_prod(self):
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=self._fake_response()):
            digest = elr_smoke.run_health_smoke("prod", 5)
        self.assertEqual(digest["profile"], "prod")

    def test_unknown_environment_profile_raises(self):
        with self.assertRaises(ValueError):
            elr_smoke.run_health_smoke("not-a-real-environment", 5)

    def test_env_var_selects_environment_profile_via_main(self):
        import os

        stdout = io.StringIO()
        with patch.dict(os.environ, {"ENCELADUS_PROFILE": "v4-gamma"}), patch(
            "elr_lib.transport.urllib.request.urlopen", return_value=self._fake_response()
        ):
            with contextlib.redirect_stdout(stdout):
                # No --profile flag passed -- argparse default "prod" wins
                # over ENCELADUS_PROFILE at the CLI layer; this test
                # documents that CLI --profile (when given) is what's
                # threaded through, while get_environment_profile() itself
                # (used when no CLI value is passed) honors the env var.
                from elr_lib import profiles as elr_profiles_mod

                resolved = elr_profiles_mod.get_environment_profile(None)
        self.assertEqual(resolved.name, "v4-gamma")

    def test_all_profiles_emits_one_digest_per_profile(self):
        from elr_lib import profiles as elr_profiles_mod

        stdout = io.StringIO()
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=self._fake_response()):
            with contextlib.redirect_stdout(stdout):
                exit_code = elr_smoke.main(["--all-profiles"])
        lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), len(elr_profiles_mod.VALID_ENVIRONMENT_PROFILES))
        seen_profiles = {json.loads(line)["profile"] for line in lines}
        self.assertEqual(seen_profiles, set(elr_profiles_mod.VALID_ENVIRONMENT_PROFILES))
        self.assertEqual(exit_code, 0)

    def test_all_profiles_nonzero_exit_when_one_profile_fails(self):
        import urllib.error

        call_count = {"n": 0}

        def _side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return self._fake_response()
            raise urllib.error.URLError("connection refused")

        stdout = io.StringIO()
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=_side_effect):
            with contextlib.redirect_stdout(stdout):
                exit_code = elr_smoke.main(["--all-profiles"])
        self.assertEqual(exit_code, 1)


class RunHealthSmokeTests(unittest.TestCase):
    def test_digest_only_output_on_success(self):
        body = json.dumps({"dynamodb": "ok", "s3": "ok"}).encode("utf-8")
        fake_resp = _FakeHttpResponse(200, body)
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
            digest = elr_smoke.run_health_smoke("prod", 5)

        self.assertTrue(digest["ok"])
        self.assertEqual(digest["status"], 200)
        self.assertEqual(digest["operation"], "elr_smoke.health_check")
        # ENC-TSK-P75 AC-4: identity_posture is now elr_lib.identity's
        # resolved posture (credential-bound/internal-key/unknown), never
        # the transport-layer "server-held-keys" classification.
        self.assertIn(digest["identity_posture"], ("credential-bound", "internal-key", "unknown"))
        self.assertEqual(digest["counts"], {"dynamodb": "ok", "s3": "ok"})
        # digest-first: the raw body dict must never leak verbatim as a
        # top-level key other than the summarized "counts".
        self.assertNotIn("dynamodb", digest)
        self.assertNotIn("s3", digest)

    def test_digest_is_json_serializable_and_stable_shape(self):
        body = json.dumps({"dynamodb": "ok", "s3": "ok"}).encode("utf-8")
        fake_resp = _FakeHttpResponse(200, body)
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
            digest = elr_smoke.run_health_smoke("prod", 5)
        serialized = json.dumps(digest, sort_keys=True)
        reparsed = json.loads(serialized)
        self.assertEqual(reparsed, digest)

    def test_main_prints_single_json_line_and_exit_code(self):
        body = json.dumps({"dynamodb": "ok", "s3": "ok"}).encode("utf-8")
        fake_resp = _FakeHttpResponse(200, body)
        stdout = io.StringIO()
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
            with contextlib.redirect_stdout(stdout):
                exit_code = elr_smoke.main([])
        self.assertEqual(exit_code, 0)
        lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertTrue(parsed["ok"])

    def test_main_nonzero_exit_on_failure_status(self):
        import urllib.error

        stdout = io.StringIO()
        with patch(
            "elr_lib.transport.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            with contextlib.redirect_stdout(stdout):
                exit_code = elr_smoke.main([])
        self.assertEqual(exit_code, 1)
        parsed = json.loads(stdout.getvalue().strip())
        self.assertFalse(parsed["ok"])
        self.assertEqual(parsed["status"], 0)

    def test_digest_carries_ca_bundle_on_success(self):
        # ENC-TSK-P76 AC-1: ca_bundle:{source,path} on every digest.
        body = json.dumps({"dynamodb": "ok", "s3": "ok"}).encode("utf-8")
        fake_resp = _FakeHttpResponse(200, body)
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
            digest = elr_smoke.run_health_smoke("prod", 5)
        self.assertIn("ca_bundle", digest)
        self.assertIn("source", digest["ca_bundle"])
        self.assertIn("path", digest["ca_bundle"])
        self.assertNotIn("remediation", digest)

    def test_tls_unresolved_fails_fast_with_exit_code_4(self):
        # ENC-TSK-P76 AC-2: a "missing" CA bundle never attempts urlopen,
        # surfaces REMEDIATION_MESSAGE as the error, and exits 4.
        import elr_lib.tls as elr_tls_mod

        stdout = io.StringIO()
        with patch.object(
            elr_tls_mod, "resolve_ca_bundle", return_value=elr_tls_mod.CaBundleResolution("missing", None)
        ), patch("elr_lib.transport.urllib.request.urlopen") as mock_urlopen:
            with contextlib.redirect_stdout(stdout):
                exit_code = elr_smoke.main([])
        mock_urlopen.assert_not_called()
        self.assertEqual(exit_code, 4)
        parsed = json.loads(stdout.getvalue().strip())
        self.assertFalse(parsed["ok"])
        self.assertEqual(parsed["remediation"], elr_tls_mod.REMEDIATION_MESSAGE)
        self.assertEqual(parsed["ca_bundle"], {"source": "missing", "path": None})


if __name__ == "__main__":
    unittest.main()
