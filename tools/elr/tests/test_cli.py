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
                parser.parse_args(["--prof", "internal"])

    def test_full_flag_name_is_accepted(self):
        parser = elr_smoke.build_parser()
        args = parser.parse_args(["--profile", "internal", "--timeout", "7"])
        self.assertEqual(args.profile, "internal")
        self.assertEqual(args.timeout, 7)

    def test_default_profile_is_internal(self):
        parser = elr_smoke.build_parser()
        args = parser.parse_args([])
        self.assertEqual(args.profile, "internal")
        self.assertEqual(args.timeout, 15)

    def test_unsupported_profile_choice_rejected(self):
        parser = elr_smoke.build_parser()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(stderr):
                parser.parse_args(["--profile", "mcp-http"])


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


class RunHealthSmokeTests(unittest.TestCase):
    def test_digest_only_output_on_success(self):
        body = json.dumps({"dynamodb": "ok", "s3": "ok"}).encode("utf-8")
        fake_resp = _FakeHttpResponse(200, body)
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
            digest = elr_smoke.run_health_smoke("internal", 5)

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
            digest = elr_smoke.run_health_smoke("internal", 5)
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
            digest = elr_smoke.run_health_smoke("internal", 5)
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
