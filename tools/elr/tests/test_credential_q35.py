"""ENC-TSK-Q35 (ENC-ISS-831): ELR's durable credential.

Before Q35 the only key ELR could find on a host without an FTR-074
credential lived in ~/.claude.json, scraped by a hand-installed sh wrapper:
direct ``python3 elr_<sub>.py`` calls 401'd, and elr_smoke reported ok:true
with no credential at all because health never authenticates. These tests
pin the replacement: an owner-only ELR key file resolved in elr_lib, a local
no-network refusal (exit 7), an authenticated smoke, and a managed launcher.
Offline: urlopen is mocked, except the launcher-parity test, which talks to
a stub HTTP server on 127.0.0.1.
"""

from __future__ import annotations

import contextlib
import http.server
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import elr_batch_get
import elr_doc_digest
import elr_doc_get
import elr_doc_patch
import elr_list
import elr_provision_key
import elr_smoke
import elr_sync
from elr_lib import config as elr_config
from elr_lib import identity as elr_identity

_URLOPEN = "elr_lib.transport.urllib.request.urlopen"
_ELR_ROOT = Path(__file__).resolve().parent.parent
_SECRET = "q35-fixture-key-0123456789abcdef"


class _Resp:
    def __init__(self, status, body):
        self._status, self._body = status, body

    def getcode(self):
        return self._status

    def read(self):
        return json.dumps(self._body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _http_error(code):
    return urllib.error.HTTPError("https://jreese.net/api/v1/tracker", code, "err", None, io.BytesIO(b"{}"))


def _write_key(path: Path, value: str = _SECRET, mode: int = 0o600) -> Path:
    path.write_text(value + "\n", encoding="utf-8")
    os.chmod(path, mode)
    return path


class _KeyFileCase(unittest.TestCase):
    """Fully isolated env: nothing but what the test sets, and a key-file
    path inside a temp dir (absent unless the test writes it)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.key_path = self.tmp / "internal_key"
        isolated = {"ENCELADUS_ELR_KEY_FILE": str(self.key_path), "HOME": str(self.tmp)}
        if os.environ.get("SSL_CERT_FILE"):  # interpreters without certifi need a CA bundle
            isolated["SSL_CERT_FILE"] = os.environ["SSL_CERT_FILE"]
        self._env = patch.dict("os.environ", isolated, clear=True)
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)


class KeyFileResolutionTests(_KeyFileCase):
    def test_key_file_is_used_when_no_env_key(self):
        _write_key(self.key_path)
        value, source = elr_config.resolve_common_internal_key()
        self.assertEqual((value, source), (_SECRET, "key_file"))
        self.assertEqual(elr_config.get_profile("internal").key_for("tracker"), _SECRET)

    def test_explicit_env_key_wins_over_key_file(self):
        _write_key(self.key_path)
        with patch.dict("os.environ", {"ENCELADUS_INTERNAL_API_KEY": "env-key-value-0123456789"}):
            self.assertEqual(elr_config.resolve_common_internal_key(), ("env-key-value-0123456789", "ENCELADUS_INTERNAL_API_KEY"))

    def test_group_or_world_readable_key_file_is_ignored_with_warning(self):
        _write_key(self.key_path, mode=0o644)
        value, warnings = elr_config.read_elr_key_file()
        self.assertEqual(value, "")
        self.assertTrue(any("elr_key_file_mode_insecure" in w for w in warnings))
        self.assertTrue(all(_SECRET not in w for w in warnings))
        self.assertEqual(elr_config.resolve_common_internal_key(), ("", "none"))

    def test_read_only_owner_mode_0400_is_accepted(self):
        _write_key(self.key_path, mode=0o400)
        self.assertEqual(elr_config.resolve_common_internal_key()[1], "key_file")

    def test_empty_key_file_warns(self):
        _write_key(self.key_path, value="")
        self.assertIn("elr_key_file_empty", elr_config.read_elr_key_file()[1][0])

    def test_claude_json_is_never_a_key_source(self):
        (self.tmp / ".claude.json").write_text(
            json.dumps({"mcpServers": {"enceladus": {"env": {"ENCELADUS_COORDINATION_INTERNAL_API_KEY": _SECRET}}}})
        )
        self.assertEqual(elr_config.resolve_common_internal_key(), ("", "none"))

    def test_repr_never_contains_the_key(self):
        _write_key(self.key_path)
        self.assertNotIn(_SECRET, repr(elr_config.get_profile("internal")))


class PostureTests(_KeyFileCase):
    def test_key_file_alone_gives_internal_key_posture(self):
        _write_key(self.key_path)
        identity = elr_identity.resolve_identity()
        self.assertEqual(identity.posture, elr_identity.POSTURE_INTERNAL_KEY)
        self.assertEqual(elr_identity.internal_key_source(), "key_file")

    def test_insecure_key_file_surfaces_as_anomaly_not_silent_unknown(self):
        _write_key(self.key_path, mode=0o640)
        identity = elr_identity.resolve_identity()
        self.assertEqual(identity.posture, elr_identity.POSTURE_UNKNOWN)
        self.assertTrue(any("elr_key_file_mode_insecure" in a for a in identity.anomalies))


class LocalRefusalTests(_KeyFileCase):
    """AC-4: an auth-required read with no credential exits 7 and sends
    nothing over the network."""

    CASES = [
        ("list", elr_list.main, ["--project", "enceladus", "--census"]),
        ("batch_get", elr_batch_get.main, ["--ids", "ENC-TSK-1", "--json"]),
        ("doc_get", elr_doc_get.main, ["DOC-0123456789AB", "--out-dir", "{tmp}"]),
        ("doc_digest", elr_doc_digest.main, ["DOC-0123456789AB", "--docs-dir", "{tmp}"]),
        (
            "doc_patch",
            elr_doc_patch.main,
            ["--doc", "DOC-0123456789AB", "--anchor", "A", "--op", "replace", "--body-file", "{tmp}/body.md", "--dry-run", "--docs-dir", "{tmp}"],
        ),
    ]

    def test_every_read_refuses_locally_with_exit_7(self):
        for name, main, argv in self.CASES:
            with self.subTest(script=name):
                argv = [a.replace("{tmp}", str(self.tmp)) for a in argv]
                stdout = io.StringIO()
                with patch(_URLOPEN) as urlopen, contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                    try:
                        code = main(argv)
                    except SystemExit as exc:  # argparse drift would show up here
                        self.fail(f"{name}: argparse rejected {argv}: {exc}")
                urlopen.assert_not_called()
                self.assertEqual(code, elr_config.EXIT_CODE_NO_CREDENTIAL, name)
                digest = json.loads(stdout.getvalue().strip().splitlines()[-1])
                self.assertFalse(digest["ok"])
                self.assertEqual(digest["status"], elr_config.NO_CREDENTIAL_STATUS)
                self.assertIn(elr_config.NO_CREDENTIAL_ANOMALY, digest["anomalies"])
                self.assertIn("elr_provision_key.py", digest["remediation"])

    def test_refusal_helper_is_none_once_the_key_file_exists(self):
        _write_key(self.key_path)
        self.assertIsNone(elr_identity.credential_refusal("x", "tracker"))


class AuthenticatedSmokeTests(_KeyFileCase):
    """AC-5: health alone can no longer make the smoke green."""

    HEALTH = _Resp(200, {"dynamodb": "ok", "s3": "ok", "governance_hash": "gh"})

    def _smoke(self, responses):
        stdout = io.StringIO()
        with patch(_URLOPEN, side_effect=responses) as urlopen, contextlib.redirect_stdout(stdout):
            code = elr_smoke.main([])
        return code, json.loads(stdout.getvalue().strip()), urlopen

    def test_no_credential_fails_after_health_without_probing(self):
        code, digest, urlopen = self._smoke([self.HEALTH])
        self.assertEqual(code, elr_config.EXIT_CODE_NO_CREDENTIAL)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["identity_posture"], "unknown")
        self.assertIn(elr_config.NO_CREDENTIAL_ANOMALY, digest["anomalies"])
        self.assertEqual(urlopen.call_count, 1)  # health only

    def test_accepted_key_probe_404_is_ok(self):
        _write_key(self.key_path)
        code, digest, urlopen = self._smoke([self.HEALTH, _http_error(404)])
        self.assertEqual(code, 0)
        self.assertTrue(digest["ok"])
        self.assertEqual(digest["auth_probe"], {"status": 404, "ok": True})
        self.assertEqual(digest["key_source"], "key_file")
        sent = urlopen.call_args_list[1].args[0]
        self.assertIn("/tracker/_/task/", sent.full_url)
        self.assertEqual(sent.get_header("X-coordination-internal-key"), _SECRET)
        self.assertNotIn(_SECRET, json.dumps(digest))

    def test_rejected_key_fails_the_smoke(self):
        _write_key(self.key_path)
        code, digest, _ = self._smoke([self.HEALTH, _http_error(401)])
        self.assertEqual(code, 1)
        self.assertFalse(digest["ok"])
        self.assertIn("auth_probe_rejected_http_401", digest["anomalies"])


class BatchAuthStatusTests(_KeyFileCase):
    def test_all_forbidden_batch_reports_auth_status_not_502(self):
        _write_key(self.key_path)
        with patch(_URLOPEN, side_effect=[_http_error(403), _http_error(403)]):
            digest = elr_batch_get.run_batch_get(["ENC-TSK-1", "ENC-TSK-2"], "prod", 5)
        self.assertEqual(digest["status"], 403)


class ProvisionKeyTests(_KeyFileCase):
    def _run(self, stdin_text, *argv):
        stdout = io.StringIO()
        with patch("sys.stdin", io.StringIO(stdin_text)), contextlib.redirect_stdout(stdout):
            code = elr_provision_key.main(list(argv))
        return code, stdout.getvalue()

    def test_writes_owner_only_file_and_never_prints_the_key(self):
        code, out = self._run(_SECRET + "\n")
        self.assertEqual(code, 0)
        self.assertNotIn(_SECRET, out)
        self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)
        self.assertEqual(elr_config.resolve_common_internal_key(), (_SECRET, "key_file"))
        self.assertEqual(json.loads(out)["key_source"], "key_file")

    def test_refuses_to_overwrite_without_force(self):
        _write_key(self.key_path, value="original-key-0123456789")
        code, out = self._run(_SECRET)
        self.assertEqual(code, 1)
        self.assertIn("key_file_exists", out)
        self.assertEqual(elr_config.read_elr_key_file()[0], "original-key-0123456789")
        code, _ = self._run(_SECRET, "--force")
        self.assertEqual((code, elr_config.read_elr_key_file()[0]), (0, _SECRET))

    def test_rejects_empty_and_whitespace_keys(self):
        for bad in ("", "two tokens-0123456789"):
            with self.subTest(bad=bad):
                code, out = self._run(bad)
                self.assertEqual(code, 1)
                self.assertFalse(self.key_path.exists())
                self.assertNotIn("0123456789", out)


class LauncherInstallTests(unittest.TestCase):
    """AC-3: the launcher is a manifest artifact and replaces only the
    legacy key-scraping wrapper."""

    def test_launcher_is_in_the_runtime_set(self):
        names = {p.name for p in elr_sync.collect_runtime_files(_ELR_ROOT)}
        self.assertIn("elr", names)
        self.assertIn("elr_provision_key.py", names)
        self.assertTrue(elr_sync._matches_runtime_pattern("tools/elr/elr"))

    def test_committed_launcher_handles_no_credential(self):
        text = (_ELR_ROOT / "elr").read_text(encoding="utf-8")
        for forbidden in (".claude.json", "INTERNAL_API_KEY", "mcpServers"):
            self.assertNotIn(forbidden, text)
        self.assertTrue(os.access(_ELR_ROOT / "elr", os.X_OK))

    def _install(self, existing=None):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(tmp)], check=False))
        dest = tmp / "bin"
        dest.mkdir()
        (dest / "elr").write_text("#!/bin/sh\n")
        link = tmp / "elr"
        if existing == "legacy":
            link.write_text("#!/bin/sh\n# ELR convenience wrapper (ENC-FTR-134). Sources the operational internal key\n")
        elif existing == "other":
            link.write_text("#!/bin/sh\necho mine\n")
        elif existing == "symlink":
            link.symlink_to(tmp / "nowhere")
        result = elr_sync._install_launcher(dest)
        return dest, link, result

    def test_replaces_the_legacy_wrapper_with_a_link(self):
        dest, link, result = self._install("legacy")
        self.assertTrue(link.is_symlink())
        self.assertEqual(Path(os.readlink(link)), dest / "elr")
        self.assertTrue(result["replaced_legacy"])
        self.assertEqual((dest / ".elr-python").read_text().strip(), sys.executable)

    def test_refreshes_an_existing_symlink(self):
        dest, link, result = self._install("symlink")
        self.assertEqual(Path(os.readlink(link)), dest / "elr")
        self.assertFalse(result["replaced_legacy"])

    def test_leaves_an_unmanaged_file_alone(self):
        _dest, link, result = self._install("other")
        self.assertFalse(link.is_symlink())
        self.assertIn("echo mine", link.read_text())
        self.assertTrue(any("launcher_link_skipped_unmanaged_file" in a for a in result["anomalies"]))


class _StubHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path.startswith("/health"):
            body, code = {"dynamodb": "ok", "s3": "ok", "governance_hash": "stub"}, 200
        elif self.headers.get("X-Coordination-Internal-Key") == _SECRET:
            body, code = {"error": "not found"}, 404
        else:
            body, code = {"error": "Authentication required"}, 401
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class LauncherParityTests(unittest.TestCase):
    """AC-3: the launcher and a direct `python3 elr_smoke.py` resolve the same
    identity posture and key source -- the credential lives in elr_lib, not
    in the launcher."""

    def setUp(self):
        try:
            import certifi  # noqa: F401  (InternalClient needs a CA bundle even for http://)
        except ImportError:
            if not os.environ.get("SSL_CERT_FILE"):
                self.skipTest("no CA bundle: certifi unavailable and SSL_CERT_FILE unset")
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.tmp)], check=False))
        base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.tmp),
            "ENCELADUS_ELR_KEY_FILE": str(self.tmp / "internal_key"),
            "ENCELADUS_HEALTH_API_URL": f"{base}/health",
            "ENCELADUS_TRACKER_API_BASE": f"{base}/tracker",
            "ELR_PYTHON": sys.executable,
        }
        if os.environ.get("SSL_CERT_FILE"):
            self.env["SSL_CERT_FILE"] = os.environ["SSL_CERT_FILE"]

    def _digest(self, argv):
        proc = subprocess.run(argv, env=self.env, capture_output=True, text=True, timeout=60)
        return proc.returncode, json.loads(proc.stdout.strip().splitlines()[-1])

    def test_same_posture_with_key_file_and_without_credential(self):
        direct = [sys.executable, str(_ELR_ROOT / "elr_smoke.py")]
        launcher = ["sh", str(_ELR_ROOT / "elr"), "smoke"]

        no_cred = [self._digest(direct), self._digest(launcher)]
        for code, digest in no_cred:
            self.assertEqual(code, elr_config.EXIT_CODE_NO_CREDENTIAL)
            self.assertEqual(digest["identity_posture"], "unknown")
            self.assertEqual(digest["key_source"], "none")

        _write_key(self.tmp / "internal_key")
        with_key = [self._digest(direct), self._digest(launcher)]
        for code, digest in with_key:
            self.assertEqual(code, 0, digest)
            self.assertEqual(digest["identity_posture"], "internal-key")
            self.assertEqual(digest["key_source"], "key_file")
            self.assertEqual(digest["auth_probe"], {"status": 404, "ok": True})


if __name__ == "__main__":
    unittest.main()
