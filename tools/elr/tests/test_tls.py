"""Offline tests for elr_lib.tls's CA-bundle resolution chain (ENC-TSK-P76,
T-B3, FR-B4-8..9). No network access -- filesystem/ssl calls are mocked.
"""

import os
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from elr_lib import tls as elr_tls


class _FakeCertStoreCtx:
    def __init__(self, x509_ca):
        self._x509_ca = x509_ca

    def cert_store_stats(self):
        return {"x509": self._x509_ca, "crl": 0, "x509_ca": self._x509_ca}


class TryEachBranchTests(unittest.TestCase):
    """AC-4: each resolution branch covered in isolation."""

    def test_ssl_cert_file_unset_returns_none(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SSL_CERT_FILE", None)
            self.assertIsNone(elr_tls._try_ssl_cert_file())

    def test_ssl_cert_file_nonexistent_returns_none(self):
        with patch.dict(os.environ, {"SSL_CERT_FILE": "/no/such/path.pem"}):
            self.assertIsNone(elr_tls._try_ssl_cert_file())

    def test_ssl_cert_file_present_and_loadable_wins(self):
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(b"not a real cert, load is mocked")
            path = f.name
        try:
            with patch.dict(os.environ, {"SSL_CERT_FILE": path}), patch.object(
                elr_tls, "_context_loads", return_value=True
            ):
                result = elr_tls._try_ssl_cert_file()
            self.assertEqual(result.source, elr_tls.SOURCE_SSL_CERT_FILE)
            self.assertEqual(result.path, path)
        finally:
            os.unlink(path)

    def test_ssl_cert_file_present_but_unparseable_returns_none(self):
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(b"garbage")
            path = f.name
        try:
            with patch.dict(os.environ, {"SSL_CERT_FILE": path}), patch.object(
                elr_tls, "_context_loads", return_value=False
            ):
                self.assertIsNone(elr_tls._try_ssl_cert_file())
        finally:
            os.unlink(path)

    def test_certifi_absent_returns_none(self):
        with patch.object(elr_tls, "certifi", None):
            self.assertIsNone(elr_tls._try_certifi())

    def test_certifi_present_and_loadable_returns_resolution(self):
        fake_certifi = MagicMock()
        fake_certifi.where.return_value = "/fake/certifi/cacert.pem"
        with patch.object(elr_tls, "certifi", fake_certifi), patch(
            "os.path.isfile", return_value=True
        ), patch.object(elr_tls, "_context_loads", return_value=True):
            result = elr_tls._try_certifi()
        self.assertEqual(result.source, elr_tls.SOURCE_CERTIFI)
        self.assertEqual(result.path, "/fake/certifi/cacert.pem")

    def test_certifi_where_raises_returns_none(self):
        fake_certifi = MagicMock()
        fake_certifi.where.side_effect = RuntimeError("boom")
        with patch.object(elr_tls, "certifi", fake_certifi):
            self.assertIsNone(elr_tls._try_certifi())

    def test_interpreter_default_no_ca_certs_returns_none(self):
        with patch.object(elr_tls.ssl, "create_default_context", return_value=_FakeCertStoreCtx(0)):
            self.assertIsNone(elr_tls._try_interpreter_default())

    def test_interpreter_default_with_ca_certs_returns_resolution(self):
        fake_paths = ssl.DefaultVerifyPaths(
            cafile="/etc/ssl/cert.pem",
            capath=None,
            openssl_cafile_env="SSL_CERT_FILE",
            openssl_cafile="/etc/ssl/cert.pem",
            openssl_capath_env="SSL_CERT_DIR",
            openssl_capath=None,
        )
        with patch.object(
            elr_tls.ssl, "create_default_context", return_value=_FakeCertStoreCtx(193)
        ), patch.object(elr_tls.ssl, "get_default_verify_paths", return_value=fake_paths):
            result = elr_tls._try_interpreter_default()
        self.assertEqual(result.source, elr_tls.SOURCE_DEFAULT)
        self.assertEqual(result.path, "/etc/ssl/cert.pem")

    def test_interpreter_default_raises_returns_none(self):
        with patch.object(
            elr_tls.ssl, "create_default_context", side_effect=ssl.SSLError("no default ctx")
        ):
            self.assertIsNone(elr_tls._try_interpreter_default())


class ResolveCaBundleOrderTests(unittest.TestCase):
    """resolve_ca_bundle() walks SSL_CERT_FILE -> certifi -> default -> missing,
    in that priority order, using the FIRST hit.
    """

    def test_ssl_cert_file_beats_certifi_and_default(self):
        with patch.object(
            elr_tls, "_try_ssl_cert_file", return_value=elr_tls.CaBundleResolution("SSL_CERT_FILE", "/a")
        ), patch.object(elr_tls, "_try_certifi") as certifi_mock, patch.object(
            elr_tls, "_try_interpreter_default"
        ) as default_mock:
            result = elr_tls.resolve_ca_bundle()
        self.assertEqual(result.source, elr_tls.SOURCE_SSL_CERT_FILE)
        certifi_mock.assert_not_called()
        default_mock.assert_not_called()

    def test_certifi_used_when_ssl_cert_file_absent(self):
        with patch.object(elr_tls, "_try_ssl_cert_file", return_value=None), patch.object(
            elr_tls, "_try_certifi", return_value=elr_tls.CaBundleResolution("certifi", "/b")
        ), patch.object(elr_tls, "_try_interpreter_default") as default_mock:
            result = elr_tls.resolve_ca_bundle()
        self.assertEqual(result.source, elr_tls.SOURCE_CERTIFI)
        default_mock.assert_not_called()

    def test_default_used_when_ssl_cert_file_and_certifi_absent(self):
        with patch.object(elr_tls, "_try_ssl_cert_file", return_value=None), patch.object(
            elr_tls, "_try_certifi", return_value=None
        ), patch.object(
            elr_tls, "_try_interpreter_default", return_value=elr_tls.CaBundleResolution("default", "/c")
        ):
            result = elr_tls.resolve_ca_bundle()
        self.assertEqual(result.source, elr_tls.SOURCE_DEFAULT)

    def test_missing_when_nothing_resolves(self):
        with patch.object(elr_tls, "_try_ssl_cert_file", return_value=None), patch.object(
            elr_tls, "_try_certifi", return_value=None
        ), patch.object(elr_tls, "_try_interpreter_default", return_value=None):
            result = elr_tls.resolve_ca_bundle()
        self.assertEqual(result.source, elr_tls.SOURCE_MISSING)
        self.assertIsNone(result.path)
        self.assertTrue(result.unresolved)


class BuildSslContextAlwaysVerifiesTests(unittest.TestCase):
    """AC-3: no flag/env/code path in this module ever disables
    verification -- every constructed context has check_hostname=True and
    verify_mode=CERT_REQUIRED, for EVERY resolution source including
    "missing".
    """

    def _assert_verifying(self, ctx: ssl.SSLContext) -> None:
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_missing_resolution_still_verifies(self):
        resolution = elr_tls.CaBundleResolution(elr_tls.SOURCE_MISSING, None)
        self._assert_verifying(elr_tls.build_ssl_context(resolution))

    def test_default_resolution_still_verifies(self):
        resolution = elr_tls.CaBundleResolution(elr_tls.SOURCE_DEFAULT, None)
        self._assert_verifying(elr_tls.build_ssl_context(resolution))

    def test_real_resolved_bundle_still_verifies(self):
        # No mocking -- exercises the real resolution chain on this host.
        self._assert_verifying(elr_tls.build_ssl_context())

    def test_no_env_var_can_flip_verification(self):
        # PYTHONHTTPSVERIFY etc. only affect ssl._create_default_https_
        # context wiring elsewhere in stdlib -- elr_lib.tls never reads
        # any such env var, so setting one here must have zero effect on
        # what build_ssl_context() returns.
        with patch.dict(os.environ, {"PYTHONHTTPSVERIFY": "0"}):
            resolution = elr_tls.CaBundleResolution(elr_tls.SOURCE_MISSING, None)
            self._assert_verifying(elr_tls.build_ssl_context(resolution))

    def test_no_disable_verification_flag_exists_anywhere_in_module(self):
        # Static guard: the module must expose no callable/attribute whose
        # name suggests a verification bypass.
        forbidden_substrings = ("disable_verif", "no_verify", "insecure", "unverified", "skip_verify")
        names = [n for n in dir(elr_tls) if not n.startswith("__")]
        for name in names:
            lowered = name.lower()
            for forbidden in forbidden_substrings:
                self.assertNotIn(
                    forbidden, lowered, f"elr_lib.tls exposes a verification-bypass-shaped name: {name}"
                )


if __name__ == "__main__":
    unittest.main()
