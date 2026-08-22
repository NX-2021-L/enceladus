"""Offline tests for elr_lib.transport's InternalClient. No network access
-- urllib.request.urlopen is mocked via unittest.mock.patch.
"""

import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from elr_lib import config as elr_config
from elr_lib import transport as elr_transport


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


def _http_error(code, body=b""):
    return urllib.error.HTTPError(
        url="https://jreese.net/api/v1/tracker",
        code=code,
        msg="error",
        hdrs=None,
        fp=io.BytesIO(body),
    )


class InternalClientRetryTests(unittest.TestCase):
    def setUp(self):
        self.cfg = elr_config.InternalProfileConfig()
        self.client = elr_transport.InternalClient(self.cfg, timeout=5)

    def test_get_retries_once_on_5xx_then_succeeds(self):
        success_body = json.dumps({"success": True}).encode("utf-8")
        side_effects = [_http_error(502, b'{"error":"bad gateway"}'), _FakeHttpResponse(200, success_body)]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=side_effects) as mock_urlopen:
            status, body = self.client.request("GET", "tracker", "/some/path")
        self.assertEqual(mock_urlopen.call_count, 2)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"success": True})

    def test_get_retries_at_most_once_on_repeated_5xx(self):
        side_effects = [_http_error(503, b""), _http_error(503, b"")]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=side_effects) as mock_urlopen:
            status, body = self.client.request("GET", "tracker", "/some/path")
        # exactly one retry attempted (2 total calls), not more
        self.assertEqual(mock_urlopen.call_count, 2)
        self.assertEqual(status, 503)

    def test_post_write_never_retried_on_5xx(self):
        """A write must never be blindly retried on 5xx -- the response
        may be an ambiguous echo of a write that already landed. ELR
        surfaces the failure instead of risking a double-apply.
        """
        side_effects = [_http_error(500, b'{"error":"internal"}')]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=side_effects) as mock_urlopen:
            status, body = self.client.request("POST", "tracker", "/create", payload={"x": 1})
        self.assertEqual(mock_urlopen.call_count, 1)
        self.assertEqual(status, 500)

    def test_get_does_not_retry_on_4xx(self):
        side_effects = [_http_error(404, b'{"error":"not found"}')]
        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=side_effects) as mock_urlopen:
            status, body = self.client.request("GET", "tracker", "/missing")
        self.assertEqual(mock_urlopen.call_count, 1)
        self.assertEqual(status, 404)

    def test_unreachable_returns_status_zero(self):
        with patch(
            "elr_lib.transport.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            status, body = self.client.request("GET", "tracker", "/x")
        self.assertEqual(status, 0)
        self.assertIn("error", body)


class InternalClientHeaderTests(unittest.TestCase):
    def test_internal_key_header_sent_when_configured(self):
        with patch.dict("os.environ", {"ENCELADUS_TRACKER_API_INTERNAL_API_KEY": "the-tracker-key"}, clear=False):
            cfg = elr_config.InternalProfileConfig()
        client = elr_transport.InternalClient(cfg, timeout=5)

        fake_resp = _FakeHttpResponse(200, b"{}")
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp) as mock_urlopen:
            client.request("GET", "tracker", "/x")
        sent_request = mock_urlopen.call_args[0][0]
        self.assertEqual(sent_request.get_header("X-coordination-internal-key"), "the-tracker-key")

    def test_health_never_sends_internal_key_header(self):
        with patch.dict("os.environ", {"ENCELADUS_TRACKER_API_INTERNAL_API_KEY": "should-not-be-sent"}, clear=False):
            cfg = elr_config.InternalProfileConfig()
        client = elr_transport.InternalClient(cfg, timeout=5)

        fake_resp = _FakeHttpResponse(200, b'{"dynamodb":"ok","s3":"ok"}')
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp) as mock_urlopen:
            status, body = client.health()
        sent_request = mock_urlopen.call_args[0][0]
        self.assertIsNone(sent_request.get_header("X-coordination-internal-key"))
        self.assertEqual(status, 200)
        self.assertEqual(body, {"dynamodb": "ok", "s3": "ok"})

    def test_no_key_configured_means_no_header_sent(self):
        env_keys_to_clear = list(elr_config.COMMON_INTERNAL_KEY_ENV_CHAIN) + [
            "ENCELADUS_TRACKER_API_INTERNAL_API_KEY",
        ]
        with patch.dict("os.environ", {}, clear=False):
            import os

            saved = {k: os.environ.pop(k, None) for k in env_keys_to_clear}
            try:
                cfg = elr_config.InternalProfileConfig()
                client = elr_transport.InternalClient(cfg, timeout=5)
                fake_resp = _FakeHttpResponse(200, b"{}")
                with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp) as mock_urlopen:
                    client.request("GET", "tracker", "/x")
                sent_request = mock_urlopen.call_args[0][0]
                self.assertIsNone(sent_request.get_header("X-coordination-internal-key"))
            finally:
                for k, v in saved.items():
                    if v is not None:
                        os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
