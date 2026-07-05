"""ENC-TSK-L53 / ENC-ISS-489: graphsearch cookie auth via APIGW v2 cookies[]."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402


class TestAuthenticateCookieParity(unittest.TestCase):
    def test_event_cookies_array_authenticates(self):
        event = {
            "headers": {},
            "cookies": ["enceladus_id_token=abc123"],
        }
        self.assertIsNone(lf._authenticate(event))

    def test_headers_cookie_authenticates(self):
        event = {
            "headers": {"Cookie": "enceladus_id_token=abc123"},
        }
        self.assertIsNone(lf._authenticate(event))

    def test_bearer_header_authenticates(self):
        event = {
            "headers": {"authorization": "Bearer abc123"},
        }
        self.assertIsNone(lf._authenticate(event))

    def test_unauthenticated_returns_error(self):
        event = {"headers": {}, "cookies": []}
        self.assertEqual(lf._authenticate(event), "Authentication required")

    @patch.object(lf, "COORDINATION_INTERNAL_API_KEY", "secret-key")
    def test_internal_key_authenticates(self):
        event = {
            "headers": {"x-coordination-internal-key": "secret-key"},
        }
        self.assertIsNone(lf._authenticate(event))


if __name__ == "__main__":
    unittest.main()
