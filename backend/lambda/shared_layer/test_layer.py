"""test_layer.py — Unit tests for enceladus_shared layer modules.

Run from shared_layer directory:
    PYTHONPATH=python python3 -m pytest test_layer.py -v
"""

from __future__ import annotations

import json
import sys
import unittest
from decimal import Decimal
from unittest.mock import MagicMock, patch

# Ensure the layer's python/ directory is importable.
sys.path.insert(0, "python")

from enceladus_shared.auth import (
    _authenticate,
    _extract_token,
    _verify_token,
)
from enceladus_shared.aws_clients import _get_ddb, _get_s3, _get_sqs
from enceladus_shared.http_utils import _error, _parse_body, _path_method, _response
from enceladus_shared.serialization import _deserialize, _now_z, _serialize, _unix_now


class AuthTests(unittest.TestCase):
    def test_extract_token_from_cookie_header(self):
        event = {
            "headers": {"cookie": "enceladus_id_token=abc123; other=val"},
        }
        self.assertEqual(_extract_token(event), "abc123")

    def test_extract_token_from_cookies_array(self):
        event = {
            "headers": {},
            "cookies": ["enceladus_id_token=xyz789", "other=val"],
        }
        self.assertEqual(_extract_token(event), "xyz789")

    def test_extract_token_missing(self):
        event = {"headers": {"cookie": "other=val"}}
        self.assertIsNone(_extract_token(event))

    def test_authenticate_internal_key(self):
        import enceladus_shared.auth as auth_mod

        orig = auth_mod.INTERNAL_API_KEY
        orig_prev = auth_mod.INTERNAL_API_KEY_PREVIOUS
        orig_keys = auth_mod.INTERNAL_API_KEYS
        auth_mod.INTERNAL_API_KEY = "test-key-123"
        auth_mod.INTERNAL_API_KEY_PREVIOUS = ""
        auth_mod.INTERNAL_API_KEYS = ("test-key-123",)
        try:
            event = {"headers": {"x-coordination-internal-key": "test-key-123"}}
            claims, err = _authenticate(event)
            self.assertIsNotNone(claims)
            self.assertIsNone(err)
            self.assertEqual(claims["auth_mode"], "internal-key")
        finally:
            auth_mod.INTERNAL_API_KEY = orig
            auth_mod.INTERNAL_API_KEY_PREVIOUS = orig_prev
            auth_mod.INTERNAL_API_KEYS = orig_keys

    def test_authenticate_previous_internal_key(self):
        import enceladus_shared.auth as auth_mod

        orig = auth_mod.INTERNAL_API_KEY
        orig_prev = auth_mod.INTERNAL_API_KEY_PREVIOUS
        orig_keys = auth_mod.INTERNAL_API_KEYS
        auth_mod.INTERNAL_API_KEY = "active-key"
        auth_mod.INTERNAL_API_KEY_PREVIOUS = "previous-key"
        auth_mod.INTERNAL_API_KEYS = ("active-key", "previous-key")
        try:
            event = {"headers": {"x-coordination-internal-key": "previous-key"}}
            claims, err = _authenticate(event)
            self.assertIsNotNone(claims)
            self.assertIsNone(err)
            self.assertEqual(claims["auth_mode"], "internal-key")
        finally:
            auth_mod.INTERNAL_API_KEY = orig
            auth_mod.INTERNAL_API_KEY_PREVIOUS = orig_prev
            auth_mod.INTERNAL_API_KEYS = orig_keys

    def test_authenticate_no_token(self):
        import enceladus_shared.auth as auth_mod

        orig = auth_mod.INTERNAL_API_KEY
        orig_prev = auth_mod.INTERNAL_API_KEY_PREVIOUS
        orig_keys = auth_mod.INTERNAL_API_KEYS
        auth_mod.INTERNAL_API_KEY = ""
        auth_mod.INTERNAL_API_KEY_PREVIOUS = ""
        auth_mod.INTERNAL_API_KEYS = ()
        try:
            event = {"headers": {}}
            claims, err = _authenticate(event)
            self.assertIsNone(claims)
            self.assertIsNotNone(err)
            self.assertEqual(err["statusCode"], 401)
        finally:
            auth_mod.INTERNAL_API_KEY = orig
            auth_mod.INTERNAL_API_KEY_PREVIOUS = orig_prev
            auth_mod.INTERNAL_API_KEYS = orig_keys


class HttpUtilsTests(unittest.TestCase):
    def test_response_format(self):
        resp = _response(200, {"key": "val"})
        self.assertEqual(resp["statusCode"], 200)
        self.assertIn("Content-Type", resp["headers"])
        body = json.loads(resp["body"])
        self.assertEqual(body["key"], "val")

    def test_error_format(self):
        resp = _error(400, "bad input")
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertFalse(body["success"])
        self.assertEqual(body["error"], "bad input")

    def test_parse_body(self):
        event = {"body": '{"key": "val"}', "isBase64Encoded": False}
        self.assertEqual(_parse_body(event), {"key": "val"})

    def test_parse_body_base64(self):
        import base64

        raw = base64.b64encode(b'{"key": "b64"}').decode()
        event = {"body": raw, "isBase64Encoded": True}
        self.assertEqual(_parse_body(event), {"key": "b64"})

    def test_path_method(self):
        event = {
            "requestContext": {"http": {"method": "POST", "path": "/api/v1/test"}},
        }
        method, path = _path_method(event)
        self.assertEqual(method, "POST")
        self.assertEqual(path, "/api/v1/test")


class SerializationTests(unittest.TestCase):
    def test_serialize_string(self):
        result = _serialize("hello")
        self.assertEqual(result, {"S": "hello"})

    def test_serialize_float(self):
        result = _serialize(3.14)
        self.assertEqual(result["N"], "3.14")

    def test_deserialize_item(self):
        item = {"name": {"S": "test"}, "count": {"N": "42"}}
        result = _deserialize(item)
        self.assertEqual(result["name"], "test")
        self.assertEqual(result["count"], 42)

    def test_now_z_format(self):
        ts = _now_z()
        self.assertTrue(ts.endswith("Z"))
        self.assertRegex(ts, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

    def test_unix_now(self):
        import time

        now = _unix_now()
        self.assertAlmostEqual(now, int(time.time()), delta=2)


class AwsClientTests(unittest.TestCase):
    @patch("enceladus_shared.aws_clients.boto3")
    def test_get_ddb_singleton(self, mock_boto3):
        import enceladus_shared.aws_clients as clients

        clients._ddb = None  # Reset singleton
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        result1 = _get_ddb()
        result2 = _get_ddb()

        # Same object returned both times.
        self.assertIs(result1, result2)
        # boto3.client called only once.
        mock_boto3.client.assert_called_once()

        clients._ddb = None  # Clean up


if __name__ == "__main__":
    unittest.main()
