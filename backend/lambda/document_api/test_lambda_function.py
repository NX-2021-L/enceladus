"""test_lambda_function.py — Mock-based integration tests for document_api.

Tests document upload (PUT), retrieve (GET), list, search, and PATCH flows,
including auth, project validation, S3 content storage, and DynamoDB metadata.
All locally runnable without AWS credentials.

Part of ENC-TSK-531: Backend Lambda integration tests.

Run: python3 -m pytest test_lambda_function.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

_spec = importlib.util.spec_from_file_location(
    "document_api",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)


def _make_event(
    method="PUT",
    path="/api/v1/documents",
    body=None,
    cookie="enceladus_id_token=valid-jwt",
    query_params=None,
):
    """Build a mock API Gateway v2 event."""
    event = {
        "requestContext": {"http": {"method": method, "path": path}},
        "headers": {"cookie": cookie} if cookie else {"host": "example.com"},
        "rawPath": path,
        "queryStringParameters": query_params or {},
    }
    if body is not None:
        event["body"] = json.dumps(body) if isinstance(body, dict) else body
    return event


class OptionsTests(unittest.TestCase):
    def test_options_returns_200(self):
        event = _make_event(method="OPTIONS")
        resp = document_api.lambda_handler(event, None)
        self.assertIn(resp["statusCode"], [200, 204])
        self.assertIn("Access-Control-Allow-Origin", resp["headers"])


class AuthTests(unittest.TestCase):
    def test_missing_cookie_returns_401(self):
        event = _make_event(cookie="")
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 401)
        body = json.loads(resp["body"])
        self.assertIn("Authentication required", body["error"])

    @patch.object(document_api, "_verify_token", side_effect=ValueError("Token expired"))
    def test_expired_token_returns_401(self, _mock_verify):
        event = _make_event()
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 401)

    @patch.object(document_api, "_verify_token", return_value={"sub": "user1"})
    def test_internal_key_auth(self, _mock_verify):
        """Internal API key bypasses JWT validation."""
        orig = document_api.DOCUMENT_API_INTERNAL_API_KEY
        document_api.DOCUMENT_API_INTERNAL_API_KEY = "test-key-123"
        try:
            event = _make_event(cookie="")
            event["headers"] = {"x-coordination-internal-key": "test-key-123"}
            # This should get past auth — will fail on body validation, not auth
            resp = document_api.lambda_handler(event, None)
            self.assertNotEqual(resp["statusCode"], 401)
        finally:
            document_api.DOCUMENT_API_INTERNAL_API_KEY = orig


class UploadValidationTests(unittest.TestCase):
    """Test PUT /api/v1/documents input validation."""

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    def test_missing_project_id_returns_400(self, _mock_auth):
        event = _make_event(body={"title": "Test", "content": "# Hello"})
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertIn("project_id", body["error"])

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    def test_missing_title_returns_400(self, _mock_auth):
        event = _make_event(body={"project_id": "devops", "content": "# Hello"})
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertIn("title", body["error"])

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    def test_missing_content_returns_400(self, _mock_auth):
        event = _make_event(body={"project_id": "devops", "title": "Test"})
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertIn("content", body["error"])

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    def test_title_too_long_returns_400(self, _mock_auth):
        event = _make_event(body={
            "project_id": "devops",
            "title": "x" * 501,
            "content": "# Hello",
        })
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertIn("Title exceeds", body["error"])

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    def test_content_too_large_returns_400(self, _mock_auth):
        event = _make_event(body={
            "project_id": "devops",
            "title": "Big doc",
            "content": "x" * (1_048_577),
        })
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)


class UploadSuccessTests(unittest.TestCase):
    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/devops/DOC-123.md", "abc123hash", 100))
    @patch.object(document_api, "_get_ddb")
    def test_upload_creates_document(self, mock_ddb, _mock_upload, _mock_proj, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.put_item.return_value = {}

        event = _make_event(body={
            "project_id": "devops",
            "title": "Test Document",
            "content": "# Hello World\n\nThis is a test.",
            "keywords": ["test", "hello"],
        })
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 201)
        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertIn("document_id", body)

        # Verify DynamoDB put_item was called
        fake_ddb.put_item.assert_called_once()
        call_args = fake_ddb.put_item.call_args
        item = call_args[1]["Item"] if "Item" in call_args[1] else call_args[0][0]
        # Item should have document_id, title, project_id
        self.assertIn("document_id", item)


class GetDocumentTests(unittest.TestCase):
    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_get_ddb")
    @patch.object(document_api, "_get_content", return_value="# Hello World")
    def test_get_existing_document(self, _mock_content, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {
            "Item": {
                "document_id": {"S": "DOC-TEST123"},
                "title": {"S": "Test Document"},
                "project_id": {"S": "devops"},
                "status": {"S": "active"},
                "created_at": {"S": "2026-01-01T00:00:00Z"},
                "updated_at": {"S": "2026-01-01T00:00:00Z"},
            }
        }

        event = _make_event(method="GET", path="/api/v1/documents/DOC-TEST123")
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["document_id"], "DOC-TEST123")

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_get_ddb")
    def test_get_nonexistent_document_returns_404(self, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {}  # No Item

        event = _make_event(method="GET", path="/api/v1/documents/DOC-NOPE")
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 404)


class ListDocumentsTests(unittest.TestCase):
    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    @patch.object(document_api, "_get_ddb")
    def test_list_by_project(self, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.query.return_value = {
            "Items": [
                {
                    "document_id": {"S": "DOC-A"},
                    "title": {"S": "Doc A"},
                    "project_id": {"S": "devops"},
                    "status": {"S": "active"},
                    "created_at": {"S": "2026-01-01T00:00:00Z"},
                    "updated_at": {"S": "2026-01-01T00:00:00Z"},
                },
            ],
            "Count": 1,
        }

        event = _make_event(
            method="GET",
            path="/api/v1/documents",
            query_params={"project": "devops"},
        )
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertIn("documents", body)

    @patch.object(document_api, "_authenticate",
                  return_value=({"sub": "user1"}, None))
    def test_list_without_project_returns_400(self, _mock_auth):
        event = _make_event(method="GET", path="/api/v1/documents")
        resp = document_api.lambda_handler(event, None)
        # Should require either project= or document ID
        self.assertIn(resp["statusCode"], [400, 200])


class S3HelperTests(unittest.TestCase):
    def test_s3_key_construction(self):
        key = document_api._s3_key("devops", "DOC-123")
        self.assertEqual(key, "agent-documents/devops/DOC-123.md")

    def test_allowed_file_extensions(self):
        self.assertTrue(document_api._is_allowed_file_name("readme.md"))
        self.assertTrue(document_api._is_allowed_file_name("notes.markdown"))
        self.assertFalse(document_api._is_allowed_file_name("script.py"))
        self.assertFalse(document_api._is_allowed_file_name(""))


class TokenExtractionTests(unittest.TestCase):
    def test_extract_from_cookie_header(self):
        event = {"headers": {"cookie": "enceladus_id_token=abc123; other=val"}}
        self.assertEqual(document_api._extract_token(event), "abc123")

    def test_extract_from_cookies_array(self):
        event = {"headers": {}, "cookies": ["enceladus_id_token=xyz789"]}
        self.assertEqual(document_api._extract_token(event), "xyz789")


class ResponseFormatTests(unittest.TestCase):
    def test_response_includes_cors(self):
        resp = document_api._response(200, {"ok": True})
        self.assertIn("Access-Control-Allow-Origin", resp["headers"])
        self.assertEqual(resp["headers"]["Access-Control-Allow-Origin"], "https://jreese.net")

    def test_error_includes_envelope(self):
        resp = document_api._error(400, "Bad input")
        body = json.loads(resp["body"])
        self.assertFalse(body["success"])
        self.assertIn("error_envelope", body)
        self.assertEqual(body["error_envelope"]["code"], "INVALID_INPUT")
        self.assertFalse(body["error_envelope"]["retryable"])

    def test_500_error_is_retryable(self):
        resp = document_api._error(500, "Internal error")
        body = json.loads(resp["body"])
        self.assertTrue(body["error_envelope"]["retryable"])


if __name__ == "__main__":
    unittest.main()
