"""test_digest_manifest_p69.py — ENC-TSK-P69 digest_only / manifest / outline persistence.

Covers:
  AC-1: GET /documents/{id}?digest_only=true and GET /documents/{id}/manifest
        both resolve to one handler and return the same content-free
        projection {document_id, project_id, title, document_subtype,
        subtypepattern, version, content_hash, size_bytes, updated_at,
        history_count, outline}.
  AC-3: ETag response header == '"' + content_hash + '"'; If-None-Match
        for the current hash returns 304 with an empty body; content_hash
        is the lowercase hex SHA-256 of the exact stored UTF-8 bytes (no
        normalization) — asserted with a CRLF + trailing-whitespace body.
  AC-4: outline is persisted on every write path (put / patch-content /
        patch-append_content); a digest read for an item that already
        carries the `outline` attribute never touches S3; a digest read
        for a pre-existing item with no `outline` attribute computes it
        from S3 content on the fly and does not write it back (read
        paths never mutate).

Mirrors the MagicMock-based mocking style of test_lambda_function.py /
test_if_match_l47.py (no moto; _get_ddb / _get_s3 / _get_content /
_authenticate are patched directly).

Run: python3 -m pytest test_digest_manifest_p69.py -v
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

_spec = importlib.util.spec_from_file_location(
    "document_api_p69",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)


def _make_event(method="GET", path="/api/v1/documents/DOC-P69TEST01", query_params=None, headers=None):
    event = {
        "requestContext": {"http": {"method": method, "path": path}},
        "rawPath": path,
        "headers": headers or {},
        "queryStringParameters": query_params or {},
    }
    return event


def _digest_item(
    document_id="DOC-P69TEST01",
    project_id="devops",
    title="Digest Test Doc",
    document_subtype="doc",
    subtypepattern="general",
    version="3",
    content_hash="abc123hash",
    size_bytes="42",
    updated_at="2026-09-01T00:00:00Z",
    history_count=None,
    outline_json=None,
):
    item = {
        "document_id": {"S": document_id},
        "project_id": {"S": project_id},
        "title": {"S": title},
        "document_subtype": {"S": document_subtype},
        "subtypepattern": {"S": subtypepattern},
        "version": {"N": version},
        "content_hash": {"S": content_hash},
        "size_bytes": {"N": size_bytes},
        "updated_at": {"S": updated_at},
        "s3_key": {"S": "agent-documents/devops/DOC-P69TEST01.md"},
        "s3_bucket": {"S": "jreese-net"},
    }
    if history_count is not None:
        item["history_count"] = {"N": str(history_count)}
    if outline_json is not None:
        item["outline"] = {"S": outline_json}
    return item


CLAIMS = ({"sub": "user1"}, None)


class DigestOnlyQueryParamTests(unittest.TestCase):
    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    def test_digest_only_true_returns_projection_without_content(self, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        outline_entries = [{"heading_path": ["Section A"], "level": 2, "ordinal": 1,
                             "block_id": None, "line_start": 3, "line_end": 5, "section_bytes": 12}]
        fake_ddb.get_item.return_value = {"Item": _digest_item(outline_json=json.dumps(outline_entries))}

        event = _make_event(query_params={"digest_only": "true"})
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertNotIn("content", body)
        for key in (
            "document_id", "project_id", "title", "document_subtype", "subtypepattern",
            "version", "content_hash", "size_bytes", "updated_at", "history_count", "outline",
        ):
            self.assertIn(key, body, f"missing projection field: {key}")
        self.assertEqual(body["document_id"], "DOC-P69TEST01")
        self.assertEqual(body["outline"], outline_entries)
        self.assertEqual(body["history_count"], 0)  # default when absent on the item

    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    def test_digest_only_false_falls_back_to_full_get(self, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _digest_item(outline_json="[]")}
        with patch.object(document_api, "_get_content", return_value="# Hello"):
            event = _make_event(query_params={"digest_only": "false", "include_content": "true"})
            resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertIn("content", body)


class ManifestRouteTests(unittest.TestCase):
    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    def test_manifest_route_shares_handler_with_digest_only(self, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        outline_entries = [{"heading_path": [], "level": 1, "ordinal": 1, "block_id": None,
                             "line_start": 2, "line_end": 4, "section_bytes": 9}]
        item = _digest_item(outline_json=json.dumps(outline_entries))
        fake_ddb.get_item.return_value = {"Item": item}

        manifest_event = _make_event(path="/api/v1/documents/DOC-P69TEST01/manifest")
        manifest_resp = document_api.lambda_handler(manifest_event, None)
        self.assertEqual(manifest_resp["statusCode"], 200)
        manifest_body = json.loads(manifest_resp["body"])

        digest_event = _make_event(query_params={"digest_only": "true"})
        digest_resp = document_api.lambda_handler(digest_event, None)
        digest_body = json.loads(digest_resp["body"])

        self.assertEqual(manifest_body, digest_body)
        self.assertNotIn("content", manifest_body)

    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    def test_manifest_route_parses_document_id_without_manifest_suffix(self, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _digest_item(outline_json="[]")}

        event = _make_event(path="/api/v1/documents/DOC-P69TEST01/manifest")
        document_api.lambda_handler(event, None)
        called_key = fake_ddb.get_item.call_args.kwargs["Key"]
        self.assertEqual(called_key, {"document_id": {"S": "DOC-P69TEST01"}})

    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    def test_manifest_route_404_for_missing_document(self, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {}
        event = _make_event(path="/api/v1/documents/DOC-NOPE/manifest")
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 404)


class ETagAndIfNoneMatchTests(unittest.TestCase):
    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    def test_etag_header_is_double_quoted_content_hash(self, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {
            "Item": _digest_item(content_hash="deadbeef00", outline_json="[]"),
        }
        event = _make_event(query_params={"digest_only": "true"})
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(resp["headers"].get("ETag"), '"deadbeef00"')

    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    def test_if_none_match_current_hash_returns_304_empty_body(self, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {
            "Item": _digest_item(content_hash="deadbeef00", outline_json="[]"),
        }
        event = _make_event(
            query_params={"digest_only": "true"},
            headers={"If-None-Match": '"deadbeef00"'},
        )
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 304)
        self.assertEqual(resp["body"], "")
        self.assertEqual(resp["headers"].get("ETag"), '"deadbeef00"')

    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    def test_if_none_match_stale_hash_returns_200(self, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {
            "Item": _digest_item(content_hash="currenthash", outline_json="[]"),
        }
        event = _make_event(
            query_params={"digest_only": "true"},
            headers={"If-None-Match": '"stalehash"'},
        )
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)

    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    def test_content_hash_is_sha256_of_exact_stored_bytes_no_normalization(self, mock_ddb, _mock_auth):
        """AC-3: store a body with CRLF endings + trailing whitespace and assert
        content_hash is the lowercase hex SHA-256 of the EXACT UTF-8 bytes,
        with no newline/whitespace normalization applied anywhere en route."""
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": {}}  # unused; _upload_content is the target here
        fake_s3 = MagicMock()
        with patch.object(document_api, "_get_s3", return_value=fake_s3):
            body_with_crlf_and_trailing_ws = "# Title\r\n\r\nLine with trailing spaces.   \r\nLast line.\t\r\n"
            s3_key, content_hash, size_bytes = document_api._upload_content(
                "devops", "DOC-P69HASH01", body_with_crlf_and_trailing_ws,
            )
        expected_hash = hashlib.sha256(body_with_crlf_and_trailing_ws.encode("utf-8")).hexdigest()
        self.assertEqual(content_hash, expected_hash)
        self.assertEqual(size_bytes, len(body_with_crlf_and_trailing_ws.encode("utf-8")))
        # Sanity: the input truly contains CRLF + trailing whitespace, so a
        # normalizing implementation would have produced a different hash.
        normalized = "\n".join(
            line.rstrip() for line in body_with_crlf_and_trailing_ws.replace("\r\n", "\n").split("\n")
        )
        self.assertNotEqual(hashlib.sha256(normalized.encode("utf-8")).hexdigest(), content_hash)


class OutlinePersistenceOnWriteTests(unittest.TestCase):
    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_get_ddb")
    @patch.object(document_api, "_get_s3")
    def test_put_persists_outline_attribute(self, mock_s3, mock_ddb, _mock_project, _mock_auth):
        fake_s3 = MagicMock()
        mock_s3.return_value = fake_s3
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb

        event = _make_event(
            method="PUT",
            path="/api/v1/documents",
        )
        event["body"] = json.dumps({
            "project_id": "devops",
            "title": "Outline Persist Test",
            "content": "# Title\n\n## Section A\n\nbody\n",
            "document_subtype": "doc",
        })
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 201)
        put_kwargs = fake_ddb.put_item.call_args.kwargs
        item = put_kwargs["Item"]
        self.assertIn("outline", item)
        outline_entries = json.loads(item["outline"]["S"])
        self.assertEqual(outline_entries[1]["heading_path"], ["Section A"])

    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    @patch.object(document_api, "_get_s3")
    def test_patch_content_replace_persists_outline_attribute(self, mock_s3, mock_ddb, _mock_auth):
        fake_s3 = MagicMock()
        mock_s3.return_value = fake_s3
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _digest_item(version="3")}

        event = _make_event(method="PATCH", path="/api/v1/documents/DOC-P69TEST01")
        event["body"] = json.dumps({"content": "# New Title\n\n## New Section\n\nbody\n"})
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        update_kwargs = fake_ddb.update_item.call_args.kwargs
        self.assertIn("outline = :outline", update_kwargs["UpdateExpression"])
        outline_entries = json.loads(update_kwargs["ExpressionAttributeValues"][":outline"]["S"])
        self.assertEqual(outline_entries[1]["heading_path"], ["New Section"])

    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_content", return_value="# Existing\n\nbody\n")
    def test_patch_append_content_persists_outline_attribute(self, _mock_content, mock_s3, mock_ddb, _mock_auth):
        fake_s3 = MagicMock()
        mock_s3.return_value = fake_s3
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _digest_item(version="3")}

        event = _make_event(method="PATCH", path="/api/v1/documents/DOC-P69TEST01")
        event["body"] = json.dumps({"append_content": "## Appended Section\n\nmore body"})
        resp = document_api.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        update_kwargs = fake_ddb.update_item.call_args.kwargs
        self.assertIn("outline = :outline", update_kwargs["UpdateExpression"])
        outline_entries = json.loads(update_kwargs["ExpressionAttributeValues"][":outline"]["S"])
        paths = [e["heading_path"] for e in outline_entries]
        self.assertIn(["Appended Section"], paths)


class OutlineReadNeverMutatesTests(unittest.TestCase):
    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    def test_digest_uses_persisted_outline_without_touching_s3(self, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        outline_entries = [{"heading_path": ["X"], "level": 2, "ordinal": 1, "block_id": None,
                             "line_start": 2, "line_end": 3, "section_bytes": 5}]
        fake_ddb.get_item.return_value = {"Item": _digest_item(outline_json=json.dumps(outline_entries))}

        with patch.object(document_api, "_get_content") as mock_get_content:
            event = _make_event(query_params={"digest_only": "true"})
            resp = document_api.lambda_handler(event, None)
            mock_get_content.assert_not_called()
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["outline"], outline_entries)

    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    def test_digest_computes_outline_from_s3_when_absent_and_does_not_write_back(self, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        item = _digest_item()  # no outline attribute at all
        fake_ddb.get_item.return_value = {"Item": item}

        with patch.object(document_api, "_get_content", return_value="# T\n\n## Computed Section\n\nbody\n") as mock_get_content:
            event = _make_event(query_params={"digest_only": "true"})
            resp = document_api.lambda_handler(event, None)
            mock_get_content.assert_called_once()

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        paths = [e["heading_path"] for e in body["outline"]]
        self.assertIn(["Computed Section"], paths)
        # AC-4: a read path must never mutate the item.
        fake_ddb.update_item.assert_not_called()
        fake_ddb.put_item.assert_not_called()

    @patch.object(document_api, "_authenticate", return_value=CLAIMS)
    @patch.object(document_api, "_get_ddb")
    def test_digest_returns_empty_outline_when_s3_content_unavailable(self, mock_ddb, _mock_auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _digest_item()}

        with patch.object(document_api, "_get_content", return_value=None):
            event = _make_event(query_params={"digest_only": "true"})
            resp = document_api.lambda_handler(event, None)

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["outline"], [])
        fake_ddb.update_item.assert_not_called()
        fake_ddb.put_item.assert_not_called()


if __name__ == "__main__":
    unittest.main()
