"""test_ftr152_brd_graduation.py - ENC-FTR-152 / ENC-TSK-S25 AC-8 coverage.

ENC-FTR-152 graduates 'brd' from a document.doc subtypepattern to a first-class
document_subtype (the first ENC-FTR-078 AC-18 graduation). Covered here:

    brd PUT happy path; brd needs no extra fields      -> BrdPutTests
    brd + subtypepattern -> SUBTYPEPATTERN_WRONG_SUBTYPE -> BrdPutTests
    brd title colon-prefix hygiene                      -> BrdTitleHygieneTests
    doc + subtypepattern=brd rejected on PUT and PATCH  -> SubtypepatternGraduatedTests
    PATCH doc+brd -> brd (metadata-only, pattern cleared) -> LegacyBrdMigrationPatchTests
    search document_subtype=brd and the deprecated
    subtypepattern=brd alias (three modes)              -> BrdSearchAliasTests

Mocking mirrors test_ftr078_subtypes.py. Run:

    python3 -m pytest test_ftr152_brd_graduation.py -v
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


def _make_event(method="PUT", path="/api/v1/documents", body=None, query_params=None):
    event = {
        "requestContext": {"http": {"method": method, "path": path}},
        "headers": {"cookie": "enceladus_id_token=valid-jwt"},
        "rawPath": path,
        "queryStringParameters": query_params or {},
    }
    if body is not None:
        event["body"] = json.dumps(body)
    return event


def _put_body(**overrides):
    body = {
        "project_id": "enceladus",
        "title": "Cost-Disciplined Velocity",
        "content": "# Cost-Disciplined Velocity\n\n## 1. Project Summary\n\nBody.",
        "document_subtype": "brd",
    }
    body.update(overrides)
    return body


def _configure_ddb_for_put(mock_ddb):
    fake_ddb = MagicMock()
    fake_ddb.put_item.return_value = {}
    mock_ddb.return_value = fake_ddb
    return fake_ddb


def _resp_body(resp):
    return json.loads(resp["body"])


def _error_code(resp):
    return (_resp_body(resp).get("error_envelope") or {}).get("code")


def _legacy_brd_item(**overrides):
    item = {
        "document_id": {"S": "DOC-LEGACYBRD01"},
        "project_id": {"S": "enceladus"},
        "title": {"S": "BRD -- Feed Freshness"},
        "status": {"S": "active"},
        "document_subtype": {"S": "doc"},
        "subtypepattern": {"S": "brd"},
        "content_hash": {"S": "a" * 64},
        "created_at": {"S": "2026-10-26T00:00:00Z"},
        "updated_at": {"S": "2026-10-26T00:00:00Z"},
        "version": {"N": "3"},
    }
    item.update(overrides)
    return item


_AUTH = patch.object(document_api, "_authenticate", return_value=({"sub": "user1"}, None))
_PROJECT = patch.object(document_api, "_validate_project_exists", return_value=None)
_UPLOAD = patch.object(
    document_api, "_upload_content", return_value=("agent-documents/enceladus/DOC-X.md", "abc123", 50)
)


class BrdEnumTests(unittest.TestCase):
    def test_brd_is_in_the_allow_list(self):
        self.assertIn("brd", document_api.DOCUMENT_SUBTYPES)
        self.assertEqual(document_api.GRADUATED_SUBTYPEPATTERNS, {"brd": "brd"})


class BrdPutTests(unittest.TestCase):
    @_AUTH
    @_PROJECT
    @_UPLOAD
    @patch.object(document_api, "_get_ddb")
    def test_put_brd_succeeds_with_doc_level_fields_only(self, mock_ddb, *_):
        fake_ddb = _configure_ddb_for_put(mock_ddb)
        resp = document_api.lambda_handler(_make_event(body=_put_body()), None)
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))
        item = fake_ddb.put_item.call_args[1]["Item"]
        self.assertEqual(item["document_subtype"], {"S": "brd"})
        self.assertNotIn("subtypepattern", item)

    @_AUTH
    @_PROJECT
    @_UPLOAD
    @patch.object(document_api, "_get_ddb")
    def test_put_brd_with_subtypepattern_is_wrong_subtype(self, mock_ddb, *_):
        _configure_ddb_for_put(mock_ddb)
        resp = document_api.lambda_handler(_make_event(body=_put_body(subtypepattern="brd")), None)
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(_error_code(resp), "SUBTYPEPATTERN_WRONG_SUBTYPE")


class BrdTitleHygieneTests(unittest.TestCase):
    @_AUTH
    @_PROJECT
    @_UPLOAD
    @patch.object(document_api, "_get_ddb")
    def test_brd_title_with_colon_prefix_rejected(self, mock_ddb, *_):
        _configure_ddb_for_put(mock_ddb)
        resp = document_api.lambda_handler(_make_event(body=_put_body(title="BRD: Feed Freshness")), None)
        self.assertEqual(resp["statusCode"], 400)
        body = _resp_body(resp)
        self.assertEqual(_error_code(resp), "DOC_TITLE_COLON_PREFIX_DISALLOWED")
        self.assertIn("document_subtype='brd'", body["remediation"])
        self.assertEqual(body["dictionary_entity"], "document.brd")

    @_AUTH
    @_PROJECT
    @_UPLOAD
    @patch.object(document_api, "_get_ddb")
    def test_brd_title_with_dash_separator_passes(self, mock_ddb, *_):
        _configure_ddb_for_put(mock_ddb)
        resp = document_api.lambda_handler(_make_event(body=_put_body(title="BRD -- Feed Freshness")), None)
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))

    @_AUTH
    @_PROJECT
    @_UPLOAD
    @patch.object(document_api, "_get_ddb")
    def test_doc_title_with_brd_prefix_redirects_to_subtype(self, mock_ddb, *_):
        _configure_ddb_for_put(mock_ddb)
        resp = document_api.lambda_handler(
            _make_event(body=_put_body(document_subtype="doc", confirm_subtype=True, title="BRD: Feed Freshness")),
            None,
        )
        self.assertEqual(resp["statusCode"], 400)
        body = _resp_body(resp)
        self.assertIn("document_subtype='brd'", body["remediation"])
        self.assertNotIn("subtypepattern", body["remediation"])

    @_AUTH
    @_PROJECT
    @_UPLOAD
    @patch.object(document_api, "_get_ddb")
    def test_doc_title_with_other_prefix_keeps_subtypepattern_redirect(self, mock_ddb, *_):
        _configure_ddb_for_put(mock_ddb)
        resp = document_api.lambda_handler(
            _make_event(body=_put_body(document_subtype="doc", confirm_subtype=True, title="Runbook: Deploy")),
            None,
        )
        self.assertEqual(resp["statusCode"], 400)
        body = _resp_body(resp)
        self.assertEqual(
            body["remediation"],
            "Remove the prefix from title and populate subtypepattern with the lowercased prefix word.",
        )
        self.assertEqual(body["dictionary_entity"], "document.doc")


class SubtypepatternGraduatedTests(unittest.TestCase):
    @_AUTH
    @_PROJECT
    @_UPLOAD
    @patch.object(document_api, "_get_ddb")
    def test_put_doc_with_graduated_pattern_rejected(self, mock_ddb, *_):
        fake_ddb = _configure_ddb_for_put(mock_ddb)
        resp = document_api.lambda_handler(
            _make_event(body=_put_body(document_subtype="doc", confirm_subtype=True, subtypepattern=" BRD ")),
            None,
        )
        self.assertEqual(resp["statusCode"], 400)
        body = _resp_body(resp)
        self.assertEqual(_error_code(resp), "SUBTYPEPATTERN_GRADUATED")
        self.assertEqual(body["graduated_to"], "brd")
        self.assertEqual(body["dictionary_entity"], "document.brd")
        self.assertIn("document_subtype='brd'", body["error"])
        fake_ddb.put_item.assert_not_called()

    @_AUTH
    @_PROJECT
    @_UPLOAD
    @patch.object(document_api, "_get_ddb")
    def test_put_doc_with_research_pattern_still_allowed(self, mock_ddb, *_):
        _configure_ddb_for_put(mock_ddb)
        resp = document_api.lambda_handler(
            _make_event(body=_put_body(document_subtype="doc", confirm_subtype=True, subtypepattern="research")),
            None,
        )
        self.assertEqual(resp["statusCode"], 201, _resp_body(resp))

    @_AUTH
    @patch.object(document_api, "_get_ddb")
    def test_patch_setting_graduated_pattern_rejected(self, mock_ddb, *_):
        fake_ddb = MagicMock()
        fake_ddb.get_item.return_value = {"Item": _legacy_brd_item(subtypepattern={"S": "runbook"})}
        mock_ddb.return_value = fake_ddb
        resp = document_api.lambda_handler(
            _make_event(method="PATCH", path="/api/v1/documents/DOC-LEGACYBRD01", body={"subtypepattern": "brd"}),
            None,
        )
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(_error_code(resp), "SUBTYPEPATTERN_GRADUATED")
        fake_ddb.update_item.assert_not_called()


class LegacyBrdMigrationPatchTests(unittest.TestCase):
    """The backfill PATCH: doc + subtypepattern=brd -> document_subtype=brd, metadata-only."""

    def _patch(self, mock_ddb, body, item=None, if_match=None):
        fake_ddb = MagicMock()
        fake_ddb.get_item.return_value = {"Item": item or _legacy_brd_item()}
        fake_ddb.update_item.return_value = {}
        mock_ddb.return_value = fake_ddb
        event = _make_event(method="PATCH", path="/api/v1/documents/DOC-LEGACYBRD01", body=body)
        if if_match:
            event["headers"]["If-Match"] = f'"{if_match}"'
        return fake_ddb, document_api.lambda_handler(event, None)

    @_AUTH
    @patch.object(document_api, "_get_ddb")
    def test_backfill_patch_moves_subtype_and_clears_pattern(self, mock_ddb, *_):
        fake_ddb, resp = self._patch(
            mock_ddb,
            {"document_subtype": "brd", "subtypepattern": "", "caused_by": "ENC-TSK-S25"},
            if_match="a" * 64,
        )
        self.assertEqual(resp["statusCode"], 200, _resp_body(resp))
        kwargs = fake_ddb.update_item.call_args[1]
        values = kwargs["ExpressionAttributeValues"]
        self.assertEqual(values[":ds_new"], {"S": "brd"})
        self.assertEqual(values[":sp"], {"S": ""})
        self.assertEqual(values[":expected_hash"], {"S": "a" * 64})
        # Metadata-only: no content write, so the content_hash is never reassigned.
        self.assertNotIn("content_hash = ", kwargs["UpdateExpression"])

    @_AUTH
    @patch.object(document_api, "_get_ddb")
    def test_subtype_change_off_doc_clears_stale_pattern(self, mock_ddb, *_):
        fake_ddb, resp = self._patch(mock_ddb, {"document_subtype": "brd"})
        self.assertEqual(resp["statusCode"], 200, _resp_body(resp))
        values = fake_ddb.update_item.call_args[1]["ExpressionAttributeValues"]
        self.assertEqual(values[":ds_new"], {"S": "brd"})
        self.assertEqual(values[":sp"], {"S": ""})

    @_AUTH
    @patch.object(document_api, "_get_ddb")
    def test_content_patch_on_unmigrated_legacy_brd_still_allowed(self, mock_ddb, *_):
        fake_ddb, resp = self._patch(mock_ddb, {"description": "updated"})
        self.assertEqual(resp["statusCode"], 200, _resp_body(resp))
        values = fake_ddb.update_item.call_args[1]["ExpressionAttributeValues"]
        self.assertNotIn(":sp", values)

    @_AUTH
    @patch.object(document_api, "_get_ddb")
    def test_backfill_patch_with_stale_hash_is_rejected(self, mock_ddb, *_):
        fake_ddb, resp = self._patch(
            mock_ddb, {"document_subtype": "brd", "subtypepattern": ""}, if_match="b" * 64
        )
        self.assertEqual(resp["statusCode"], 412)
        # Only the rejected-event history append runs (ENC-TSK-P72); the subtype never moves.
        for call in fake_ddb.update_item.call_args_list:
            self.assertNotIn(":ds_new", call[1].get("ExpressionAttributeValues", {}))


class BrdSearchAliasTests(unittest.TestCase):
    def _seed(self):
        def row(doc_id, subtype, pattern=""):
            item = {
                "document_id": {"S": doc_id},
                "project_id": {"S": "enceladus"},
                "title": {"S": doc_id},
                "status": {"S": "active"},
                "document_subtype": {"S": subtype},
                "created_at": {"S": "2026-10-01T00:00:00Z"},
                "updated_at": {"S": "2026-10-01T00:00:00Z"},
                "keywords": {"L": []},
                "related_items": {"L": []},
            }
            if pattern:
                item["subtypepattern"] = {"S": pattern}
            return item

        return [
            row("DOC-BRD-NEW", "brd"),
            row("DOC-BRD-LEGACY", "doc", "brd"),
            row("DOC-RESEARCH", "doc", "research"),
            row("DOC-IDEA", "idea"),
        ]

    def _search(self, mock_ddb, query):
        fake_ddb = MagicMock()
        fake_ddb.scan.return_value = {"Items": self._seed()}
        mock_ddb.return_value = fake_ddb
        resp = document_api.lambda_handler(
            _make_event(method="GET", path="/api/v1/documents/search", query_params=query), None
        )
        self.assertEqual(resp["statusCode"], 200, _resp_body(resp))
        body = _resp_body(resp)
        return {d["document_id"] for d in body["documents"]}, body

    @_AUTH
    @patch.object(document_api, "_get_ddb")
    def test_document_subtype_brd_is_strict(self, mock_ddb, *_):
        ids, body = self._search(mock_ddb, {"document_subtype": "brd"})
        self.assertEqual(ids, {"DOC-BRD-NEW"})
        self.assertNotIn("deprecation", body)

    @_AUTH
    @patch.object(document_api, "_get_ddb")
    def test_subtypepattern_brd_alias_returns_union_with_deprecation(self, mock_ddb, *_):
        ids, body = self._search(mock_ddb, {"subtypepattern": "BRD"})
        self.assertEqual(ids, {"DOC-BRD-NEW", "DOC-BRD-LEGACY"})
        self.assertEqual(body["deprecation"]["replacement"], "document_subtype=brd")
        self.assertEqual(body["deprecation"]["ref"], "ENC-FTR-152")

    @_AUTH
    @patch.object(document_api, "_get_ddb")
    def test_doc_plus_subtypepattern_brd_is_raw_legacy_probe(self, mock_ddb, *_):
        ids, body = self._search(mock_ddb, {"document_subtype": "doc", "subtypepattern": "brd"})
        self.assertEqual(ids, {"DOC-BRD-LEGACY"})
        self.assertIn("deprecation", body)

    @_AUTH
    @patch.object(document_api, "_get_ddb")
    def test_non_graduated_pattern_filter_unchanged(self, mock_ddb, *_):
        ids, body = self._search(mock_ddb, {"subtypepattern": "research"})
        self.assertEqual(ids, {"DOC-RESEARCH"})
        self.assertNotIn("deprecation", body)


if __name__ == "__main__":
    unittest.main()
