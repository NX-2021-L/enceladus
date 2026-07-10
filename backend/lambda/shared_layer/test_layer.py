"""test_layer.py — Unit tests for enceladus_shared layer modules.

Run from shared_layer directory:
    PYTHONPATH=python python3 -m pytest test_layer.py -v
"""

from __future__ import annotations

import json
import os
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
from enceladus_shared.record_extensions import (
    attach_record_extensions,
    compute_freshness,
    compute_max_degree,
    compute_structural_importance,
)
from enceladus_shared.relationship_store import (
    _fetch_project_relationship_items,
    build_create_transact_puts,
    iter_project_relationship_items,
    write_target_tables,
)
from enceladus_shared.record_extensions import query_typed_relationships_for_projects


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


class RecordExtensionsTests(unittest.TestCase):
    def test_structural_importance_absolute_degree(self):
        edges = {
            "A": [{"target_id": "B"}, {"target_id": "C"}],
            "B": [{"target_id": "A"}],
        }
        max_degree = compute_max_degree(edges)
        self.assertEqual(compute_structural_importance("A", edges, max_degree), 1.0)
        self.assertEqual(compute_structural_importance("C", edges, max_degree), 1 / 3)

    def test_attach_record_extensions_sets_context_node(self):
        edges = {"ENC-TSK-001": [{"relationship_type": "relates-to", "target_id": "ENC-TSK-002"}]}
        record = {
            "task_id": "ENC-TSK-001",
            "title": "Example",
            "description": "x" * 100,
            "updated_at": "2026-07-01T00:00:00Z",
        }
        attach_record_extensions([record], "task_id", "task", edges, max_degree=2)
        self.assertEqual(len(record["typed_relationships"]), 1)
        ctx = record["context_node"]
        self.assertIn("freshness_score", ctx)
        self.assertGreater(ctx["structural_importance"], 0)
        self.assertGreater(ctx["information_density"], 0)

    def test_attach_record_extensions_requires_typed_id_key(self):
        """Tracker GET deserializes item_id only; handler must promote to plan_id first."""
        record = {"item_id": "ENC-PLN-006", "title": "Plan", "updated_at": "2026-07-01T00:00:00Z"}
        attach_record_extensions([record], "plan_id", "plan", {}, max_degree=1)
        self.assertNotIn("context_node", record)
        record["plan_id"] = record["item_id"]
        attach_record_extensions([record], "plan_id", "plan", {}, max_degree=1)
        self.assertIn("context_node", record)

    def test_compute_freshness_missing_timestamp_defaults(self):
        self.assertEqual(compute_freshness(None, "task"), 0.5)


class RelationshipStoreTests(unittest.TestCase):
    def test_write_target_tables_dual_write(self):
        with patch.dict(
            os.environ,
            {"RELATIONSHIPS_TABLE": "enceladus-relationships-gamma"},
            clear=False,
        ):
            targets = write_target_tables("devops-project-tracker-gamma")
        self.assertEqual(
            targets,
            ["enceladus-relationships-gamma", "devops-project-tracker-gamma"],
        )

    def test_build_create_transact_puts_dual_write(self):
        forward = {"project_id": {"S": "enceladus"}, "record_id": {"S": "rel#A#relates-to#B"}}
        inverse = {"project_id": {"S": "enceladus"}, "record_id": {"S": "rel#B#related-to#A"}}
        with patch.dict(
            os.environ,
            {"RELATIONSHIPS_TABLE": "enceladus-relationships-gamma"},
            clear=False,
        ):
            items = build_create_transact_puts("devops-project-tracker-gamma", forward, inverse)
        self.assertEqual(len(items), 4)
        tables = {item["Put"]["TableName"] for item in items}
        self.assertEqual(
            tables,
            {"enceladus-relationships-gamma", "devops-project-tracker-gamma"},
        )


def _rel_item(project_id: str, sk: str) -> dict:
    return {"project_id": {"S": project_id}, "record_id": {"S": sk}}


class _FakeRelationshipPaginator:
    def __init__(self, items_by_table_and_project):
        self._items_by_table_and_project = items_by_table_and_project

    def paginate(self, **kwargs):
        table = kwargs["TableName"]
        pid = kwargs["ExpressionAttributeValues"][":pid"]["S"]
        items = self._items_by_table_and_project.get((table, pid), [])
        yield {"Items": items}


class _FakeRelationshipDdb:
    """Records every query call so tests can assert per-project isolation."""

    def __init__(self, items_by_table_and_project):
        self._items_by_table_and_project = items_by_table_and_project
        self.calls: list = []

    def get_paginator(self, name):
        assert name == "query"
        return _FakeRelationshipPaginator(self._items_by_table_and_project)


class IterProjectRelationshipItemsTests(unittest.TestCase):
    """ENC-TSK-M49: parallel fan-out must match the prior sequential contract exactly."""

    def _fixture_ddb(self):
        # Two tables (relationships + tracker) x three projects, with one
        # duplicate key across tables (rel_table must win, matching the
        # pre-M49 first-seen-wins merge) and one project with no rows at all.
        return _FakeRelationshipDdb(
            {
                ("enceladus-relationships-gamma", "enceladus"): [
                    _rel_item("enceladus", "rel#A#relates-to#B"),
                    _rel_item("enceladus", "rel#A#blocks#C"),
                ],
                ("devops-project-tracker-gamma", "enceladus"): [
                    # Duplicate of the first row above -- rel_table copy must win.
                    _rel_item("enceladus", "rel#A#relates-to#B"),
                    _rel_item("enceladus", "rel#B#related-to#A"),
                ],
                ("enceladus-relationships-gamma", "cfg"): [
                    _rel_item("cfg", "rel#X#relates-to#Y"),
                ],
                ("devops-project-tracker-gamma", "cfg"): [],
                ("enceladus-relationships-gamma", "empty-proj"): [],
                ("devops-project-tracker-gamma", "empty-proj"): [],
            }
        )

    def test_parity_with_sequential_reference_implementation(self):
        project_ids = ["enceladus", "cfg", "empty-proj"]
        ser_s = lambda value: {"S": value}  # noqa: E731

        with patch.dict(os.environ, {"RELATIONSHIPS_TABLE": "enceladus-relationships-gamma"}, clear=False):
            parallel_result = list(
                iter_project_relationship_items(
                    self._fixture_ddb(), "devops-project-tracker-gamma", project_ids, ser_s=ser_s
                )
            )

            # Reference: call the single-project fetch helper directly, in
            # order, exactly as the pre-M49 sequential loop did.
            sequential_result = []
            rel_table = "enceladus-relationships-gamma"
            for pid in project_ids:
                sequential_result.extend(
                    _fetch_project_relationship_items(
                        self._fixture_ddb(), "devops-project-tracker-gamma", rel_table, pid, "rel#", ser_s
                    )
                )

        self.assertEqual(parallel_result, sequential_result)
        # rel_table's copy of the duplicate key must win (first-seen-wins,
        # tables=[rel_table, tracker_table]).
        enceladus_sks = {r["record_id"]["S"] for r in parallel_result if r["project_id"]["S"] == "enceladus"}
        self.assertEqual(enceladus_sks, {"rel#A#relates-to#B", "rel#A#blocks#C", "rel#B#related-to#A"})

    def test_preserves_original_project_ids_order(self):
        ser_s = lambda value: {"S": value}  # noqa: E731
        # Reversed vs. the fixture's natural table layout -- output order
        # must follow THIS list, not fetch-completion order.
        project_ids = ["empty-proj", "cfg", "enceladus"]

        with patch.dict(os.environ, {"RELATIONSHIPS_TABLE": "enceladus-relationships-gamma"}, clear=False):
            result = list(
                iter_project_relationship_items(
                    self._fixture_ddb(), "devops-project-tracker-gamma", project_ids, ser_s=ser_s
                )
            )

        # cfg's single row must appear before any of enceladus's three rows.
        cfg_index = next(i for i, r in enumerate(result) if r["project_id"]["S"] == "cfg")
        enceladus_indices = [i for i, r in enumerate(result) if r["project_id"]["S"] == "enceladus"]
        self.assertTrue(all(cfg_index < i for i in enceladus_indices))

    def test_empty_project_ids_short_circuits_without_calling_ddb(self):
        ddb = self._fixture_ddb()
        result = list(iter_project_relationship_items(ddb, "devops-project-tracker-gamma", [], ser_s=lambda v: {"S": v}))
        self.assertEqual(result, [])

    def test_falsy_project_ids_are_skipped(self):
        ser_s = lambda value: {"S": value}  # noqa: E731
        with patch.dict(os.environ, {"RELATIONSHIPS_TABLE": "enceladus-relationships-gamma"}, clear=False):
            result = list(
                iter_project_relationship_items(
                    self._fixture_ddb(), "devops-project-tracker-gamma", ["", None, "cfg"], ser_s=ser_s
                )
            )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["project_id"]["S"], "cfg")


class QueryTypedRelationshipsForProjectsTests(unittest.TestCase):
    """ENC-TSK-M49: record_extensions' bare-import-with-fallback still resolves
    iter_project_relationship_items correctly when only the real
    enceladus_shared package (no flat vendored copy) is on sys.path -- the
    exact shared_layer/test_layer.py situation."""

    def test_builds_edges_by_source_via_package_qualified_fallback(self):
        ddb = _FakeRelationshipDdb(
            {
                ("devops-project-tracker-gamma", "enceladus"): [
                    _rel_item("enceladus", "rel#ENC-TSK-1#relates-to#ENC-TSK-2"),
                ],
            }
        )
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("RELATIONSHIPS_TABLE", None)
            edges = query_typed_relationships_for_projects(
                ddb,
                "devops-project-tracker-gamma",
                ["enceladus"],
                ddb_str=lambda item, key: item.get(key, {}).get("S", ""),
                ddb_float=lambda item, key: 0.0,
            )
        self.assertIn("ENC-TSK-1", edges)
        self.assertEqual(edges["ENC-TSK-1"][0]["relationship_type"], "relates-to")
        self.assertEqual(edges["ENC-TSK-1"][0]["target_id"], "ENC-TSK-2")

    def test_prefers_bare_vendored_module_when_present(self):
        """Simulates the real deployed feed_query/tracker_mutation zip, where
        .build_extras vendors relationship_store.py flat at the zip root
        (a bare top-level module, not inside an enceladus_shared/ package)."""
        import types

        sentinel_calls = []

        def fake_iter(ddb, table_name, project_ids, *, ser_s, rel_prefix="rel#"):
            sentinel_calls.append(list(project_ids))
            yield _rel_item("enceladus", "rel#ENC-TSK-9#relates-to#ENC-TSK-8")

        fake_module = types.ModuleType("relationship_store")
        fake_module.iter_project_relationship_items = fake_iter

        with patch.dict(sys.modules, {"relationship_store": fake_module}):
            edges = query_typed_relationships_for_projects(
                _FakeRelationshipDdb({}),
                "devops-project-tracker-gamma",
                ["enceladus"],
                ddb_str=lambda item, key: item.get(key, {}).get("S", ""),
                ddb_float=lambda item, key: 0.0,
            )

        # The bare vendored module's fake was used, not the real package copy.
        self.assertEqual(sentinel_calls, [["enceladus"]])
        self.assertIn("ENC-TSK-9", edges)


if __name__ == "__main__":
    unittest.main()
