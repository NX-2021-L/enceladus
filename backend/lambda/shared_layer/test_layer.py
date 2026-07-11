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
    build_create_transact_puts,
    write_target_tables,
)


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


class _FakePaginator:
    """Emulates ddb.get_paginator('query') over in-memory raw items keyed by
    (table, project_id). Supports the two KeyConditionExpressions used by
    iter_project_relationship_items: begins_with prefix and BETWEEN bounds."""

    def __init__(self, data, call_log):
        self._data = data
        self._call_log = call_log

    def paginate(self, **kwargs):
        self._call_log.append(kwargs)
        table = kwargs["TableName"]
        values = kwargs["ExpressionAttributeValues"]
        pid = values[":pid"]["S"]
        items = self._data.get((table, pid), [])
        cond = kwargs["KeyConditionExpression"]
        if "BETWEEN" in cond:
            lo, hi = values[":lo"]["S"], values[":hi"]["S"]
            matched = [i for i in items if lo <= i["record_id"]["S"] <= hi]
        else:
            prefix = values[":rel_prefix"]["S"]
            matched = [i for i in items if i["record_id"]["S"].startswith(prefix)]
        yield {"Items": matched, "ScannedCount": len(matched)}


class _FakeDDB:
    def __init__(self, data):
        self.data = data
        self.call_log = []

    def get_paginator(self, op):
        assert op == "query"
        return _FakePaginator(self.data, self.call_log)


def _rel_item(source_id, rel_type, target_id, weight="1"):
    return {
        "project_id": {"S": "enceladus"},
        "record_id": {"S": f"rel#{source_id}#{rel_type}#{target_id}"},
        "weight": {"N": weight},
        "confidence": {"N": "0.9"},
        "created_at": {"S": "2026-07-11T00:00:00Z"},
    }


class RangeBoundedRelationshipQueryTests(unittest.TestCase):
    """ENC-TSK-M55: fallback elimination + range-bounded per-project queries."""

    REL_TABLE = "enceladus-relationships-gamma"
    TRK_TABLE = "devops-project-tracker-gamma"

    def _env(self, authoritative=False, extra=None):
        env = {"RELATIONSHIPS_TABLE": self.REL_TABLE}
        if authoritative:
            env["RELATIONSHIPS_TABLE_AUTHORITATIVE"] = "true"
        env.update(extra or {})
        return patch.dict(os.environ, env, clear=False)

    def _edges_data(self):
        items = [
            _rel_item("ENC-TSK-M10", "relates-to", "ENC-ISS-100"),
            _rel_item("ENC-TSK-M55", "implements", "ENC-FTR-130"),
            _rel_item("ENC-ISS-100", "blocks", "ENC-TSK-M10"),
            _rel_item("ENC-TSK-A01", "relates-to", "ENC-TSK-M10"),
        ]
        return {
            (self.REL_TABLE, "enceladus"): list(items),
            (self.TRK_TABLE, "enceladus"): list(items),
        }

    def test_relationships_authoritative_flag_parsing(self):
        from enceladus_shared.relationship_store import relationships_authoritative

        with patch.dict(os.environ, {"RELATIONSHIPS_TABLE_AUTHORITATIVE": "false"}, clear=False):
            self.assertFalse(relationships_authoritative())
        with patch.dict(os.environ, {"RELATIONSHIPS_TABLE_AUTHORITATIVE": "true"}, clear=False):
            self.assertTrue(relationships_authoritative())

    def test_build_page_sk_ranges_single_range_default(self):
        from enceladus_shared.relationship_store import build_page_sk_ranges

        ranges = build_page_sk_ranges(["ENC-TSK-M55", "ENC-ISS-100", "ENC-TSK-A01"])
        self.assertEqual(len(ranges), 1)
        lo, hi = ranges[0]
        self.assertEqual(lo, "rel#ENC-ISS-100#")
        self.assertTrue(hi.startswith("rel#ENC-TSK-M55#"))
        # Every page source's edge keys fall inside the bounds.
        for sk in (
            "rel#ENC-ISS-100#blocks#ENC-TSK-M10",
            "rel#ENC-TSK-A01#relates-to#ENC-TSK-M10",
            "rel#ENC-TSK-M55#implements#ENC-FTR-130",
        ):
            self.assertTrue(lo <= sk <= hi, sk)
        # Out-of-range sources are excluded.
        self.assertFalse(lo <= "rel#ENC-TSK-Z99#relates-to#X" <= hi)

    def test_build_page_sk_ranges_per_prefix_clusters(self):
        from enceladus_shared.relationship_store import build_page_sk_ranges

        ranges = build_page_sk_ranges(
            ["ENC-TSK-M55", "ENC-ISS-100", "ENC-TSK-A01", "ENC-FTR-130"],
            max_ranges=3,
        )
        self.assertEqual(len(ranges), 3)
        self.assertEqual(ranges[0][0], "rel#ENC-FTR-130#")
        self.assertEqual(ranges[1][0], "rel#ENC-ISS-100#")
        self.assertEqual(ranges[2][0], "rel#ENC-TSK-A01#")

    def test_build_page_sk_ranges_empty(self):
        from enceladus_shared.relationship_store import build_page_sk_ranges

        self.assertEqual(build_page_sk_ranges([]), [])

    def test_authoritative_skips_tracker_fallback_pass(self):
        from enceladus_shared.relationship_store import iter_project_relationship_items

        ddb = _FakeDDB(self._edges_data())
        with self._env(authoritative=True):
            items = list(
                iter_project_relationship_items(
                    ddb, self.TRK_TABLE, ["enceladus"], ser_s=lambda v: {"S": v}
                )
            )
        self.assertEqual(len(items), 4)
        queried_tables = {c["TableName"] for c in ddb.call_log}
        self.assertEqual(queried_tables, {self.REL_TABLE})
        self.assertEqual(len(ddb.call_log), 1)

    def test_non_authoritative_keeps_dual_pass(self):
        from enceladus_shared.relationship_store import iter_project_relationship_items

        ddb = _FakeDDB(self._edges_data())
        with self._env(authoritative=False):
            items = list(
                iter_project_relationship_items(
                    ddb, self.TRK_TABLE, ["enceladus"], ser_s=lambda v: {"S": v}
                )
            )
        self.assertEqual(len(items), 4)  # merged dedup, rel table wins
        queried_tables = {c["TableName"] for c in ddb.call_log}
        self.assertEqual(queried_tables, {self.REL_TABLE, self.TRK_TABLE})

    def test_range_bounded_query_shape_and_stats(self):
        from enceladus_shared.relationship_store import (
            build_page_sk_ranges,
            iter_project_relationship_items,
        )

        ddb = _FakeDDB(self._edges_data())
        ranges = {"enceladus": build_page_sk_ranges(["ENC-TSK-M10", "ENC-TSK-M55"])}
        stats = {}
        with self._env(authoritative=True):
            items = list(
                iter_project_relationship_items(
                    ddb,
                    self.TRK_TABLE,
                    ["enceladus"],
                    ser_s=lambda v: {"S": v},
                    sk_ranges_by_project=ranges,
                    stats=stats,
                )
            )
        # Both in-span sources' edges are returned; out-of-span sources are not.
        sks = {i["record_id"]["S"] for i in items}
        self.assertIn("rel#ENC-TSK-M10#relates-to#ENC-ISS-100", sks)
        self.assertIn("rel#ENC-TSK-M55#implements#ENC-FTR-130", sks)
        self.assertNotIn("rel#ENC-ISS-100#blocks#ENC-TSK-M10", sks)
        self.assertNotIn("rel#ENC-TSK-A01#relates-to#ENC-TSK-M10", sks)
        self.assertIn("BETWEEN", ddb.call_log[0]["KeyConditionExpression"])
        self.assertEqual(stats["query_count"], 1)
        self.assertEqual(stats["items_seen"], 2)
        self.assertEqual(stats["scanned_count"], 2)

    def test_typed_relationships_parity_with_page_scoping(self):
        """Output contract: typed_relationships byte-identical for in-page
        records whether or not page scoping is applied (AC-2)."""
        from enceladus_shared.record_extensions import (
            query_typed_relationships_for_projects,
        )

        def ddb_str(raw, key):
            val = raw.get(key, {})
            return val.get("S", "") if isinstance(val, dict) else ""

        def ddb_float(raw, key):
            try:
                return float(raw.get(key, {}).get("N", "0"))
            except (TypeError, ValueError):
                return 0.0

        page_ids = ["ENC-TSK-M10", "ENC-TSK-M55", "ENC-ISS-100", "ENC-TSK-A01"]
        with self._env(authoritative=True):
            baseline = query_typed_relationships_for_projects(
                _FakeDDB(self._edges_data()),
                self.TRK_TABLE,
                ["enceladus"],
                ddb_str=ddb_str,
                ddb_float=ddb_float,
            )
            scoped = query_typed_relationships_for_projects(
                _FakeDDB(self._edges_data()),
                self.TRK_TABLE,
                ["enceladus"],
                ddb_str=ddb_str,
                ddb_float=ddb_float,
                source_ids_by_project={"enceladus": page_ids},
            )
        for rid in page_ids:
            self.assertEqual(baseline.get(rid), scoped.get(rid), rid)

    def test_kill_switch_disables_range_bounding(self):
        from enceladus_shared.record_extensions import (
            query_typed_relationships_for_projects,
        )

        def ddb_str(raw, key):
            val = raw.get(key, {})
            return val.get("S", "") if isinstance(val, dict) else ""

        ddb = _FakeDDB(self._edges_data())
        with self._env(
            authoritative=True, extra={"FEED_EDGE_RANGE_BOUND_DISABLED": "true"}
        ):
            query_typed_relationships_for_projects(
                ddb,
                self.TRK_TABLE,
                ["enceladus"],
                ddb_str=ddb_str,
                ddb_float=lambda raw, key: 0.0,
                source_ids_by_project={"enceladus": ["ENC-TSK-M10"]},
            )
        self.assertIn("begins_with", ddb.call_log[0]["KeyConditionExpression"])


if __name__ == "__main__":
    unittest.main()
