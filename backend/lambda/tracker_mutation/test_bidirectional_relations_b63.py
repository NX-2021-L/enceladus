"""ENC-TSK-B63 AC-7 / ENC-ISS-241: bidirectional related_*_ids enforcement tests.

Mock-based coverage of the atomic reverse-edge writer and the tracker.relate
convenience action, in the established tracker_mutation house style (patch
_get_ddb / _get_record_raw / _get_prefix_map_cached; no live AWS). The
end-to-end Neo4j projection traversal of the now-symmetric edges is validated on
gamma as the OGTM live-traversal criterion (related_*_ids already projects an
existing edge type, so no new edge type is introduced).

Run: python3 -m pytest test_bidirectional_relations_b63.py -v
"""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(__file__))

_spec = importlib.util.spec_from_file_location(
    "lambda_function",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
lf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lf)


def _raw(record_id_sk: str, **fields) -> dict:
    """Build a raw DynamoDB item with related_*_ids list fields."""
    item = {"record_id": {"S": record_id_sk}}
    for k, v in fields.items():
        if isinstance(v, list):
            item[k] = {"L": [{"S": str(x)} for x in v]}
        else:
            item[k] = {"S": str(v)}
    return item


class TestPureHelpers(unittest.TestCase):
    def test_inverse_relation_field(self):
        self.assertEqual(lf._inverse_relation_field("task"), "related_task_ids")
        self.assertEqual(lf._inverse_relation_field("issue"), "related_issue_ids")
        self.assertEqual(lf._inverse_relation_field("feature"), "related_feature_ids")
        # plan/lesson have no canonical related_<type>_ids inverse field.
        self.assertIsNone(lf._inverse_relation_field("plan"))
        self.assertIsNone(lf._inverse_relation_field("lesson"))

    def test_field_to_target_type(self):
        self.assertEqual(lf._RELATION_FIELD_TO_TARGET_TYPE["related_issue_ids"], "issue")
        self.assertEqual(
            set(lf._RELATION_FIELD_TO_TARGET_TYPE.values()),
            set(lf._BIDIRECTIONAL_SOURCE_TYPES),
        )

    def test_flag_default_on(self):
        # No AppConfig / env override in the test env -> default True.
        os.environ.pop("ENABLE_BIDIRECTIONAL_RELATIONS", None)
        self.assertTrue(lf._bidirectional_relations_enabled())

    def test_flag_env_rollback(self):
        with patch.dict(os.environ, {"ENABLE_BIDIRECTIONAL_RELATIONS": "false"}):
            # AppConfig may still win in a real env, but in unit context the env
            # fallback path resolves False (rollback validated, ENC-TSK-B63 AC-4).
            self.assertFalse(lf._bidirectional_relations_enabled())


class TestBidirectionalWriter(unittest.TestCase):
    def setUp(self):
        self.ddb = MagicMock()

    def _call(self, *, field, new_ids, item_data, targets):
        """targets: {record_id_sk: raw_item or None}."""
        def _grr(project, rtype, rid):
            sk = f"{rtype}#{rid.upper()}"
            return targets.get(sk)

        with patch.object(lf, "_get_ddb", return_value=self.ddb), \
                patch.object(lf, "_get_record_raw", side_effect=_grr), \
                patch.object(lf, "_get_prefix_map_cached", return_value={"ENC": "enceladus"}):
            return lf._write_relation_field_bidirectional(
                "enceladus", "task", "ENC-TSK-1", field, new_ids, item_data, {},
            )

    def test_addition_writes_inverse_atomically(self):
        resp = self._call(
            field="related_issue_ids",
            new_ids=["ENC-ISS-9"],
            item_data={"related_issue_ids": []},
            targets={"issue#ENC-ISS-9": _raw("issue#ENC-ISS-9", related_task_ids=[])},
        )
        self.assertEqual(resp["statusCode"], 200)
        self.ddb.transact_write_items.assert_called_once()
        items = self.ddb.transact_write_items.call_args.kwargs["TransactItems"]
        # primary (source) + 1 inverse (target)
        self.assertEqual(len(items), 2)
        # inverse update targets the issue's related_task_ids with the source id
        inv = items[1]["Update"]
        self.assertEqual(inv["ExpressionAttributeNames"]["#inv"], "related_task_ids")
        self.assertEqual(inv["Key"]["record_id"]["S"], "issue#ENC-ISS-9")
        self.assertIn("attribute_exists(record_id)", inv["ConditionExpression"])

    def test_missing_target_fails_atomically(self):
        resp = self._call(
            field="related_issue_ids",
            new_ids=["ENC-ISS-404"],
            item_data={"related_issue_ids": []},
            targets={"issue#ENC-ISS-404": None},  # target does not exist
        )
        self.assertEqual(resp["statusCode"], 404)
        import json as _json
        body = _json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "RELATION_TARGET_NOT_FOUND")
        # No silent unidirectional edge: the transaction is never issued.
        self.ddb.transact_write_items.assert_not_called()

    def test_idempotent_skips_existing_inverse(self):
        resp = self._call(
            field="related_issue_ids",
            new_ids=["ENC-ISS-9"],
            item_data={"related_issue_ids": []},
            targets={"issue#ENC-ISS-9": _raw(
                "issue#ENC-ISS-9", related_task_ids=["ENC-TSK-1"])},
        )
        self.assertEqual(resp["statusCode"], 200)
        items = self.ddb.transact_write_items.call_args.kwargs["TransactItems"]
        # inverse already present -> only the primary write, no target update
        self.assertEqual(len(items), 1)
        self.assertEqual(resp_affected(resp), [])

    def test_removal_writes_inverse_removal(self):
        resp = self._call(
            field="related_issue_ids",
            new_ids=[],  # clearing the list removes ENC-ISS-9
            item_data={"related_issue_ids": ["ENC-ISS-9"]},
            targets={"issue#ENC-ISS-9": _raw(
                "issue#ENC-ISS-9", related_task_ids=["ENC-TSK-1", "ENC-TSK-2"])},
        )
        self.assertEqual(resp["statusCode"], 200)
        items = self.ddb.transact_write_items.call_args.kwargs["TransactItems"]
        self.assertEqual(len(items), 2)
        inv_vals = items[1]["Update"]["ExpressionAttributeValues"][":inv"]["L"]
        remaining = [x["S"] for x in inv_vals]
        self.assertEqual(remaining, ["ENC-TSK-2"])  # source removed from inverse

    def test_removal_missing_target_is_tolerated(self):
        # Removing a reference to an already-deleted target must not fail the write.
        resp = self._call(
            field="related_issue_ids",
            new_ids=[],
            item_data={"related_issue_ids": ["ENC-ISS-GONE"]},
            targets={"issue#ENC-ISS-GONE": None},
        )
        self.assertEqual(resp["statusCode"], 200)
        items = self.ddb.transact_write_items.call_args.kwargs["TransactItems"]
        self.assertEqual(len(items), 1)  # only the primary write

    def test_transaction_cancelled_returns_409(self):
        self.ddb.transact_write_items.side_effect = ClientError(
            {"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems"
        )
        resp = self._call(
            field="related_issue_ids",
            new_ids=["ENC-ISS-9"],
            item_data={"related_issue_ids": []},
            targets={"issue#ENC-ISS-9": _raw("issue#ENC-ISS-9", related_task_ids=[])},
        )
        self.assertEqual(resp["statusCode"], 409)


def resp_affected(resp) -> list:
    import json as _json
    return _json.loads(resp["body"]).get("affected_targets", [])


class TestHandleRelate(unittest.TestCase):
    def setUp(self):
        self.ddb = MagicMock()

    def _relate(self, body, records):
        def _grr(project, rtype, rid):
            sk = f"{rtype}#{rid.upper()}"
            return records.get(sk)

        with patch.object(lf, "_get_ddb", return_value=self.ddb), \
                patch.object(lf, "_get_record_raw", side_effect=_grr), \
                patch.object(lf, "_get_prefix_map_cached", return_value={"ENC": "enceladus"}):
            return lf._handle_relate("enceladus", body)

    def test_relate_writes_both_sides(self):
        resp = self._relate(
            {"source_id": "ENC-TSK-1", "target_id": "ENC-FTR-7"},
            {
                "task#ENC-TSK-1": _raw("task#ENC-TSK-1", related_feature_ids=[]),
                "feature#ENC-FTR-7": _raw("feature#ENC-FTR-7", related_task_ids=[]),
            },
        )
        self.assertEqual(resp["statusCode"], 200)
        items = self.ddb.transact_write_items.call_args.kwargs["TransactItems"]
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["Update"]["ExpressionAttributeNames"]["#fld"], "related_feature_ids")
        self.assertEqual(items[1]["Update"]["ExpressionAttributeNames"]["#inv"], "related_task_ids")

    def test_relate_self_rejected(self):
        resp = self._relate(
            {"source_id": "ENC-TSK-1", "target_id": "ENC-TSK-1"}, {})
        self.assertEqual(resp["statusCode"], 400)

    def test_relate_unsupported_target_type_rejected(self):
        resp = self._relate(
            {"source_id": "ENC-TSK-1", "target_id": "ENC-PLN-1"},
            {"task#ENC-TSK-1": _raw("task#ENC-TSK-1")},
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_relate_missing_source_404(self):
        resp = self._relate(
            {"source_id": "ENC-TSK-404", "target_id": "ENC-FTR-7"},
            {"task#ENC-TSK-404": None, "feature#ENC-FTR-7": _raw("feature#ENC-FTR-7")},
        )
        self.assertEqual(resp["statusCode"], 404)

    def test_relate_self_heals_missing_inverse(self):
        # Forward edge already present on source, but inverse missing on target.
        resp = self._relate(
            {"source_id": "ENC-TSK-1", "target_id": "ENC-FTR-7"},
            {
                "task#ENC-TSK-1": _raw("task#ENC-TSK-1", related_feature_ids=["ENC-FTR-7"]),
                "feature#ENC-FTR-7": _raw("feature#ENC-FTR-7", related_task_ids=[]),
            },
        )
        self.assertEqual(resp["statusCode"], 200)
        items = self.ddb.transact_write_items.call_args.kwargs["TransactItems"]
        # force_add_targets ensures the inverse is repaired even with no forward diff.
        self.assertEqual(len(items), 2)


class TestRouting(unittest.TestCase):
    def test_relate_route_registered(self):
        self.assertIsNotNone(lf._RE_RELATE.match("/enceladus/relate"))
        self.assertIsNotNone(lf._RE_RELATE.match("/api/v1/tracker/enceladus/relate"))
        self.assertIsNone(lf._RE_RELATE.match("/enceladus/task/ENC-TSK-1"))


if __name__ == "__main__":
    unittest.main()
