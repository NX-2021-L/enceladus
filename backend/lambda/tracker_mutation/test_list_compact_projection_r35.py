"""test_list_compact_projection_r35.py -- compact default list projection
(ENC-TSK-R35, ENC-PLN-100 C3.2, BRD FR-24, ruling A11).

Behavior under test (GET /{project} -> _handle_list_records):
  * TRACKER_LIST_COMPACT=true and no `fields=` -> rows carry only the compact
    summary attributes (no description / *evidence* / history / technical_notes),
    read via a DynamoDB ProjectionExpression on BOTH query branches
    (project-type-index and base table), response labelled projection=compact.
  * `fields=a,b` -> EXACTLY those fields (A11 explicit-fields-exact), cursor
    paging still works; `fields=full` -> whole item, unlabelled.
  * flag off -> byte-for-byte today's behavior (no ProjectionExpression).
  * page size default 50 / hard cap 200; count-style requests -> mode=census.
  * CONTRACT: every in-repo caller of the list route either reads only compact
    fields or passes `fields=` (A11: no silent data loss to any consumer).

Run: python3 -m pytest test_list_compact_projection_r35.py -q
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

import boto3
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

sys.path.insert(0, os.path.dirname(__file__))
_spec = importlib.util.spec_from_file_location(
    "tracker_mutation_list_compact_r35",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
tm = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)

PROJECT = "enceladus"
HEAVY = ("description", "evidence", "documentation_evidence", "transition_evidence",
         "history", "technical_notes", "worklog")


class _SpyDdb:
    """Delegating wrapper recording every query() kwargs."""

    def __init__(self, real):
        self._real = real
        self.queries = []

    def query(self, **kw):
        self.queries.append(kw)
        return self._real.query(**kw)

    def __getattr__(self, name):
        return getattr(self._real, name)


def _body(resp):
    return json.loads(resp["body"])


class CompactListProjectionTests(unittest.TestCase):
    flag = "true"

    def setUp(self):
        self._moto = mock_aws()
        self._moto.start()
        self.addCleanup(self._moto.stop)
        real = boto3.client("dynamodb", region_name="us-west-2")
        real.create_table(
            TableName=tm.DYNAMODB_TABLE,
            AttributeDefinitions=[
                {"AttributeName": "project_id", "AttributeType": "S"},
                {"AttributeName": "record_id", "AttributeType": "S"},
                {"AttributeName": "record_type", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "project_id", "KeyType": "HASH"},
                {"AttributeName": "record_id", "KeyType": "RANGE"},
            ],
            GlobalSecondaryIndexes=[{
                "IndexName": "project-type-index",
                "KeySchema": [
                    {"AttributeName": "project_id", "KeyType": "HASH"},
                    {"AttributeName": "record_type", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }],
            BillingMode="PAY_PER_REQUEST",
        )
        self.real = real
        self.ddb = _SpyDdb(real)
        p = mock.patch.object(tm, "_ddb", self.ddb)
        p.start()
        self.addCleanup(p.stop)
        env = mock.patch.dict(os.environ, {"TRACKER_LIST_COMPACT": self.flag})
        env.start()
        self.addCleanup(env.stop)

    def put_task(self, n: int, status: str = "open"):
        item_id = f"ENC-TSK-{n:04d}"
        self.real.put_item(TableName=tm.DYNAMODB_TABLE, Item={
            "project_id": {"S": PROJECT},
            "record_id": {"S": f"task#{item_id}"},
            "item_id": {"S": item_id},
            "record_type": {"S": "task"},
            "status": {"S": status},
            "title": {"S": f"title {n}"},
            "priority": {"S": "P2"},
            "parent": {"S": "ENC-FTR-001"},
            "related_feature_ids": {"L": [{"S": "ENC-FTR-001"}]},
            "description": {"S": "d" * 500},
            "technical_notes": {"S": "t" * 500},
            "evidence": {"L": [{"M": {"description": {"S": "e"}}}]},
            "documentation_evidence": {"S": '["DOC-AAAA11112222"]'},
            "transition_evidence": {"S": "{}"},
            "worklog": {"L": [{"S": "w1"}]},
            "history": {"L": [{"M": {"status": {"S": "open"}}}]},
            "updated_at": {"S": "2026-01-01T00:00:00Z"},
        })
        return item_id

    def seed(self, n: int = 3):
        for i in range(1, n + 1):
            self.put_task(i)
        # a counter row must still be filtered (needs record_type in projection)
        self.real.put_item(TableName=tm.DYNAMODB_TABLE, Item={
            "project_id": {"S": PROJECT}, "record_id": {"S": "counter#task"},
            "record_type": {"S": "counter"}, "next_num": {"N": "9"},
        })

    def list(self, **params):
        return tm._handle_list_records(PROJECT, {k: str(v) for k, v in params.items()})


class CompactDefaultTests(CompactListProjectionTests):
    def test_compact_default_excludes_heavy_fields_gsi_branch(self):
        self.seed()
        resp = self.list(type="task")
        self.assertEqual(resp["statusCode"], 200)
        body = _body(resp)
        self.assertEqual(body["projection"], "compact")
        self.assertEqual(body["count"], 3)
        for rec in body["records"]:
            for heavy in HEAVY:
                self.assertNotIn(heavy, rec)
            self.assertEqual(rec["priority"], "P2")
            self.assertEqual(rec["parent"], "ENC-FTR-001")
            self.assertEqual(rec["related_feature_ids"], ["ENC-FTR-001"])
            self.assertTrue(rec["title"].startswith("title"))
        q = self.ddb.queries[0]
        self.assertEqual(q["IndexName"], "project-type-index")
        self.assertIn("ProjectionExpression", q)

    def test_compact_default_excludes_heavy_fields_base_branch(self):
        self.seed()
        body = _body(self.list())  # no type -> base table branch
        self.assertEqual(body["projection"], "compact")
        self.assertEqual(body["count"], 3)  # counter row still filtered
        for rec in body["records"]:
            for heavy in HEAVY:
                self.assertNotIn(heavy, rec)
        q = self.ddb.queries[0]
        self.assertNotIn("IndexName", q)
        self.assertIn("ProjectionExpression", q)

    def test_compact_set_never_contains_excluded_fields(self):
        for name in tm._LIST_COMPACT_FIELDS:
            self.assertNotIn("evidence", name)
            self.assertNotIn(name, ("description", "history", "worklog", "technical_notes"))

    def test_filters_and_cursor_still_work_with_projection(self):
        self.seed(3)
        first = _body(self.list(type="task", page_size=2, status="open"))
        self.assertEqual(first["count"], 2)
        self.assertTrue(first["next_cursor"])
        second = _body(self.list(type="task", page_size=2, status="open",
                                 next_cursor=first["next_cursor"]))
        ids = {r["item_id"] for r in first["records"]} | {r["item_id"] for r in second["records"]}
        self.assertEqual(ids, {"ENC-TSK-0001", "ENC-TSK-0002", "ENC-TSK-0003"})


class ExplicitFieldsTests(CompactListProjectionTests):
    def test_fields_exact(self):
        self.seed()
        body = _body(self.list(type="task", fields="title,description"))
        self.assertEqual(body["projection"], "fields")
        self.assertEqual(body["fields"], ["title", "description"])
        for rec in body["records"]:
            self.assertEqual(set(rec), {"title", "description"})  # keys NOT leaked

    def test_fields_exact_with_reserved_words_and_cursor(self):
        self.seed(3)
        first = _body(self.list(type="task", fields="status,update,item_id", page_size=2))
        self.assertTrue(first["next_cursor"])
        for rec in first["records"]:
            self.assertEqual(set(rec), {"status", "item_id"})  # absent attr stays absent
        second = _body(self.list(type="task", fields="status,update,item_id", page_size=2,
                                 next_cursor=first["next_cursor"]))
        self.assertEqual(second["count"], 1)

    def test_fields_exact_base_branch_includes_evidence_when_requested(self):
        self.seed()
        body = _body(self.list(fields="item_id,documentation_evidence,transition_evidence"))
        for rec in body["records"]:
            self.assertEqual(set(rec), {"item_id", "documentation_evidence", "transition_evidence"})

    def test_fields_full_returns_everything_unlabelled(self):
        self.seed()
        body = _body(self.list(type="task", fields="full"))
        self.assertNotIn("projection", body)
        for rec in body["records"]:
            for heavy in HEAVY:
                self.assertIn(heavy, rec)
        self.assertNotIn("ProjectionExpression", self.ddb.queries[0])

    def test_invalid_fields_rejected(self):
        self.seed(1)
        self.assertEqual(self.list(type="task", fields="title;drop")["statusCode"], 400)
        self.assertEqual(self.list(type="task", fields=",")["statusCode"], 400)
        too_many = ",".join(f"f{i}" for i in range(tm._LIST_FIELDS_MAX + 1))
        self.assertEqual(self.list(type="task", fields=too_many)["statusCode"], 400)


class FlagOffTests(CompactListProjectionTests):
    flag = "false"

    def test_flag_off_is_unchanged(self):
        self.seed()
        body = _body(self.list(type="task"))
        self.assertNotIn("projection", body)
        for rec in body["records"]:
            for heavy in HEAVY:
                self.assertIn(heavy, rec)
        self.assertNotIn("ProjectionExpression", self.ddb.queries[0])
        self.assertEqual(body["page_size"], 50)

    def test_flag_off_unset_env_defaults_off(self):
        self.seed(1)
        with mock.patch.dict(os.environ):
            os.environ.pop("TRACKER_LIST_COMPACT", None)
            body = _body(self.list(type="task"))
        self.assertNotIn("projection", body)
        self.assertIn("description", body["records"][0])

    def test_flag_off_limit_zero_not_rerouted(self):
        self.seed(2)
        body = _body(self.list(type="task", limit=0, page_size=0))
        self.assertIn("records", body)  # legacy clamp-to-1 behavior preserved
        self.assertEqual(body["page_size"], 1)

    def test_flag_off_explicit_fields_still_exact(self):
        self.seed(1)
        body = _body(self.list(type="task", fields="title"))
        self.assertEqual(set(body["records"][0]), {"title"})


class PageCapAndCensusRoutingTests(CompactListProjectionTests):
    def test_page_size_default_and_cap(self):
        self.seed(1)
        self.assertEqual(_body(self.list(type="task"))["page_size"], tm._LIST_DEFAULT_PAGE_SIZE)
        self.assertEqual(tm._LIST_DEFAULT_PAGE_SIZE, 50)
        self.assertEqual(_body(self.list(type="task", page_size=100000))["page_size"], 200)
        self.assertEqual(_body(self.list(type="task", page_size="junk"))["page_size"], 50)

    def test_count_true_routes_to_census(self):
        self.seed(3)
        body = _body(self.list(type="task", count="true"))
        self.assertNotIn("records", body)
        self.assertEqual(body["count"], 3)
        self.assertIn("by_type", body)
        self.assertIn("pages", body)

    def test_limit_zero_routes_to_census_when_flag_on(self):
        self.seed(3)
        for params in ({"limit": 0}, {"page_size": 0}):
            body = _body(self.list(type="task", **params))
            self.assertNotIn("records", body)
            self.assertEqual(body["count"], 3)

    def test_explicit_census_mode_unaffected(self):
        self.seed(2)
        body = _body(self.list(type="task", mode="census"))
        self.assertEqual(body["count"], 2)
        self.assertNotIn("records", body)

    def test_count_true_routes_to_census_even_when_flag_off(self):
        self.seed(2)
        with mock.patch.dict(os.environ, {"TRACKER_LIST_COMPACT": "false"}):
            body = _body(self.list(type="task", count="true"))
        self.assertEqual(body["count"], 2)
        self.assertNotIn("records", body)


# ---------------------------------------------------------------------------
# CONTRACT: every in-repo caller of the tracker list route (GET /{project}).
# `reads` = record fields the caller consumes; `fields_marker` = substring that
# must appear in the caller's source when it passes `fields=` (None -> the
# caller must read only compact fields).
# ---------------------------------------------------------------------------
REPO = Path(__file__).resolve().parents[3]

CALLER_CONTRACT = [
    {   # MCP tracker_list -> _summarize_tracker_records (+ orphan detection)
        "name": "mcp tracker_list", "file": "tools/enceladus-mcp-server/server.py",
        "reads": {"id", "item_id", "record_type", "status", "priority", "title",
                  "parent", "related_feature_ids"},
        "fields_marker": None,
    },
    {   # ELR elr_list._extract_ids
        "name": "elr elr_list", "file": "tools/elr/elr_list.py",
        "reads": {"item_id", "id", "record_id"}, "fields_marker": None,
    },
    {   # ui-v2 fetchLessons (LessonRecord)
        "name": "ui-v2 coordination lessons", "file": "frontend/ui-v2/src/api/coordination.ts",
        "reads": {"item_id", "project_id", "title", "status", "provenance",
                  "created_at", "updated_at"},
        "fields_marker": None,
    },
    {   # ui-v2 homeQueue -> mode=census, reads no record rows
        "name": "ui-v2 homeQueue", "file": "frontend/ui-v2/src/api/homeQueue.ts",
        "reads": set(), "fields_marker": None,
    },
    {   # checkout_service closed-task documentation-evidence reuse gate
        "name": "checkout_service closed doc evidence",
        "file": "backend/lambda/checkout_service/lambda_function.py",
        "reads": {"id", "record_id", "task_id", "documentation_evidence", "transition_evidence"},
        "fields_marker": "_CLOSED_DOC_EVIDENCE_LIST_FIELDS", "explicit_const": True,
    },
    {   # rhythm_cycle baseline (description topic match, related_*_ids)
        "name": "rhythm_cycle baseline", "file": "backend/lambda/rhythm_cycle/baseline.py",
        "reads": {"item_id", "record_id", "title", "description", "related_task_ids",
                  "related_issue_ids", "related_feature_ids"},
        "fields_marker": '"fields": "full"',
    },
    {   # corpus_entropy_engine (history etc.)
        "name": "corpus_entropy_engine", "file": "backend/lambda/corpus_entropy_engine/lambda_function.py",
        "reads": {"history", "related_task_ids", "item_id", "record_id", "status"},
        "fields_marker": "fields=full",
    },
    {   # MCP tracker_list_lessons returns raw rows verbatim
        "name": "mcp tracker_list_lessons", "file": "tools/enceladus-mcp-server/server.py",
        "reads": {"description", "insight", "observation", "evidence_chain"},
        "fields_marker": '"type": "lesson", "fields": "full"',
    },
    {   # MCP telemetry rank reads an arbitrary attribute + write_source
        "name": "mcp telemetry rank", "file": "tools/enceladus-mcp-server/server.py",
        "reads": {"write_source", "category", "components"},
        "fields_marker": '"type": record_type, "fields": "full"',
    },
]


class CallerContractTests(unittest.TestCase):
    def test_every_caller_is_compact_safe_or_passes_fields(self):
        compact = set(tm._LIST_COMPACT_FIELDS)
        for caller in CALLER_CONTRACT:
            with self.subTest(caller=caller["name"]):
                src = (REPO / caller["file"]).read_text(encoding="utf-8")
                if caller["fields_marker"] is None:
                    missing = caller["reads"] - compact
                    self.assertFalse(
                        missing,
                        f"{caller['name']} reads excluded field(s) {sorted(missing)} "
                        "without passing fields= (A11 silent data loss)",
                    )
                else:
                    self.assertIn(caller["fields_marker"], src,
                                  f"{caller['name']} must pass fields= to the list route")

    def test_explicit_field_list_covers_every_read(self):
        ns: dict = {}
        src = (REPO / "backend/lambda/checkout_service/lambda_function.py").read_text(encoding="utf-8")
        marker = "_CLOSED_DOC_EVIDENCE_LIST_FIELDS = ("
        start = src.index(marker)
        end = src.index(")\n", start) + 1
        exec(src[start:end], ns)  # a parenthesised string literal -- no imports needed
        listed = set(ns["_CLOSED_DOC_EVIDENCE_LIST_FIELDS"].split(","))
        reads = next(c for c in CALLER_CONTRACT if c.get("explicit_const"))["reads"]
        self.assertTrue(reads <= listed, sorted(reads - listed))

    def test_no_compact_field_is_an_excluded_class(self):
        for name in tm._LIST_COMPACT_FIELDS:
            self.assertNotIn("evidence", name.lower())


if __name__ == "__main__":
    unittest.main()
