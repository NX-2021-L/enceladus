"""ENC-TSK-R82-0B: tools/backfill_orphan_sessions.py mapping, idempotence, legacy preservation."""

from __future__ import annotations

import importlib.util
import os
import unittest

_SPEC = importlib.util.spec_from_file_location(
    "backfill_orphan_sessions", os.path.join(os.path.dirname(__file__), "backfill_orphan_sessions.py"))
bf = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(bf)


def T(surface, model, status="active"):
    return {"surface": surface, "model": model, "status": status}


TYPES = {
    "ENC-AGT-003": T("cursor-cloud-agent", "claude-opus-4-8"),
    "ENC-AGT-005": T("claude_code_cli", "claude-sonnet-5"),
    "ENC-AGT-002": T("Claude Code CLI", "claude-opus-4-8"),
    "ENC-AGT-00F": T("claude_code_cli", "claude-opus-5"),
    "ENC-AGT-00A": T("cowork-desktop", "claude-sonnet-5", "retired"),
    "ENC-AGT-0ZZ": T("unknown", "unknown"),
}


def S(sid, aid, runtime=None):
    r = {"session_id": sid, "agent_type_id": aid}
    if runtime:
        r["runtime"] = runtime
    return r


class MappingTests(unittest.TestCase):
    def fb(self):
        return bf.find_fallback_type(TYPES)

    def test_fallback_detected_and_pinned(self):
        self.assertEqual(self.fb(), "ENC-AGT-0ZZ")
        self.assertEqual(bf.find_fallback_type(TYPES, "ENC-AGT-003"), "ENC-AGT-003")
        self.assertIsNone(bf.find_fallback_type(TYPES, "ENC-AGT-00A"))  # retired: not usable
        self.assertIsNone(bf.find_fallback_type({k: v for k, v in TYPES.items() if k != "ENC-AGT-0ZZ"}))

    def test_unique_surface_maps_via_normal_form(self):
        self.assertEqual(bf.map_orphan(S("a", "cursor-cloud-agent"), TYPES, self.fb()),
                         ("ENC-AGT-003", bf.REASON_SURFACE))
        self.assertEqual(bf.map_orphan(S("a", "Cursor Cloud Agent"), TYPES, self.fb())[0], "ENC-AGT-003")

    def test_ambiguous_surface_uses_model_hint_else_fallback(self):
        self.assertEqual(bf.map_orphan(S("a", "claude_code_cli", "claude-opus-5"), TYPES, self.fb()),
                         ("ENC-AGT-00F", bf.REASON_SURFACE_MODEL))
        self.assertEqual(bf.map_orphan(S("a", "claude-code", "claude_code_cli"), TYPES, self.fb()),
                         ("ENC-AGT-0ZZ", bf.REASON_FALLBACK_AMBIGUOUS))

    def test_unmapped_goes_to_fallback_and_retired_is_never_target(self):
        self.assertEqual(bf.map_orphan(S("a", "coord-lead"), TYPES, self.fb()),
                         ("ENC-AGT-0ZZ", bf.REASON_FALLBACK_NO_MATCH))
        self.assertEqual(bf.map_orphan(S("a", "cowork-desktop"), TYPES, self.fb())[0], "ENC-AGT-0ZZ")
        self.assertEqual(bf.map_orphan(S("a", ""), TYPES, self.fb())[0], "ENC-AGT-0ZZ")

    def test_no_fallback_yields_none_target(self):
        self.assertEqual(bf.map_orphan(S("a", "coord-lead"), TYPES, None)[0], None)

    def test_plan_skips_canonical_and_counters(self):
        rows = [S("s1", "ENC-AGT-005"), S("counter#x", "junk"), S("s2", "coord-lead"), S("s3", "")]
        plan = bf.plan_rewrites(rows, TYPES, self.fb())
        self.assertEqual([p["session_id"] for p in plan], ["s2", "s3"])
        self.assertEqual(plan[0]["original"], "coord-lead")
        self.assertEqual(sum(bf.summarize(plan)["by_target"].values()), 2)


class _Cond(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class _FakeDdb:
    """In-memory sessions table honouring the update_item ConditionExpression we send."""

    def __init__(self, rows):
        self.rows = {r["session_id"]: dict(r) for r in rows}
        self.deleted = 0

    def update_item(self, TableName, Key, UpdateExpression, ConditionExpression, ExpressionAttributeValues):
        row = self.rows.get(Key["session_id"]["S"])
        o = ExpressionAttributeValues[":o"]["S"]
        if row is None or row.get("agent_type_id") != o or "legacy_agent_type_id" in row:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")
        row["agent_type_id"] = ExpressionAttributeValues[":c"]["S"]
        row["legacy_agent_type_id"] = o


class ApplyTests(unittest.TestCase):
    def setUp(self):
        try:
            import botocore  # noqa: F401
        except ImportError:
            self.skipTest("botocore not installed")
        self.rows = [S("s1", "coord-lead"), S("s2", "cursor-cloud-agent"), S("s3", "ENC-AGT-005")]

    def test_apply_rewrites_preserves_legacy_and_is_idempotent(self):
        ddb = _FakeDdb(self.rows)
        plan = bf.plan_rewrites(list(ddb.rows.values()), TYPES, "ENC-AGT-0ZZ")
        self.assertEqual(bf.apply_plan(ddb, plan), (2, 0))
        self.assertEqual(ddb.rows["s1"]["agent_type_id"], "ENC-AGT-0ZZ")
        self.assertEqual(ddb.rows["s1"]["legacy_agent_type_id"], "coord-lead")
        self.assertEqual(ddb.rows["s2"]["agent_type_id"], "ENC-AGT-003")
        self.assertEqual(ddb.rows["s2"]["legacy_agent_type_id"], "cursor-cloud-agent")
        self.assertNotIn("legacy_agent_type_id", ddb.rows["s3"])
        self.assertEqual(len(ddb.rows), 3)  # no rows dropped
        # Re-run: nothing is an orphan any more.
        self.assertEqual(bf.plan_rewrites(list(ddb.rows.values()), TYPES, "ENC-AGT-0ZZ"), [])
        # Stale plan replayed: conditional write skips, never clobbers legacy value.
        self.assertEqual(bf.apply_plan(ddb, plan), (0, 2))
        self.assertEqual(ddb.rows["s1"]["legacy_agent_type_id"], "coord-lead")

    def test_missing_target_rows_are_skipped_not_written(self):
        ddb = _FakeDdb(self.rows)
        plan = bf.plan_rewrites(list(ddb.rows.values()), TYPES, None)
        self.assertEqual(bf.apply_plan(ddb, plan), (1, 1))
        self.assertEqual(ddb.rows["s1"]["agent_type_id"], "coord-lead")

    def test_apply_refuses_without_approval_and_without_fallback_message(self):
        self.assertEqual(bf.main(["--apply"]), 2)
        self.assertIn("agent.type.register", bf.fallback_missing_message())


if __name__ == "__main__":
    unittest.main()
