"""ENC-TSK-S46-0D / ENC-ISS-180 defect A (ENC-PLN-104 W6a.4, io decision E2).

Edges whose target node is not yet projected must still land: the projector MERGEs a
placeholder for the target (one placeholder convention: ``_merge_placeholder``, keyed
by (label, record_id), ``is_placeholder = true`` on create), the edge is created, and
the target's later real projection completes the placeholder in place.

Uses a small in-memory interpreter (``_FakeGraphTx``) for the Cypher shapes graph_sync
emits, in the spirit of test_edge_ownership_s33.py's recording fake tx.
"""
import re
import unittest
from unittest.mock import MagicMock


def _lf():
    import lambda_function as lf
    return lf


class _Result:
    def __init__(self, row):
        self._row = row

    def single(self):
        return self._row


class _FakeGraphTx:
    """Interprets the Cypher shapes graph_sync emits against an in-memory graph.

    nodes: {(label, key): props}; edges: list of [type, src_node_key, dst_node_key, props].
    Project nodes are keyed by project_id, every other label by record_id.
    """

    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.queries = []

    # --- helpers -------------------------------------------------------------------------
    def _find(self, label, rid):
        if label:
            return (label, rid) if (label, rid) in self.nodes else None
        hits = [k for k in self.nodes if k[1] == rid]
        return hits[0] if hits else None

    def edge_keys(self):
        return {(e[0], e[1][1], e[2][1]) for e in self.edges}

    # --- tx.run --------------------------------------------------------------------------
    def run(self, q, **kw):
        self.queries.append((q, kw))
        q1 = " ".join(q.split())
        # Owner-scoped deletes (S33).
        m = re.match(r"MATCH \((\w+):(\w+) \{record_id: \$rid\}\)-\[r\]->\(\) WHERE type\(r\) IN \$start_owned", q1)
        if m and "DELETE r" in q1:
            node = (m.group(2), kw["rid"])
            self.edges = [e for e in self.edges if not (
                e[1] == node and e[0] in kw["start_owned"] and e[0] != "SUPERSEDED_BY" and "source_id" not in e[3])]
            return _Result(None)
        m = re.match(r"MATCH \(\)-\[r\]->\((\w+):(\w+) \{record_id: \$rid\}\) WHERE type\(r\) IN \$end_owned", q1)
        if m and "DELETE r" in q1:
            node = (m.group(2), kw["rid"])
            self.edges = [e for e in self.edges if not (
                e[2] == node and e[0] in kw["end_owned"] and e[0] != "SUPERSEDED_BY" and "source_id" not in e[3])]
            return _Result(None)
        # Placeholder guard (the one convention).
        m = re.search(r"MERGE \((\w+):(\w+) \{record_id: \$rid\}\) ON CREATE SET \1\.is_placeholder = true", q1)
        if m and "OPTIONAL MATCH" in q1:
            key = (m.group(2), kw["rid"])
            created = key not in self.nodes
            if created:
                self.nodes[key] = {"record_id": kw["rid"], "is_placeholder": True,
                                   "project_id": kw.get("project_id"),
                                   "placeholder_created_at": kw.get("now")}
            return _Result({"created": created})
        # Real node upsert.
        m = re.match(r"MERGE \(n:(\w+) \{record_id: \$record_id\}\) SET n \+= \$props SET n\.is_placeholder = false", q1)
        if m:
            props = self.nodes.setdefault((m.group(1), kw["record_id"]), {})
            props.update(kw["props"])
            props["is_placeholder"] = False
            if "status_val" in kw:
                props["status"] = kw["status_val"]
            return _Result(None)
        m = re.match(r"MERGE \(p:Project \{project_id: \$pid\}\)", q1)
        if m and "-[" not in q1:
            self.nodes.setdefault(("Project", kw["pid"]), {"project_id": kw["pid"]})
            return _Result(None)
        if "MERGE (" in q1 and "]->(" in q1:
            return self._edge_query(q1, kw)
        return _Result(None)

    def _edge_query(self, q1, kw):
        labels = dict(re.findall(r"\((\w+):(\w+)[ )]", q1))
        binds = {}
        for var, prop, param in re.findall(r"(\w+)\.(record_id|project_id) = \$(\w+)", q1):
            binds[var] = kw[param]
        for var, lab, param in re.findall(r"\((\w+)(?::(\w+))? \{record_id: \$(\w+)\}\)", q1):
            binds[var] = kw[param]
            if lab:
                labels[var] = lab
        bound = {}
        for var, rid in binds.items():
            node = self._find(labels.get(var), rid)
            if node is None:
                return _Result({"n": 0})  # MATCH found nothing: no rows, no edge
            bound[var] = node
        m = re.search(r"coalesce\(canon, (\w+)\) AS tgt", q1)
        if m:
            b = bound[m.group(1)]
            canon = [e[2] for e in self.edges if e[0] == "SUPERSEDED_BY" and e[1] == b]
            bound["tgt"] = canon[0] if canon else b
            src = re.search(r"WITH (\w+), coalesce", q1).group(1)
            if bound["tgt"][1] == bound[src][1]:
                return _Result({"n": 0})
        n = 0
        for s, _rv, etype, props, d in re.findall(r"MERGE \((\w+)\)-\[(\w*):(\w+)\s*(\{[^}]*\})?\]->\((\w+)\)", q1):
            pd = {}
            for k, v in re.findall(r"(\w+): ([^,}]+)", props or ""):
                v = v.strip()
                pd[k] = kw[v[1:]] if v.startswith("$") else v.strip("'")
            key = [etype, bound[s], bound[d], pd]
            if not any(e[:3] == key[:3] and (not pd or e[3] == pd) for e in self.edges):
                self.edges.append(key)
            n += 1
        return _Result({"n": n})


TASK_A = {"record_type": "task", "record_id": "ENC-TSK-A01", "project_id": "enceladus",
          "title": "A", "related_task_ids": ["ENC-TSK-B01"]}
TASK_B = {"record_type": "task", "record_id": "ENC-TSK-B01", "project_id": "enceladus",
          "title": "B real", "status": "open"}


def _project(tx, record):
    lf = _lf()
    lf._upsert_project_node(tx, record["project_id"])
    lf._upsert_node(tx, record)
    lf._reconcile_edges(tx, record)


class TestCreateEdgeBeforeNode(unittest.TestCase):
    def setUp(self):
        _lf()._edge_guard_reset()

    def test_1_placeholder_target_and_edge_created(self):
        tx = _FakeGraphTx()
        _project(tx, TASK_A)
        b = tx.nodes.get(("Task", "ENC-TSK-B01"))
        self.assertIsNotNone(b, "target placeholder must be MERGEd")
        self.assertTrue(b["is_placeholder"])
        self.assertEqual(b["project_id"], "enceladus")
        self.assertTrue(b.get("placeholder_created_at"))
        self.assertIn(("RELATED_TO", "ENC-TSK-A01", "ENC-TSK-B01"), tx.edge_keys())

    def test_2_real_projection_completes_placeholder_in_place(self):
        tx = _FakeGraphTx()
        _project(tx, TASK_A)
        _project(tx, TASK_B)
        b_nodes = [k for k in tx.nodes if k[1] == "ENC-TSK-B01"]
        self.assertEqual(b_nodes, [("Task", "ENC-TSK-B01")], "no duplicate node")
        b = tx.nodes[("Task", "ENC-TSK-B01")]
        self.assertFalse(b["is_placeholder"])
        self.assertEqual(b["title"], "B real")
        self.assertIn(("RELATED_TO", "ENC-TSK-A01", "ENC-TSK-B01"), tx.edge_keys(),
                      "B's reconcile must not delete A's edge into it")

    def test_child_of_issue_feature_generation_targets_guarded(self):
        tx = _FakeGraphTx()
        _project(tx, {"record_type": "task", "record_id": "ENC-TSK-C01", "project_id": "enceladus",
                      "parent": "ENC-TSK-P01", "related_issue_ids": ["ENC-ISS-001"],
                      "related_feature_ids": ["ENC-FTR-001"], "target_generation": "ENC-GEN-001"})
        keys = tx.edge_keys()
        for e in (("CHILD_OF", "ENC-TSK-C01", "ENC-TSK-P01"), ("RELATED_TO", "ENC-TSK-C01", "ENC-ISS-001"),
                  ("ADDRESSES", "ENC-TSK-C01", "ENC-ISS-001"), ("RELATED_TO", "ENC-TSK-C01", "ENC-FTR-001"),
                  ("IMPLEMENTS", "ENC-TSK-C01", "ENC-FTR-001"), ("TARGETS_GENERATION", "ENC-TSK-C01", "ENC-GEN-001")):
            self.assertIn(e, keys)

    def test_5_counters(self):
        lf = _lf()
        tx = _FakeGraphTx()
        _project(tx, TASK_A)
        fields = lf._edge_guard_audit_fields()
        self.assertEqual(fields["edges_skipped_missing_target"], 0)
        self.assertEqual(fields["edges_placeholder_targets"], 1)
        lf._edge_guard_reset()
        _project(tx, TASK_B)  # completes the placeholder: nothing materialized, nothing skipped
        self.assertEqual(lf._edge_guard_audit_fields(),
                         {"edges_skipped_missing_target": 0, "edges_placeholder_targets": 0})

    def test_skip_counted_when_target_label_unknown(self):
        lf = _lf()
        tx = _FakeGraphTx()
        _project(tx, {"record_type": "plan", "record_id": "ENC-PLN-001", "project_id": "enceladus",
                      "objectives_set": ["LEGACYFLAT"]})
        self.assertEqual(lf._edge_guard_audit_fields()["edges_skipped_missing_target"], 1)

    def test_label_mismatch_creates_no_wrong_label_placeholder(self):
        lf = _lf()
        tx = _FakeGraphTx()
        _project(tx, dict(TASK_A, related_task_ids=["ENC-ISS-009"]))  # issue id in a task field
        self.assertNotIn(("Task", "ENC-ISS-009"), tx.nodes)
        self.assertEqual(lf._edge_guard_audit_fields(),
                         {"edges_skipped_missing_target": 1, "edges_placeholder_targets": 0})

    def test_counters_ignore_mock_results(self):
        lf = _lf()
        lf._reconcile_edges(MagicMock(), dict(TASK_A))
        self.assertEqual(lf._edge_guard_audit_fields(),
                         {"edges_skipped_missing_target": 0, "edges_placeholder_targets": 0})


class TestRelationshipRecordOrderGuard(unittest.TestCase):
    def setUp(self):
        _lf()._edge_guard_reset()

    def test_3_rel_record_to_unprojected_target(self):
        lf = _lf()
        tx = _FakeGraphTx()
        _project(tx, TASK_A)
        lf._edge_guard_reset()
        lf._upsert_relationship_edge(tx, {"relationship_type": "blocks", "source_id": "ENC-TSK-A01",
                                          "target_id": "ENC-TSK-Z09", "project_id": "enceladus"})
        z = tx.nodes[("Task", "ENC-TSK-Z09")]
        self.assertTrue(z["is_placeholder"])
        self.assertEqual(z["project_id"], "enceladus")
        self.assertIn(("BLOCKS", "ENC-TSK-A01", "ENC-TSK-Z09"), tx.edge_keys())
        self.assertEqual(lf._edge_guard_audit_fields(),
                         {"edges_skipped_missing_target": 0, "edges_placeholder_targets": 1})
        _project(tx, dict(TASK_B, record_id="ENC-TSK-Z09"))
        self.assertEqual([k for k in tx.nodes if k[1] == "ENC-TSK-Z09"], [("Task", "ENC-TSK-Z09")])
        self.assertFalse(tx.nodes[("Task", "ENC-TSK-Z09")]["is_placeholder"])
        self.assertIn(("BLOCKS", "ENC-TSK-A01", "ENC-TSK-Z09"), tx.edge_keys())

    def test_rel_record_unlabelled_missing_endpoint_is_skipped_and_counted(self):
        lf = _lf()
        tx = _FakeGraphTx()
        lf._upsert_relationship_edge(tx, {"relationship_type": "blocks", "source_id": "LEGACYFLAT",
                                          "target_id": "ENC-TSK-Z01"})
        self.assertEqual(lf._edge_guard_audit_fields()["edges_skipped_missing_target"], 1)


class TestOwnerScopedReconcileWithPlaceholders(unittest.TestCase):
    def setUp(self):
        _lf()._edge_guard_reset()

    def test_4_reconcile_deletes_only_owned_edges(self):
        lf = _lf()
        tx = _FakeGraphTx()
        _project(tx, TASK_A)                                     # A -RELATED_TO-> placeholder B
        lf._upsert_relationship_edge(tx, {"relationship_type": "depends-on", "source_id": "ENC-TSK-B01",
                                          "target_id": "ENC-TSK-A01"})  # rel edge B -> A
        _project(tx, {"record_type": "task", "record_id": "ENC-TSK-C01", "project_id": "enceladus",
                      "related_task_ids": ["ENC-TSK-B01"]})   # C -> placeholder B
        _project(tx, TASK_B)                                     # completes B; B owns nothing to A/C
        keys = tx.edge_keys()
        self.assertIn(("RELATED_TO", "ENC-TSK-A01", "ENC-TSK-B01"), keys)
        self.assertIn(("RELATED_TO", "ENC-TSK-C01", "ENC-TSK-B01"), keys)
        self.assertIn(("DEPENDS_ON", "ENC-TSK-B01", "ENC-TSK-A01"), keys)
        # A drops B from its fields: only A's own start-owned edge goes; rel edge B->A stays.
        _project(tx, dict(TASK_A, related_task_ids=[]))
        keys = tx.edge_keys()
        self.assertNotIn(("RELATED_TO", "ENC-TSK-A01", "ENC-TSK-B01"), keys)
        self.assertIn(("RELATED_TO", "ENC-TSK-C01", "ENC-TSK-B01"), keys)
        self.assertIn(("DEPENDS_ON", "ENC-TSK-B01", "ENC-TSK-A01"), keys)

    def test_placeholder_targets_are_purge_candidates(self):
        refs = _lf()._collect_placeholder_target_refs(
            {"record_type": "task", "record_id": "ENC-TSK-A01", "parent": "ENC-TSK-P01",
             "related_task_ids": ["ENC-TSK-B01"], "related_issue_ids": ["ENC-ISS-001"],
             "related_feature_ids": ["ENC-FTR-001"], "target_generation": "ENC-GEN-001"})
        self.assertTrue({("Task", "ENC-TSK-P01"), ("Task", "ENC-TSK-B01"), ("Issue", "ENC-ISS-001"),
                         ("Feature", "ENC-FTR-001")} <= refs)


class TestSupersededRedirectWithPlaceholder(unittest.TestCase):
    def setUp(self):
        _lf()._edge_guard_reset()

    def test_6_superseded_by_redirect_on_placeholder(self):
        lf = _lf()
        tx = _FakeGraphTx()
        # Only the supersession relationship record has arrived: both ends are placeholders.
        lf._upsert_relationship_edge(tx, {"relationship_type": "superseded-by", "source_id": "ENC-ISS-002",
                                          "target_id": "ENC-ISS-001"})
        self.assertTrue(tx.nodes[("Issue", "ENC-ISS-002")]["is_placeholder"])
        _project(tx, {"record_type": "task", "record_id": "ENC-TSK-A01", "project_id": "enceladus",
                      "related_issue_ids": ["ENC-ISS-002"]})
        keys = tx.edge_keys()
        self.assertIn(("RELATED_TO", "ENC-TSK-A01", "ENC-ISS-001"), keys)
        self.assertIn(("ADDRESSES", "ENC-TSK-A01", "ENC-ISS-001"), keys)
        self.assertNotIn(("RELATED_TO", "ENC-TSK-A01", "ENC-ISS-002"), keys)

    def test_6b_redirect_target_unprojected_creates_placeholder_then_redirects(self):
        tx = _FakeGraphTx()
        _project(tx, {"record_type": "task", "record_id": "ENC-TSK-A01", "project_id": "enceladus",
                      "related_task_ids": ["ENC-TSK-B01"]})
        _lf()._upsert_relationship_edge(tx, {"relationship_type": "superseded-by", "source_id": "ENC-TSK-B01",
                                             "target_id": "ENC-TSK-B02"})
        _project(tx, {"record_type": "task", "record_id": "ENC-TSK-A01", "project_id": "enceladus",
                      "related_task_ids": ["ENC-TSK-B01"]})
        keys = tx.edge_keys()
        self.assertIn(("RELATED_TO", "ENC-TSK-A01", "ENC-TSK-B02"), keys)
        self.assertNotIn(("RELATED_TO", "ENC-TSK-A01", "ENC-TSK-B01"), keys)


class TestWriteAuditField(unittest.TestCase):
    def test_audit_line_carries_counters(self):
        import io
        import json
        from contextlib import redirect_stdout
        lf = _lf()
        lf._edge_guard_reset()
        lf._EDGE_GUARD_STATS["edges_placeholder_targets"] = 2
        image = {"correlation_id": {"S": "c-1"}, "version_seq": {"N": "3"}, "item_id": {"S": "ENC-TSK-A01"},
                 "updated_at": {"S": "2026-11-04T00:00:00Z"}}
        buf = io.StringIO()
        with redirect_stdout(buf):
            lf._wa_consumer_emit("graph_sync", {}, {"eventName": "MODIFY", "dynamodb": {"NewImage": image}}, 1, 2)
        line = [ln for ln in buf.getvalue().splitlines() if ln.startswith("[WRITE-AUDIT] ")][0]
        payload = json.loads(line[len("[WRITE-AUDIT] "):])
        self.assertEqual(payload["edges_skipped_missing_target"], 0)
        self.assertEqual(payload["edges_placeholder_targets"], 2)


if __name__ == "__main__":
    unittest.main()
