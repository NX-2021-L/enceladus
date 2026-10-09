"""Unit tests for tools/graph_feed_resync.py (no network)."""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).with_name("graph_feed_resync.py")
SPEC = importlib.util.spec_from_file_location("graph_feed_resync_under_test", PATH)
R = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = R
SPEC.loader.exec_module(R)


def S(v):
    return {"S": v}


def trk(pid, iid, status="open", rtype="task"):
    return {"project_id": S(pid), "record_id": S(f"{rtype}#{iid}"), "item_id": S(iid),
            "record_type": S(rtype), "status": S(status)}


def doc(did, pid="enceladus", upd="2026-01-02T00:00:00Z"):
    return {"document_id": S(did), "project_id": S(pid), "updated_at": S(upd)}


def resolved_for(items):
    out = []
    for it in items:
        if "document_id" in it:
            ent = {"table": "documents", "document_id": it["document_id"]["S"], "project_id": it["project_id"]["S"]}
            keys = {"document_id": it["document_id"]}
        else:
            ent = {"table": "tracker", "project_id": it["project_id"]["S"], "record_id": it["record_id"]["S"]}
            keys = {"project_id": it["project_id"], "record_id": it["record_id"]}
        out.append((ent, keys, it))
    return out


class MessageTests(unittest.TestCase):
    def test_shape_and_passthrough(self):
        item = trk("enceladus", "ENC-TSK-1")
        keys = {"project_id": item["project_id"], "record_id": item["record_id"]}
        m = R.build_stream_message(item, keys, "us-west-2")
        self.assertEqual(m["eventName"], "MODIFY")
        self.assertTrue(m["eventID"].startswith("resync-"))
        self.assertIs(m["dynamodb"]["NewImage"], item)
        self.assertEqual(m["dynamodb"]["Keys"], keys)
        self.assertEqual(m["dynamodb"]["StreamViewType"], "NEW_AND_OLD_IMAGES")

    def test_dedup_unique_and_equals_event_id(self):
        items = [trk("enceladus", f"ENC-TSK-{i}") for i in range(30)]
        out = R.build_entries(resolved_for(items), "us-west-2", ["graph", "feed"])
        ids = [e["MessageDeduplicationId"] for e in out["graph"]]
        self.assertEqual(len(set(ids)), 30)
        for e in out["graph"] + out["feed"]:
            self.assertEqual(e["MessageDeduplicationId"], json.loads(e["MessageBody"])["eventID"])
            self.assertLessEqual(len(e["MessageDeduplicationId"]), 128)

    def test_group_ids(self):
        items = [trk("enceladus", "ENC-TSK-1"), doc("DOC-1", "enceladus")]
        out = R.build_entries(resolved_for(items), "us-west-2", ["graph"])
        self.assertEqual(out["graph"][0]["MessageGroupId"], "enceladus")
        self.assertEqual(out["graph"][1]["MessageGroupId"], "document")

    def test_feed_collapses_per_project(self):
        items = [trk("a", "A-1"), trk("a", "A-2"), trk("b", "B-1"), doc("DOC-1", "b")]
        out = R.build_entries(resolved_for(items), "us-west-2", ["graph", "feed"])
        self.assertEqual(len(out["graph"]), 4)
        self.assertEqual(sorted(e["MessageGroupId"] for e in out["feed"]), ["a", "b"])

    def test_targets_filter(self):
        out = R.build_entries(resolved_for([trk("a", "A-1")]), "r", ["feed"])
        self.assertNotIn("graph", out)


class DriftTests(unittest.TestCase):
    def test_classification(self):
        nodes = {"task": {"ENC-TSK-2": {"status": "open"}, "ENC-TSK-3": {"status": "open"}},
                 "document": {"DOC-2": {"updated_at": "2026-01-01T00:00:00Z"},
                              "DOC-3": {"updated_at": "2026-01-02T00:00:00Z"}}}
        tracker = [trk("p", "ENC-TSK-1"), trk("p", "ENC-TSK-2", "closed"), trk("p", "ENC-TSK-3", "open"),
                   {"project_id": S("p"), "record_id": S("rel#x"), "record_type": S("relationship")}]
        docs = [doc("DOC-1"), doc("DOC-2"), doc("DOC-3")]
        ids, summary = R.build_drift(tracker, docs, nodes, ["task"])
        got = {(i.get("item_id") or i["document_id"], i["class"]) for i in ids}
        self.assertEqual(got, {("ENC-TSK-1", "missing"), ("ENC-TSK-2", "status_drift"),
                               ("DOC-1", "missing"), ("DOC-2", "stale")})
        self.assertEqual(summary["top_status_pairs"][0]["pair"], "closed -> open")

    def test_edge_rows_skipped(self):
        edge = {"project_id": S("p"), "record_id": S("rel#1"), "record_type": S("relationship")}
        self.assertFalse(R.is_entity_record(edge, ["task", "relationship"]))
        self.assertTrue(R.is_relationship_record(edge))


class SendTests(unittest.TestCase):
    def test_chunking(self):
        sqs = mock.Mock()
        sqs.send_message_batch.return_value = {"Successful": [], "Failed": []}
        entries = [{"Id": str(i), "MessageBody": "{}"} for i in range(23)]
        R.send_entries(sqs, "url", entries)
        sizes = [len(c.kwargs["Entries"]) for c in sqs.send_message_batch.call_args_list]
        self.assertEqual(sizes, [10, 10, 3])

    def test_failures_collected(self):
        sqs = mock.Mock()
        sqs.send_message_batch.return_value = {"Failed": [{"Id": "0"}]}
        self.assertEqual(len(R.send_entries(sqs, "u", [{"Id": "0"}])), 1)

    def test_dry_run_sends_nothing(self):
        item = trk("p", "ENC-TSK-1")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"ids": [{"table": "tracker", "project_id": "p", "record_id": "task#ENC-TSK-1"}]}, fh)
        ddb = mock.Mock()
        ddb.get_item.return_value = {"Item": item}
        sess = mock.Mock()
        sess.client.return_value = ddb
        with mock.patch.object(R, "_sessions", return_value=sess) as ms, \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            rc = R.main(["replay", "--ids-file", fh.name, "--dry-run"])
        self.assertEqual(rc, 0)
        self.assertEqual(ms.call_count, 1)  # read session only, never the send session
        self.assertEqual([c.args[0] for c in ms.call_args_list], [mock.ANY])
        self.assertIn("graph: 1 messages", out.getvalue())
        self.assertIn("feed: 1 messages", out.getvalue())


class Neo4jTests(unittest.TestCase):
    def test_uri_conversion(self):
        self.assertEqual(R.neo4j_https_base("neo4j+s://abc123.databases.neo4j.io"),
                         "https://abc123.databases.neo4j.io")
        self.assertEqual(R.neo4j_https_base("bolt+s://h.io:7687/"), "https://h.io")

    def test_query_parsing_with_mocked_urlopen(self):
        body = json.dumps({"data": {"fields": ["record_id", "status", "updated_at"],
                                    "values": [["ENC-TSK-1", "open", "t"]]}}).encode()
        resp = mock.MagicMock()
        resp.read.return_value = body
        resp.__enter__.return_value = resp
        opener = mock.Mock(return_value=resp)
        c = R.Neo4jClient({"NEO4J_URI": "neo4j+s://h.io", "NEO4J_PASSWORD": "pw"}, opener=opener)
        nodes = c.fetch_nodes("Task")
        self.assertEqual(nodes["ENC-TSK-1"]["status"], "open")
        req = opener.call_args.args[0]
        self.assertEqual(req.full_url, "https://h.io/db/neo4j/query/v2")
        self.assertTrue(req.get_header("Authorization").startswith("Basic "))
        self.assertIn("MATCH (n:Task)", json.loads(req.data)["statement"])


if __name__ == "__main__":
    unittest.main()
