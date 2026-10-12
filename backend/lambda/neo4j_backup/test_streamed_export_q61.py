"""ENC-TSK-Q61 / ENC-ISS-847: streamed gzip-NDJSON Neo4j export.

No Neo4j, S3 or CloudWatch is contacted: the driver, S3 client and CloudWatch
client are in-memory fakes. What is asserted:

  - the export is lazy and page-bounded (the next read transaction is not issued
    until the previous page has been fully written out);
  - the manifest is written last and its counts and checksums match the files;
  - every gzip NDJSON line parses;
  - dry_run reads one page each and writes nothing;
  - stable-key selection order;
  - the success metric is emitted on success and never on failure.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

import lambda_function as lf  # noqa: E402


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeGraph:
    """Deterministic graph with elementId-ordered nodes and relationships."""

    def __init__(self, n_nodes, n_rels):
        self.nodes = []
        for i in range(n_nodes):
            labels = ["Task"] if i % 3 else ["Task", "Tracked"]
            props = {"record_id": "ENC-TSK-%04d" % i, "title": "t%d" % i}
            if i % 10 == 0:
                props = {"project_id": "proj-%d" % i}
                labels = ["Project"]
            self.nodes.append({"eid": "4:g:%06d" % i, "labels": labels, "props": props})
        self.rels = []
        for i in range(n_rels):
            a = self.nodes[i % n_nodes]
            b = self.nodes[(i + 1) % n_nodes]
            self.rels.append({
                "eid": "5:g:%06d" % i,
                "type": "RELATED_TO" if i % 2 else "PARENT_OF",
                "props": {"w": i},
                "start_eid": a["eid"], "end_eid": b["eid"],
                "start_labels": a["labels"], "end_labels": b["labels"],
                "start_key": lf.stable_key(a["props"])[1],
                "end_key": lf.stable_key(b["props"])[1],
            })


class FakeTx:
    def __init__(self, driver):
        self._d = driver

    def run(self, cypher, after, page):
        d = self._d
        is_node = cypher.startswith("MATCH (n)")
        rows = d.graph.nodes if is_node else d.graph.rels
        selected = [r for r in rows if r["eid"] > after][:page]
        d.events.append(("query", "nodes" if is_node else "rels", after))
        d.queries += 1
        d.unwritten_at_query.append(d.fetched - d.written)
        d.fetched += len(selected)
        # fresh dicts per call: nothing is cached by the fake
        return [dict(r) for r in selected]


class FakeSession:
    def __init__(self, driver):
        self._d = driver

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute_read(self, fn):
        self._d.read_txs += 1
        if self._d.fail_on_query is not None and self._d.queries >= self._d.fail_on_query:
            raise RuntimeError("boom: bolt connection lost")
        return fn(FakeTx(self._d))

    def run(self, cypher, **params):
        if cypher.startswith("SHOW CONSTRAINTS"):
            return [{"name": "uniq_record_id", "type": "UNIQUENESS"}]
        if cypher.startswith("SHOW INDEXES"):
            return [
                {"name": "idx_status", "type": "RANGE"},
                {"name": "vec_gov", "type": "VECTOR",
                 "options": {"indexConfig": {"vector.dimensions": 1024}}},
            ]
        if "db.labels" in cypher:
            return [{"label": "Task"}, {"label": "Project"}, {"label": "Tracked"}]
        if "db.relationshipTypes" in cypher:
            return [{"relationshipType": "RELATED_TO"}, {"relationshipType": "PARENT_OF"}]
        if "dbms.components" in cypher:
            return [{"name": "Neo4j Kernel", "versions": ["5.26.0"], "edition": "enterprise"}]
        raise AssertionError("unexpected cypher: " + cypher)


class FakeDriver:
    def __init__(self, graph, fail_on_query=None):
        self.graph = graph
        self.fail_on_query = fail_on_query
        self.events = []
        self.queries = 0
        self.read_txs = 0
        self.fetched = 0
        self.written = 0
        self.unwritten_at_query = []
        self.closed = False

    def session(self, **kwargs):
        return FakeSession(self)

    def verify_connectivity(self):
        return None

    def close(self):
        self.closed = True


class FakeS3:
    def __init__(self, fail_upload_for=None):
        self.objects = {}
        self.order = []
        self.fail_upload_for = fail_upload_for
        self.transfer_configs = []

    def upload_fileobj(self, Fileobj, Bucket, Key, ExtraArgs=None, Config=None, **kw):
        if self.fail_upload_for and self.fail_upload_for in Key:
            raise RuntimeError("S3 multipart upload failed")
        self.objects[(Bucket, Key)] = Fileobj.read()
        self.order.append(Key)
        self.transfer_configs.append(Config)

    def put_object(self, Bucket, Key, Body, **kw):
        assert isinstance(Body, (bytes, bytearray))
        self.objects[(Bucket, Key)] = bytes(Body)
        self.order.append(Key)


class FakeCloudWatch:
    def __init__(self, s3=None):
        self.calls = []
        self.s3 = s3
        self.s3_writes_at_call = []

    def put_metric_data(self, Namespace, MetricData):
        self.calls.append((Namespace, MetricData))
        self.s3_writes_at_call.append(len(self.s3.order) if self.s3 else None)


CREDS = {
    "NEO4J_URI": "neo4j+s://abc123.databases.neo4j.io",
    "NEO4J_USERNAME": "neo4j",
    "NEO4J_PASSWORD": "not-a-real-secret",
}


@pytest.fixture
def wired(monkeypatch):
    """Wire the handler to fakes. Returns a factory so tests pick the graph."""
    monkeypatch.setenv("BACKUP_BUCKET", "test-backup-bucket")
    monkeypatch.setenv("BACKUP_PREFIX", "neo4j-backups/")
    monkeypatch.setenv("BACKUP_ENV", "prod")
    monkeypatch.setattr(lf, "_neo4j_creds", None)

    def _wire(graph, page_size=4, fail_on_query=None, fail_upload_for=None):
        monkeypatch.setattr(lf, "PAGE_SIZE", page_size)
        driver = FakeDriver(graph, fail_on_query=fail_on_query)
        s3 = FakeS3(fail_upload_for=fail_upload_for)
        cw = FakeCloudWatch(s3)
        monkeypatch.setattr(lf, "_get_neo4j_credentials", lambda: CREDS)
        monkeypatch.setattr(lf, "_open_driver", lambda creds: driver)
        monkeypatch.setattr(lf, "_get_s3", lambda: s3)
        monkeypatch.setattr(lf, "_get_cloudwatch", lambda: cw)
        return driver, s3, cw

    return _wire


def _run_prefix(s3):
    manifest_keys = [k for k in s3.order if k.endswith("/manifest.json")]
    assert len(manifest_keys) == 1
    return manifest_keys[0].rsplit("/", 1)[0] + "/"


def _ndjson(s3, key):
    raw = s3.objects[("test-backup-bucket", key)]
    return [json.loads(line) for line in gzip.decompress(raw).decode("utf-8").splitlines()]


# ---------------------------------------------------------------------------
# Streaming and bounded memory
# ---------------------------------------------------------------------------

def test_export_streams_page_by_page_and_never_materialises_the_graph():
    graph = FakeGraph(n_nodes=10, n_rels=0)  # 10 nodes at page size 4 -> 3 pages
    driver = FakeDriver(graph)

    def sink(record):
        driver.events.append(("write", record["eid"]))
        driver.written += 1

    count, per_label = lf.export_nodes(driver, sink, page_size=4)

    assert count == 10
    assert driver.read_txs == 3, "one read transaction per page"
    kinds = [e[0] for e in driver.events]
    # query, 4 writes, query, 4 writes, query, 2 writes: the next page is not
    # requested until the previous one has been drained by the sink.
    assert kinds == ["query"] + ["write"] * 4 + ["query"] + ["write"] * 4 + ["query"] + ["write"] * 2
    # keyset resume: each query seeds from the last eid of the previous page
    afters = [e[2] for e in driver.events if e[0] == "query"]
    assert afters == ["", "4:g:000003", "4:g:000007"]
    # at every query, everything previously fetched had already been written
    assert driver.unwritten_at_query == [0, 0, 0]
    assert sum(per_label.values()) >= count  # multi-label nodes count per label


def test_iter_pages_is_a_lazy_generator():
    driver = FakeDriver(FakeGraph(n_nodes=9, n_rels=0))
    pages = lf.iter_pages(driver, lf.NODE_PAGE_CYPHER, page_size=4)
    assert driver.queries == 0, "creating the generator must not read anything"
    first = next(pages)
    assert len(first) == 4 and driver.queries == 1
    second = next(pages)
    assert len(second) == 4 and driver.queries == 2
    third = next(pages)
    assert len(third) == 1 and driver.queries == 3
    with pytest.raises(StopIteration):
        next(pages)
    assert driver.queries == 3, "a short page ends the scan without a trailing empty query"


def test_pagination_covers_every_row_exactly_once_on_page_boundaries():
    # 8 rows at page size 4: the last page is full, so one empty probe follows.
    driver = FakeDriver(FakeGraph(n_nodes=8, n_rels=0))
    seen = [row["eid"] for page in lf.iter_pages(driver, lf.NODE_PAGE_CYPHER, 4) for row in page]
    assert seen == ["4:g:%06d" % i for i in range(8)]
    assert driver.queries == 3


# ---------------------------------------------------------------------------
# Manifest, ordering, content
# ---------------------------------------------------------------------------

def test_manifest_written_last_and_counts_match(wired):
    graph = FakeGraph(n_nodes=10, n_rels=7)
    driver, s3, cw = wired(graph)

    result = lf.lambda_handler({}, None)

    assert result["ok"] is True and result["node_count"] == 10 and result["rel_count"] == 7
    # Commit order: data files, schema, manifest, then the latest pointer.
    names = [k.rsplit("/", 1)[-1] for k in s3.order]
    assert names == [
        "nodes.ndjson.gz", "relationships.ndjson.gz", "schema.json",
        "manifest.json", "latest.json",
    ]

    prefix = _run_prefix(s3)
    assert prefix.startswith("neo4j-backups/prod/")
    manifest = json.loads(s3.objects[("test-backup-bucket", prefix + "manifest.json")])
    assert manifest["export_version"] == 1
    assert manifest["env"] == "prod"
    assert manifest["node_count"] == 10 and manifest["rel_count"] == 7
    for field in ("started_at", "finished_at", "duration_s", "per_label_counts", "per_type_counts"):
        assert field in manifest
    nodes = _ndjson(s3, prefix + "nodes.ndjson.gz")
    rels = _ndjson(s3, prefix + "relationships.ndjson.gz")
    assert len(nodes) == manifest["node_count"] and len(rels) == manifest["rel_count"]
    assert manifest["per_label_counts"]["Project"] == sum("Project" in n["labels"] for n in nodes)
    assert sum(manifest["per_type_counts"].values()) == 7
    # bytes and sha256 describe the stored objects exactly
    for fkey in ("nodes", "relationships", "schema"):
        info = manifest["files"][fkey]
        stored = s3.objects[("test-backup-bucket", info["key"])]
        assert info["bytes"] == len(stored)
        assert info["sha256"] == hashlib.sha256(stored).hexdigest()
    assert manifest["source"]["host"] == "abc123.databases.neo4j.io"
    assert manifest["source"]["server_version"] == "5.26.0"
    assert "not-a-real-secret" not in json.dumps(manifest)

    latest = json.loads(s3.objects[("test-backup-bucket", "neo4j-backups/prod/latest.json")])
    assert latest["manifest_key"] == prefix + "manifest.json"
    assert latest["node_count"] == 10 and latest["rel_count"] == 7
    assert driver.closed is True


def test_schema_json_carries_constraints_indexes_inventory_and_version(wired):
    driver, s3, _ = wired(FakeGraph(n_nodes=5, n_rels=2))
    lf.lambda_handler({}, None)
    prefix = _run_prefix(s3)
    schema = json.loads(s3.objects[("test-backup-bucket", prefix + "schema.json")])
    assert [c["name"] for c in schema["constraints"]] == ["uniq_record_id"]
    assert {i["name"] for i in schema["indexes"]} == {"idx_status", "vec_gov"}
    vec = schema["vector_indexes"]
    assert len(vec) == 1 and vec[0]["options"]["indexConfig"]["vector.dimensions"] == 1024
    assert schema["labels"] == ["Project", "Task", "Tracked"]
    assert schema["relationship_types"] == ["PARENT_OF", "RELATED_TO"]
    assert schema["server"]["version"] == "5.26.0"


def test_gzip_ndjson_lines_parse_and_carry_stable_keys(wired):
    _, s3, _ = wired(FakeGraph(n_nodes=10, n_rels=6))
    lf.lambda_handler({}, None)
    prefix = _run_prefix(s3)
    nodes = _ndjson(s3, prefix + "nodes.ndjson.gz")
    rels = _ndjson(s3, prefix + "relationships.ndjson.gz")
    assert [n["eid"] for n in nodes] == sorted(n["eid"] for n in nodes)
    by_eid = {n["eid"]: n for n in nodes}
    assert by_eid["4:g:000000"]["key_prop"] == "project_id"
    assert by_eid["4:g:000001"]["key_prop"] == "record_id"
    assert by_eid["4:g:000001"]["key"] == "ENC-TSK-0001"
    for r in rels:
        assert set(r) >= {"eid", "type", "start_eid", "end_eid", "start_key", "end_key",
                          "start_labels", "end_labels", "properties"}
        assert r["start_key"] == by_eid[r["start_eid"]]["key"]
        assert r["end_key"] == by_eid[r["end_eid"]]["key"]


def test_non_json_native_property_values_are_serialised():
    class FakeDateTime:
        def iso_format(self):
            return "2026-10-11T03:00:00+00:00"

    line = lf._dumps({"when": FakeDateTime(), "blob": b"\x00\x01", "tags": {"b", "a"}})
    parsed = json.loads(line)
    assert parsed["when"] == "2026-10-11T03:00:00+00:00"
    assert parsed["blob"] == {"$base64": "AAE="}
    assert parsed["tags"] == ["a", "b"]


def test_spool_is_disk_backed_gzip_with_matching_checksum():
    spool = lf.GzipNdjsonSpool()
    try:
        for i in range(1000):
            spool.write_record({"i": i})
        fileobj = spool.finish()
        data = fileobj.read()
        assert hasattr(fileobj, "fileno"), "spool must be a real file, not an in-memory buffer"
        assert len(data) == spool.size
        assert hashlib.sha256(data).hexdigest() == spool.sha256
        assert spool.lines == 1000
        assert len(gzip.decompress(data).splitlines()) == 1000
    finally:
        spool.close()


# ---------------------------------------------------------------------------
# dry_run
# ---------------------------------------------------------------------------

def test_dry_run_reads_one_page_of_each_and_writes_nothing(wired):
    driver, s3, cw = wired(FakeGraph(n_nodes=30, n_rels=30), page_size=4)

    result = lf.lambda_handler({"dry_run": True}, None)

    assert result["ok"] is True and result["dry_run"] is True
    assert result["nodes_sampled"] == 4 and result["relationships_sampled"] == 4
    assert driver.queries == 2, "exactly one node page and one relationship page"
    assert s3.objects == {} and s3.order == []
    assert cw.calls == [], "a canary must not look like a successful backup"
    assert driver.closed is True


# ---------------------------------------------------------------------------
# stable key
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("props,expected", [
    ({"record_id": "R", "doc_id": "D", "id": "I", "item_id": "T", "project_id": "P"}, ("record_id", "R")),
    ({"doc_id": "D", "id": "I", "item_id": "T"}, ("doc_id", "D")),
    ({"id": "I", "item_id": "T"}, ("id", "I")),
    ({"item_id": "T", "project_id": "P"}, ("item_id", "T")),
    ({"project_id": "P", "name": "x"}, ("project_id", "P")),
    ({"record_id": None, "doc_id": "D"}, ("doc_id", "D")),
    ({"name": "x"}, (None, None)),
    ({}, (None, None)),
    (None, (None, None)),
])
def test_stable_key_selection(props, expected):
    assert lf.stable_key(props) == expected


def test_relationship_query_coalesces_endpoint_keys_in_the_same_order():
    expected = "coalesce(%s)"
    for side in ("a", "b"):
        body = ", ".join("%s.%s" % (side, p) for p in lf.STABLE_KEY_PROPS)
        assert expected % body in lf.REL_PAGE_CYPHER
    assert lf.STABLE_KEY_PROPS[:4] == ("record_id", "doc_id", "id", "item_id")
    assert "elementId(r) > $after" in lf.REL_PAGE_CYPHER
    assert "ORDER BY eid LIMIT $page" in lf.REL_PAGE_CYPHER
    assert "elementId(n) > $after" in lf.NODE_PAGE_CYPHER


# ---------------------------------------------------------------------------
# metrics and failure behaviour
# ---------------------------------------------------------------------------

def test_success_metric_is_emitted_with_env_dimension(wired):
    _, s3, cw = wired(FakeGraph(n_nodes=10, n_rels=7))
    lf.lambda_handler({}, None)

    assert len(cw.calls) == 1
    namespace, data = cw.calls[0]
    assert namespace == "EnceladusBackup"
    by_name = {m["MetricName"]: m for m in data}
    assert set(by_name) == {"Neo4jSnapshotSucceeded", "SnapshotBytes", "NodeCount", "RelCount"}
    assert by_name["Neo4jSnapshotSucceeded"]["Value"] == 1
    assert by_name["NodeCount"]["Value"] == 10 and by_name["RelCount"]["Value"] == 7
    assert by_name["SnapshotBytes"]["Value"] > 0
    for m in data:
        assert m["Dimensions"] == [{"Name": "Env", "Value": "prod"}]
    # the metric is emitted after the commit marker and the pointer, never before:
    # nodes, relationships, schema, manifest, latest = 5 writes already landed
    assert cw.s3_writes_at_call == [5]


def test_metric_not_emitted_and_error_raised_when_a_read_fails_midway(wired):
    driver, s3, cw = wired(FakeGraph(n_nodes=12, n_rels=3), fail_on_query=2)

    with pytest.raises(lf.BackupError) as excinfo:
        lf.lambda_handler({}, None)

    assert excinfo.value.stage == "export_nodes"
    assert "bolt connection lost" in str(excinfo.value)
    assert cw.calls == []
    assert not any(k.endswith("manifest.json") for k in s3.order)
    assert not any(k.endswith("latest.json") for k in s3.order)
    assert driver.closed is True


def test_metric_not_emitted_and_manifest_withheld_when_upload_fails(wired):
    _, s3, cw = wired(FakeGraph(n_nodes=10, n_rels=5), fail_upload_for="relationships")

    with pytest.raises(lf.BackupError) as excinfo:
        lf.lambda_handler({}, None)

    assert excinfo.value.stage == "upload_relationships"
    assert cw.calls == []
    assert not any(k.endswith(("manifest.json", "latest.json")) for k in s3.order)


def test_credential_failure_raises_with_stage(monkeypatch):
    monkeypatch.setenv("BACKUP_ENV", "prod")

    def _boom():
        raise RuntimeError("secret not found")

    monkeypatch.setattr(lf, "_get_neo4j_credentials", _boom)
    with pytest.raises(lf.BackupError) as excinfo:
        lf.lambda_handler({}, None)
    assert excinfo.value.stage == "credentials"


def test_invalid_backup_env_is_rejected(monkeypatch):
    monkeypatch.setenv("BACKUP_ENV", "staging")
    with pytest.raises(lf.BackupError) as excinfo:
        lf.lambda_handler({}, None)
    assert excinfo.value.stage == "config"


# ---------------------------------------------------------------------------
# configuration defaults
# ---------------------------------------------------------------------------

def test_config_defaults_to_the_private_enceladus_bucket(monkeypatch):
    for var in ("BACKUP_BUCKET", "BACKUP_PREFIX", "BACKUP_ENV", "AWS_LAMBDA_FUNCTION_NAME"):
        monkeypatch.delenv(var, raising=False)
    cfg = lf._config()
    assert cfg == {
        "bucket": "enceladus-356364570033-us-west-2-an",
        "prefix": "neo4j-backups/",
        "env": "prod",
    }
    assert cfg["bucket"] != "jreese-net"


def test_config_infers_gamma_from_function_name_and_normalises_prefix(monkeypatch):
    monkeypatch.delenv("BACKUP_ENV", raising=False)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "enceladus-neo4j-backup-gamma")
    monkeypatch.setenv("BACKUP_PREFIX", "/neo4j-backups")
    cfg = lf._config()
    assert cfg["env"] == "gamma" and cfg["prefix"] == "neo4j-backups/"
