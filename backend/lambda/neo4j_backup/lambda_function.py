"""Neo4j AuraDB graph snapshot to S3 (ENC-TSK-Q61 / ENC-ISS-847).

Streams the whole graph out of AuraDB as gzip NDJSON, one record per line, into
a PRIVATE bucket, then commits the run with a manifest.

Why it was rewritten: the previous version loaded every node and relationship
into Python lists and then built one ``json.dumps(indent=2)`` string for a single
``put_object``. That OOMed the 512 MB function every night from 2026-08-17 and
wrote its output to the public site bucket. Nothing alerted on the missed backup.

Design
------
* Keyset-paged reads: one READ transaction per page of ``PAGE_SIZE`` rows,
  ordered by ``elementId`` and resumed with ``WHERE elementId(x) > $after``.
  Only the current page is ever held in memory.
* Each record is serialised to one JSON line, pushed through gzip into a
  disk-backed spool file in /tmp (the function has 2 GB of ephemeral storage),
  then handed to ``upload_fileobj`` which performs an S3 multipart upload.
* Per run, under ``s3://$BACKUP_BUCKET/$BACKUP_PREFIX$env/YYYY/MM/DD/<ts>/``:
  nodes.ndjson.gz, relationships.ndjson.gz, schema.json and, written LAST as
  the commit marker, manifest.json. A run without a manifest is incomplete.
* ``$BACKUP_PREFIX$env/latest.json`` is rewritten only after the manifest lands
  and points at the newest complete manifest.
* CloudWatch namespace ``EnceladusBackup`` (dimension ``Env``) receives
  ``Neo4jSnapshotSucceeded=1`` ONLY on success; the freshness alarm in
  05-monitoring.yaml treats a missing datapoint as breaching.
* ``{"dry_run": true}`` reads one page of nodes and one of relationships and
  writes nothing. It is the post-deploy canary.

Restore path: tools/backfill_graph.py re-projects from DynamoDB (source of
truth). This export is the audit/disaster-recovery copy of the projection,
including the vector properties and the schema (constraints and indexes).
"""
import base64
import gzip
import hashlib
import json
import logging
import os
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

EXPORT_VERSION = 1
PAGE_SIZE = 5000
METRIC_NAMESPACE = "EnceladusBackup"

DEFAULT_BACKUP_BUCKET = "enceladus-356364570033-us-west-2-an"
DEFAULT_BACKUP_PREFIX = "neo4j-backups/"
VALID_ENVS = ("prod", "gamma")

# The application-level identity of a node, in priority order. graph_sync MERGEs
# every governed record on ``record_id`` (tasks, issues, features, plans, lessons,
# documents, recipes, escalations, tools, agent identities...); ``:Project`` is the
# one exception and MERGEs on ``project_id``, so that is the final fallback.
# doc_id / id / item_id are carried for older or hand-written nodes.
STABLE_KEY_PROPS = ("record_id", "doc_id", "id", "item_id", "project_id")

_COALESCE_A = "coalesce(" + ", ".join("a.%s" % p for p in STABLE_KEY_PROPS) + ")"
_COALESCE_B = "coalesce(" + ", ".join("b.%s" % p for p in STABLE_KEY_PROPS) + ")"

NODE_PAGE_CYPHER = (
    "MATCH (n) WHERE elementId(n) > $after "
    "RETURN elementId(n) AS eid, labels(n) AS labels, properties(n) AS props "
    "ORDER BY eid LIMIT $page"
)
REL_PAGE_CYPHER = (
    "MATCH (a)-[r]->(b) WHERE elementId(r) > $after "
    "RETURN elementId(r) AS eid, type(r) AS type, properties(r) AS props, "
    "elementId(a) AS start_eid, elementId(b) AS end_eid, "
    "labels(a) AS start_labels, labels(b) AS end_labels, "
    + _COALESCE_A + " AS start_key, " + _COALESCE_B + " AS end_key "
    "ORDER BY eid LIMIT $page"
)

# S3 multipart tuning. Concurrency x chunk size bounds the buffered bytes.
_MULTIPART_BYTES = 8 * 1024 * 1024
_UPLOAD_CONCURRENCY = 4

_secretsmanager = None
_neo4j_creds = None
_s3_client = None
_cloudwatch = None


class BackupError(RuntimeError):
    """Raised for any failed export; the message carries the failing stage."""

    def __init__(self, stage, message):
        super().__init__("neo4j snapshot failed at stage=%s: %s" % (stage, message))
        self.stage = stage


class _Stage:
    """Mutable cursor so the top-level handler can report where a run died."""

    def __init__(self):
        self.name = "init"

    def set(self, name):
        self.name = name


# ---------------------------------------------------------------------------
# AWS clients and credentials
# ---------------------------------------------------------------------------

def _get_secrets():
    global _secretsmanager
    if _secretsmanager is None:
        _secretsmanager = boto3.client(
            "secretsmanager",
            region_name=os.environ.get("SECRETS_REGION", "us-west-2"),
        )
    return _secretsmanager


def _get_neo4j_credentials():
    global _neo4j_creds
    if _neo4j_creds is None:
        secret_name = os.environ.get(
            "NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials"
        )
        resp = _get_secrets().get_secret_value(SecretId=secret_name)
        _neo4j_creds = json.loads(resp["SecretString"])
    return _neo4j_creds


def _get_s3():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3", region_name=os.environ.get("AWS_REGION", "us-west-2"))
    return _s3_client


def _get_cloudwatch():
    global _cloudwatch
    if _cloudwatch is None:
        _cloudwatch = boto3.client(
            "cloudwatch", region_name=os.environ.get("AWS_REGION", "us-west-2")
        )
    return _cloudwatch


def _open_driver(creds):
    """Open a neo4j 5.x driver. Imported lazily so tests need no driver package."""
    from neo4j import GraphDatabase

    return GraphDatabase.driver(
        creds["NEO4J_URI"],
        auth=(creds.get("NEO4J_USERNAME", "neo4j"), creds["NEO4J_PASSWORD"]),
    )


def _config():
    bucket = os.environ.get("BACKUP_BUCKET") or DEFAULT_BACKUP_BUCKET
    prefix = (os.environ.get("BACKUP_PREFIX") or DEFAULT_BACKUP_PREFIX).lstrip("/")
    if not prefix.endswith("/"):
        prefix += "/"
    env = os.environ.get("BACKUP_ENV")
    if not env:
        fn = os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "")
        env = "gamma" if fn.endswith("-gamma") else "prod"
    if env not in VALID_ENVS:
        raise ValueError("BACKUP_ENV must be one of %s, got %r" % (VALID_ENVS, env))
    return {"bucket": bucket, "prefix": prefix, "env": env}


# ---------------------------------------------------------------------------
# Record shaping and serialisation
# ---------------------------------------------------------------------------

def stable_key(props):
    """Return (property_name, value) of the first present identity property.

    "Present" means non-null, the same rule Cypher's coalesce() applies in the
    relationship query, so node keys and relationship endpoint keys agree.
    """
    if props:
        for name in STABLE_KEY_PROPS:
            value = props.get(name)
            if value is not None:
                return name, value
    return None, None


def _json_default(obj):
    """Fallback for values the neo4j driver returns that json cannot encode."""
    iso = getattr(obj, "iso_format", None)  # neo4j.time Date/Time/DateTime/Duration
    if callable(iso):
        return iso()
    if isinstance(obj, (bytes, bytearray)):
        return {"$base64": base64.b64encode(bytes(obj)).decode("ascii")}
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=str)
    return str(obj)


def _dumps(obj):
    return json.dumps(obj, default=_json_default, separators=(",", ":"), ensure_ascii=False)


class _HashingWriter:
    """Pass-through writer that hashes and counts the (compressed) bytes."""

    def __init__(self, raw):
        self._raw = raw
        self.sha256 = hashlib.sha256()
        self.size = 0

    def write(self, data):
        self.sha256.update(data)
        self.size += len(data)
        return self._raw.write(data)

    def flush(self):
        self._raw.flush()


class GzipNdjsonSpool:
    """Append JSON lines through gzip into a disk-backed file.

    Memory use is independent of record count: the gzip compressor holds a
    window, the spool lives on /tmp. ``finish()`` seals the stream and rewinds
    it for ``upload_fileobj``.
    """

    def __init__(self):
        self._file = tempfile.TemporaryFile()
        self._hasher = _HashingWriter(self._file)
        self._gz = gzip.GzipFile(fileobj=self._hasher, mode="wb", compresslevel=6, mtime=0)
        self.lines = 0
        self._sealed = False

    def write_record(self, record):
        self._gz.write(_dumps(record).encode("utf-8") + b"\n")
        self.lines += 1

    def finish(self):
        if not self._sealed:
            self._gz.close()
            self._file.flush()
            self._file.seek(0)
            self._sealed = True
        return self._file

    @property
    def size(self):
        return self._hasher.size

    @property
    def sha256(self):
        return self._hasher.sha256.hexdigest()

    def close(self):
        try:
            if not self._sealed:
                self._gz.close()
        finally:
            self._file.close()


# ---------------------------------------------------------------------------
# Keyset-paged reads
# ---------------------------------------------------------------------------

def _read_page(session, cypher, after, page_size):
    def _tx(tx):
        return [dict(rec) for rec in tx.run(cypher, after=after, page=page_size)]

    return session.execute_read(_tx)


def iter_pages(driver, cypher, page_size=PAGE_SIZE, database=None, max_pages=None):
    """Yield successive lists of at most ``page_size`` rows.

    A generator on purpose: the caller drains one page before the next read
    transaction is issued, so at most one page is resident. Each page is its own
    read transaction; ``eid`` of the last row seeds the next page.
    """
    after = ""
    pages = 0
    session_kwargs = {"database": database} if database else {}
    with driver.session(**session_kwargs) as session:
        while True:
            rows = _read_page(session, cypher, after, page_size)
            if not rows:
                return
            pages += 1
            yield rows
            if len(rows) < page_size or (max_pages is not None and pages >= max_pages):
                return
            after = rows[-1]["eid"]


def node_record(row):
    props = row.get("props") or {}
    key_prop, key = stable_key(props)
    return {
        "eid": row["eid"],
        "labels": list(row.get("labels") or []),
        "key_prop": key_prop,
        "key": key,
        "properties": props,
    }


def relationship_record(row):
    return {
        "eid": row["eid"],
        "type": row["type"],
        "start_eid": row["start_eid"],
        "end_eid": row["end_eid"],
        "start_key": row.get("start_key"),
        "end_key": row.get("end_key"),
        "start_labels": list(row.get("start_labels") or []),
        "end_labels": list(row.get("end_labels") or []),
        "properties": row.get("props") or {},
    }


def export_nodes(driver, sink, page_size=PAGE_SIZE, database=None, max_pages=None):
    """Stream every node into ``sink(record)``. Returns (count, per_label_counts)."""
    per_label = Counter()
    count = 0
    for page in iter_pages(driver, NODE_PAGE_CYPHER, page_size, database, max_pages):
        for row in page:
            rec = node_record(row)
            sink(rec)
            count += 1
            for label in rec["labels"]:
                per_label[label] += 1
    return count, dict(sorted(per_label.items()))


def export_relationships(driver, sink, page_size=PAGE_SIZE, database=None, max_pages=None):
    """Stream every relationship into ``sink(record)``. Returns (count, per_type_counts)."""
    per_type = Counter()
    count = 0
    for page in iter_pages(driver, REL_PAGE_CYPHER, page_size, database, max_pages):
        for row in page:
            rec = relationship_record(row)
            sink(rec)
            count += 1
            per_type[rec["type"]] += 1
    return count, dict(sorted(per_type.items()))


def collect_schema(driver, database=None):
    """SHOW CONSTRAINTS / INDEXES (vector index options included), inventories, version."""
    session_kwargs = {"database": database} if database else {}
    with driver.session(**session_kwargs) as session:
        constraints = [dict(r) for r in session.run("SHOW CONSTRAINTS YIELD *")]
        indexes = [dict(r) for r in session.run("SHOW INDEXES YIELD *")]
        labels = [r["label"] for r in session.run("CALL db.labels() YIELD label RETURN label")]
        rel_types = [
            r["relationshipType"]
            for r in session.run(
                "CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType"
            )
        ]
        components = [
            dict(r)
            for r in session.run(
                "CALL dbms.components() YIELD name, versions, edition "
                "RETURN name, versions, edition"
            )
        ]
    server = next((c for c in components if c.get("name") == "Neo4j Kernel"), None)
    if server is None and components:
        server = components[0]
    versions = (server or {}).get("versions") or []
    return {
        "constraints": constraints,
        "indexes": indexes,
        "vector_indexes": [i for i in indexes if str(i.get("type", "")).upper() == "VECTOR"],
        "labels": sorted(labels),
        "relationship_types": sorted(rel_types),
        "server": {
            "version": versions[0] if versions else None,
            "edition": (server or {}).get("edition"),
            "components": components,
        },
        "stable_key_order": list(STABLE_KEY_PROPS),
    }


# ---------------------------------------------------------------------------
# S3 and metrics
# ---------------------------------------------------------------------------

def _upload_spool(s3, spool, bucket, key):
    from boto3.s3.transfer import TransferConfig

    fileobj = spool.finish()
    s3.upload_fileobj(
        Fileobj=fileobj,
        Bucket=bucket,
        Key=key,
        ExtraArgs={"ContentType": "application/x-ndjson"},
        Config=TransferConfig(
            multipart_threshold=_MULTIPART_BYTES,
            multipart_chunksize=_MULTIPART_BYTES,
            max_concurrency=_UPLOAD_CONCURRENCY,
        ),
    )
    return {
        "key": key,
        "bytes": spool.size,
        "sha256": spool.sha256,
        "lines": spool.lines,
    }


def _put_json(s3, bucket, key, document):
    body = (json.dumps(document, default=_json_default, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    s3.put_object(
        Bucket=bucket, Key=key, Body=body, ContentType="application/json"
    )
    return {"key": key, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def _emit_metrics(env, total_bytes, node_count, rel_count):
    dims = [{"Name": "Env", "Value": env}]
    _get_cloudwatch().put_metric_data(
        Namespace=METRIC_NAMESPACE,
        MetricData=[
            {"MetricName": "Neo4jSnapshotSucceeded", "Dimensions": dims, "Value": 1, "Unit": "Count"},
            {"MetricName": "SnapshotBytes", "Dimensions": dims, "Value": total_bytes, "Unit": "Bytes"},
            {"MetricName": "NodeCount", "Dimensions": dims, "Value": node_count, "Unit": "Count"},
            {"MetricName": "RelCount", "Dimensions": dims, "Value": rel_count, "Unit": "Count"},
        ],
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _dry_run(driver, database, stage):
    """Canary: one page of each, serialised and discarded. Writes nothing."""
    stage.set("dry_run_nodes")
    sampled_nodes = 0

    def _discard(record):
        _dumps(record)

    sampled_nodes, _ = export_nodes(driver, _discard, PAGE_SIZE, database, max_pages=1)
    stage.set("dry_run_relationships")
    sampled_rels, _ = export_relationships(driver, _discard, PAGE_SIZE, database, max_pages=1)
    logger.info("[DRY-RUN] ok: %d nodes, %d relationships sampled", sampled_nodes, sampled_rels)
    return {
        "statusCode": 200,
        "ok": True,
        "dry_run": True,
        "nodes_sampled": sampled_nodes,
        "relationships_sampled": sampled_rels,
    }


def _run_export(driver, cfg, creds, database, stage):
    s3 = _get_s3()
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    run_ts = started.strftime("%Y%m%dT%H%M%SZ")
    run_prefix = "%s%s/%s/%s/" % (cfg["prefix"], cfg["env"], started.strftime("%Y/%m/%d"), run_ts)
    bucket = cfg["bucket"]
    files = {}

    stage.set("export_nodes")
    nodes_spool = GzipNdjsonSpool()
    try:
        node_count, per_label = export_nodes(driver, nodes_spool.write_record, PAGE_SIZE, database)
        logger.info("[INFO] streamed %d nodes", node_count)
        stage.set("upload_nodes")
        files["nodes"] = _upload_spool(s3, nodes_spool, bucket, run_prefix + "nodes.ndjson.gz")
    finally:
        nodes_spool.close()

    stage.set("export_relationships")
    rels_spool = GzipNdjsonSpool()
    try:
        rel_count, per_type = export_relationships(
            driver, rels_spool.write_record, PAGE_SIZE, database
        )
        logger.info("[INFO] streamed %d relationships", rel_count)
        stage.set("upload_relationships")
        files["relationships"] = _upload_spool(
            s3, rels_spool, bucket, run_prefix + "relationships.ndjson.gz"
        )
    finally:
        rels_spool.close()

    stage.set("schema")
    schema = collect_schema(driver, database)
    schema_doc = dict(schema, export_version=EXPORT_VERSION, env=cfg["env"])
    stage.set("upload_schema")
    files["schema"] = _put_json(s3, bucket, run_prefix + "schema.json", schema_doc)

    stage.set("manifest")
    finished = datetime.now(timezone.utc)
    duration_s = round(time.monotonic() - t0, 3)
    uri = urlparse(str(creds.get("NEO4J_URI", "")))
    manifest = {
        "export_version": EXPORT_VERSION,
        "env": cfg["env"],
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_s": duration_s,
        "node_count": node_count,
        "rel_count": rel_count,
        "per_label_counts": per_label,
        "per_type_counts": per_type,
        "files": files,
        "source": {
            "database": database or creds.get("NEO4J_DATABASE") or "neo4j",
            "host": uri.hostname,
            "scheme": uri.scheme,
            "server_version": schema["server"]["version"],
        },
        "page_size": PAGE_SIZE,
        "stable_key_order": list(STABLE_KEY_PROPS),
        "bucket": bucket,
        "prefix": run_prefix,
    }
    manifest_key = run_prefix + "manifest.json"
    # The manifest is the commit marker: nothing else may be written after it
    # except the latest.json pointer.
    manifest_info = _put_json(s3, bucket, manifest_key, manifest)

    stage.set("latest_pointer")
    latest_key = "%s%s/latest.json" % (cfg["prefix"], cfg["env"])
    _put_json(
        s3,
        bucket,
        latest_key,
        {
            "export_version": EXPORT_VERSION,
            "env": cfg["env"],
            "manifest_key": manifest_key,
            "manifest_sha256": manifest_info["sha256"],
            "run_ts": run_ts,
            "finished_at": finished.isoformat(),
            "node_count": node_count,
            "rel_count": rel_count,
        },
    )

    stage.set("metrics")
    total_bytes = sum(f["bytes"] for f in files.values()) + manifest_info["bytes"]
    _emit_metrics(cfg["env"], total_bytes, node_count, rel_count)

    logger.info(
        "[SUCCESS] snapshot s3://%s/%s (%d nodes, %d rels, %d bytes, %.1fs)",
        bucket, run_prefix, node_count, rel_count, total_bytes, duration_s,
    )
    return {
        "statusCode": 200,
        "ok": True,
        "env": cfg["env"],
        "s3_bucket": bucket,
        "manifest_key": manifest_key,
        "latest_key": latest_key,
        "node_count": node_count,
        "rel_count": rel_count,
        "bytes": total_bytes,
        "duration_s": duration_s,
    }


def lambda_handler(event, context):
    """Export the Neo4j graph to S3 (or, with ``{"dry_run": true}``, probe it)."""
    event = event if isinstance(event, dict) else {}
    dry_run = bool(event.get("dry_run"))
    stage = _Stage()
    logger.info("[START] Neo4j graph snapshot export (dry_run=%s)", dry_run)

    driver = None
    try:
        stage.set("config")
        cfg = _config()

        stage.set("credentials")
        creds = _get_neo4j_credentials()
        database = creds.get("NEO4J_DATABASE") or None

        stage.set("connect")
        driver = _open_driver(creds)
        driver.verify_connectivity()
        logger.info("[INFO] Neo4j connection verified")

        if dry_run:
            return _dry_run(driver, database, stage)
        return _run_export(driver, cfg, creds, database, stage)
    except Exception as exc:
        logger.exception(
            "[ERROR] stage=%s %s: %s", stage.name, type(exc).__name__, exc
        )
        raise BackupError(stage.name, "%s: %s" % (type(exc).__name__, exc)) from exc
    finally:
        if driver is not None:
            try:
                driver.close()
            except Exception:  # pragma: no cover - close must never mask the result
                logger.warning("[WARN] driver.close() failed", exc_info=True)
