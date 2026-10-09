#!/usr/bin/env python3
"""Detect Neo4j drift and replay DynamoDB images into graph/feed FIFO queues.

ENC-TSK-Q57: a FIFO dedup bug dropped ~75% of DynamoDB stream events, leaving
Neo4j nodes stale. ``compare`` finds the drift (missing nodes, status drift,
stale documents); ``replay`` re-sends CURRENT DynamoDB images to the queues as
stream-shaped messages so graph_sync and feed_publisher converge.

Stdlib + boto3 only (Neo4j is queried via the HTTPS Query API v2).

Usage:
    python3 tools/graph_feed_resync.py compare --env prod --out drift.json
    python3 tools/graph_feed_resync.py replay --ids-file drift.json --dry-run
    python3 tools/graph_feed_resync.py replay --ids-file drift.json \
        --targets graph,feed --send-profile enceladus-agent
"""
from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import json
import functools
import logging
import ssl
import sys
import urllib.request
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("graph_feed_resync")

DEFAULT_REGION = "us-west-2"
DEFAULT_SECRET = "enceladus/neo4j/auradb-credentials"
ENTITY_LABELS = {
    "task": "Task",
    "issue": "Issue",
    "feature": "Feature",
    "plan": "Plan",
    "document": "Document",
}
DEFAULT_RECORD_TYPES = "task,issue,feature,plan"
BATCH_SIZE = 10
PAGE_SIZE = 5000


def _suffix(env: str) -> str:
    return "-gamma" if env == "gamma" else ""


def _bare_id(record_id: str) -> str:
    """Mirror graph_sync._bare_id: 'task#ENC-TSK-1' -> 'ENC-TSK-1'."""
    return record_id.split("#", 1)[-1] if "#" in record_id else record_id


# --------------------------------------------------------------------------
# DynamoDB-JSON helpers
# --------------------------------------------------------------------------
def _plain(attr: Dict[str, Any]) -> Any:
    """Tiny DynamoDB-JSON -> python for the scalar fields we compare."""
    if not isinstance(attr, dict):
        return attr
    if "S" in attr:
        return attr["S"]
    if "N" in attr:
        return attr["N"]
    if "BOOL" in attr:
        return attr["BOOL"]
    return None


def _flat(item: Dict[str, Any], key: str) -> str:
    return str(_plain(item.get(key, {})) or "")


def is_relationship_record(item: Dict[str, Any]) -> bool:
    """Edge rows: record_type == 'relationship' (graph_sync/backfill_graph rule)."""
    return _flat(item, "record_type").strip() == "relationship"


def is_entity_record(item: Dict[str, Any], record_types: Iterable[str]) -> bool:
    if is_relationship_record(item):
        return False
    return _flat(item, "record_type").strip() in set(record_types)


# --------------------------------------------------------------------------
# Neo4j Query API v2
# --------------------------------------------------------------------------
def neo4j_https_base(uri: str) -> str:
    """Convert neo4j+s://host[:port] (or bolt/neo4j schemes) to https://host."""
    rest = uri.split("://", 1)[-1].strip().rstrip("/")
    host = rest.split("/", 1)[0]
    if ":" in host:
        host = host.split(":", 1)[0]
    return f"https://{host}"


def parse_query_response(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = payload.get("data") or {}
    fields = data.get("fields") or []
    return [dict(zip(fields, row)) for row in data.get("values") or []]


def _ssl_context() -> ssl.SSLContext:
    """Prefer certifi's CA bundle: framework Pythons on macOS ship without one."""
    try:
        import certifi  # botocore depends on it, so it is normally present
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


class Neo4jClient:
    def __init__(self, creds: Dict[str, str], opener=None):
        self.base = neo4j_https_base(creds["NEO4J_URI"])
        self.database = creds.get("NEO4J_DATABASE") or "neo4j"
        user = creds.get("NEO4J_USERNAME") or "neo4j"
        token = base64.b64encode(f"{user}:{creds['NEO4J_PASSWORD']}".encode()).decode()
        self._auth = f"Basic {token}"
        self._open = opener or functools.partial(urllib.request.urlopen, context=_ssl_context())

    def query(self, statement: str, parameters: Optional[Dict[str, Any]] = None):
        req = urllib.request.Request(
            f"{self.base}/db/{self.database}/query/v2",
            data=json.dumps({"statement": statement, "parameters": parameters or {}}).encode(),
            headers={
                "Authorization": self._auth,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        with self._open(req, timeout=60) as resp:
            return parse_query_response(json.loads(resp.read().decode()))

    def fetch_nodes(self, label: str) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        skip = 0
        while True:
            rows = self.query(
                f"MATCH (n:{label}) RETURN n.record_id AS record_id, n.status AS status, "
                "n.updated_at AS updated_at ORDER BY n.record_id SKIP $skip LIMIT $limit",
                {"skip": skip, "limit": PAGE_SIZE},
            )
            for row in rows:
                out[str(row.get("record_id"))] = row
            if len(rows) < PAGE_SIZE:
                return out
            skip += PAGE_SIZE


# --------------------------------------------------------------------------
# compare
# --------------------------------------------------------------------------
def scan_all(ddb, table: str) -> Iterable[Dict[str, Any]]:
    kwargs: Dict[str, Any] = {"TableName": table}
    while True:
        resp = ddb.scan(**kwargs)
        for item in resp.get("Items", []):
            yield item
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            return
        kwargs["ExclusiveStartKey"] = lek


def classify_tracker(item: Dict[str, Any], nodes: Dict[str, Dict[str, Any]]) -> Optional[str]:
    rid = _bare_id(_flat(item, "item_id") or _flat(item, "record_id"))
    node = nodes.get(rid)
    if node is None:
        return "missing"
    if str(node.get("status") or "") != _flat(item, "status"):
        return "status_drift"
    return None


def classify_document(item: Dict[str, Any], nodes: Dict[str, Dict[str, Any]]) -> Optional[str]:
    node = nodes.get(_flat(item, "document_id"))
    if node is None:
        return "missing"
    if str(node.get("updated_at") or "") < _flat(item, "updated_at"):
        return "stale"
    return None


def build_drift(
    tracker_items: Iterable[Dict[str, Any]],
    document_items: Iterable[Dict[str, Any]],
    graph_nodes: Dict[str, Dict[str, Dict[str, Any]]],
    record_types: List[str],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    ids: List[Dict[str, Any]] = []
    counts: Dict[str, Dict[str, int]] = collections.defaultdict(lambda: collections.defaultdict(int))
    pairs: collections.Counter = collections.Counter()
    for item in tracker_items:
        if not is_entity_record(item, record_types):
            continue
        rtype = _flat(item, "record_type")
        cls = classify_tracker(item, graph_nodes.get(rtype, {}))
        if not cls:
            continue
        rid = _bare_id(_flat(item, "item_id") or _flat(item, "record_id"))
        if cls == "status_drift":
            node = graph_nodes.get(rtype, {}).get(rid, {})
            pairs[f"{_flat(item, 'status')} -> {node.get('status')}"] += 1
        counts[rtype][cls] += 1
        ids.append({
            "table": "tracker",
            "project_id": _flat(item, "project_id"),
            "record_id": _flat(item, "record_id"),
            "item_id": _flat(item, "item_id") or rid,
            "record_type": rtype,
            "class": cls,
        })
    for item in document_items:
        cls = classify_document(item, graph_nodes.get("document", {}))
        if not cls:
            continue
        counts["document"][cls] += 1
        ids.append({
            "table": "documents",
            "document_id": _flat(item, "document_id"),
            "project_id": _flat(item, "project_id"),
            "class": cls,
        })
    summary = {
        "counts": {k: dict(v) for k, v in counts.items()},
        "top_status_pairs": [{"pair": p, "count": c} for p, c in pairs.most_common(10)],
        "total": len(ids),
    }
    return ids, summary


def _sessions(args, profile: str):
    import boto3
    return boto3.Session(profile_name=profile, region_name=args.region)


def cmd_compare(args) -> int:
    sfx = _suffix(args.env)
    sess = _sessions(args, args.read_profile)
    ddb = sess.client("dynamodb")
    sm = sess.client("secretsmanager")
    creds = json.loads(sm.get_secret_value(SecretId=args.secret_name)["SecretString"])
    neo = Neo4jClient(creds)
    record_types = [t.strip() for t in args.record_types.split(",") if t.strip()]
    labels = [t for t in record_types if t in ENTITY_LABELS]
    if not args.no_documents:
        labels.append("document")
    graph_nodes = {t: neo.fetch_nodes(ENTITY_LABELS[t]) for t in labels}
    for t, n in graph_nodes.items():
        logger.info("[INFO] graph %s nodes: %d", t, len(n))
    tracker = scan_all(ddb, f"devops-project-tracker{sfx}")
    docs = [] if args.no_documents else scan_all(ddb, f"documents{sfx}")
    ids, summary = build_drift(tracker, docs, graph_nodes, record_types)
    out = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "env": args.env,
        "summary": summary,
        "ids": ids,
    }
    with open(args.out, "w") as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps(summary, indent=2))
    print(f"[SUCCESS] wrote {len(ids)} ids to {args.out}")
    return 0


# --------------------------------------------------------------------------
# replay
# --------------------------------------------------------------------------
def build_stream_message(item: Dict[str, Any], keys: Dict[str, Any], region: str) -> Dict[str, Any]:
    return {
        "eventID": f"resync-{uuid.uuid4().hex}",
        "eventName": "MODIFY",
        "eventSource": "aws:dynamodb",
        "awsRegion": region,
        "dynamodb": {"Keys": keys, "NewImage": item, "StreamViewType": "NEW_AND_OLD_IMAGES"},
    }


def _entry(idx: int, group: str, body: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "Id": str(idx),
        "MessageBody": json.dumps(body),
        "MessageGroupId": group,
        "MessageDeduplicationId": body["eventID"],
    }


def build_entries(
    resolved: List[Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]],
    region: str,
    targets: List[str],
) -> Dict[str, List[Dict[str, Any]]]:
    """resolved: [(id_entry, keys, item)] -> {"graph": [...], "feed": [...]}."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    if "graph" in targets:
        out["graph"] = []
        for i, (ent, keys, item) in enumerate(resolved):
            group = "document" if ent.get("table") == "documents" else (
                ent.get("project_id") or _flat(item, "project_id"))
            out["graph"].append(_entry(i, group, build_stream_message(item, keys, region)))
    if "feed" in targets:
        out["feed"] = []
        seen = set()
        for ent, keys, item in resolved:
            pid = ent.get("project_id") or _flat(item, "project_id")
            if not pid or pid in seen:
                continue
            seen.add(pid)
            out["feed"].append(_entry(len(out["feed"]), pid, build_stream_message(item, keys, region)))
    return out


def chunked(seq: List[Any], n: int = BATCH_SIZE) -> List[List[Any]]:
    return [seq[i:i + n] for i in range(0, len(seq), n)]


def send_entries(sqs, queue_url: str, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    failed: List[Dict[str, Any]] = []
    for batch in chunked(entries):
        # Ids only need to be unique within a batch.
        batch = [dict(e, Id=str(i)) for i, e in enumerate(batch)]
        resp = sqs.send_message_batch(QueueUrl=queue_url, Entries=batch)
        failed.extend(resp.get("Failed", []))
    return failed


def _key_for(ent: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    if ent.get("table") == "documents":
        return "documents", {"document_id": {"S": ent["document_id"]}}
    return "tracker", {"project_id": {"S": ent["project_id"]}, "record_id": {"S": ent["record_id"]}}


def cmd_replay(args) -> int:
    sfx = _suffix(args.env)
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    with open(args.ids_file) as fh:
        ids = json.load(fh)["ids"]
    ddb = _sessions(args, args.read_profile).client("dynamodb")
    resolved = []
    for ent in ids:
        kind, key = _key_for(ent)
        table = f"documents{sfx}" if kind == "documents" else f"devops-project-tracker{sfx}"
        item = ddb.get_item(TableName=table, Key=key).get("Item")
        if not item:
            logger.warning("[WARN] %s gone, skipping", ent.get("record_id") or ent.get("document_id"))
            continue
        resolved.append((ent, key, item))
    entries = build_entries(resolved, args.region, targets)
    queues = {"graph": f"devops-graph-sync-queue{sfx}.fifo", "feed": f"devops-feed-publish-queue{sfx}.fifo"}
    for t, es in entries.items():
        print(f"[INFO] {t}: {len(es)} messages -> {queues[t]}")
    if args.dry_run:
        for t, es in entries.items():
            if es:
                print(f"[INFO] sample {t} body: {es[0]['MessageBody']}")
        return 0
    sqs = _sessions(args, args.send_profile).client("sqs")
    failed_total = 0
    for t, es in entries.items():
        url = sqs.get_queue_url(QueueName=queues[t])["QueueUrl"]
        failed = send_entries(sqs, url, es)
        failed_total += len(failed)
        print(f"[{'ERROR' if failed else 'SUCCESS'}] {t}: sent {len(es) - len(failed)}, failed {len(failed)}")
        for f in failed:
            print(f"  failed: {json.dumps(f)}")
    return 1 if failed_total else 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--env", choices=["prod", "gamma"], default="prod")
        sp.add_argument("--region", default=DEFAULT_REGION)
        sp.add_argument("--read-profile", default="product-lead")

    c = sub.add_parser("compare")
    common(c)
    c.add_argument("--secret-name", default=DEFAULT_SECRET)
    c.add_argument("--record-types", default=DEFAULT_RECORD_TYPES)
    c.add_argument("--no-documents", action="store_true")
    c.add_argument("--out", required=True)
    r = sub.add_parser("replay")
    common(r)
    r.add_argument("--ids-file", required=True)
    r.add_argument("--send-profile", default="enceladus-agent")
    r.add_argument("--targets", default="graph,feed")
    r.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    return cmd_compare(args) if args.cmd == "compare" else cmd_replay(args)


if __name__ == "__main__":
    sys.exit(main())
