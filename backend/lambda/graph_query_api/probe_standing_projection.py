#!/usr/bin/env python3
"""ENC-FTR-101 (Option B) live-AGA standing-projection persistence probe.

Run from a product-lead / io-dev-admin terminal that can reach the live AuraDB
Aura Graph Analytics instance (agent-CLI IAM denies the Neo4j secret). This probe
answers the ONE empirical question Option B rests on — the one the
ENC-ISS-265/268/311 saga shows must be measured, never assumed:

    Does a named GDS projection created OUT OF BAND on one Bolt connection persist
    and remain queryable (gds.pageRank.stream) from a SEPARATE Bolt connection?
    i.e. does the raw-Cypher standing-projection model hold against live AGA
    session semantics, and at what warm latency?

It mirrors the production split exactly:
    connection A  = the out-of-band refresher  (_refresh_standing_projection)
    connection B  = a warm request-path Lambda  (_hybrid_graph_ranks_gds_warm)

If B sees A's projection and streams PPR within the read budget, the raw-Cypher
Option B implementation in lambda_function.py is validated and can be activated by
setting GDS_STANDING_PROJECTION_PREFIX + provisioning the EventBridge refresh.
If B does NOT see it, escalate to explicit NAMED SESSIONS via the graphdatascience
Python client per io field guide DOC-D4CB8048798B (GdsSessions.get_or_create with
a stable session_name; thread sessionId through project + stream).

Usage:
    # creds via Secrets Manager (default secret matches the Lambda):
    python3 probe_standing_projection.py --anchor ENC-FTR-050
    # or creds via env:
    NEO4J_URI=neo4j+s://... NEO4J_USERNAME=neo4j NEO4J_PASSWORD=... \\
        python3 probe_standing_projection.py --project enceladus --anchor ENC-FTR-050

Exit codes:
    0  projection persisted cross-connection AND warm PPR returned rows  (Option B validated)
    2  projection did NOT persist/query cross-connection                 (escalate to named sessions)
    3  setup / connection error
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid

DEFAULT_SECRET = os.environ.get("NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials")
DEFAULT_REGION = os.environ.get("SECRETS_REGION", "us-west-2")
DEFAULT_MEMORY = os.environ.get("GDS_SESSION_MEMORY", "2GB")


def _load_creds() -> dict:
    """Direct env creds take precedence; otherwise pull from Secrets Manager."""
    uri = os.environ.get("NEO4J_URI")
    if uri:
        return {
            "NEO4J_URI": uri,
            "NEO4J_USERNAME": os.environ.get("NEO4J_USERNAME", "neo4j"),
            "NEO4J_PASSWORD": os.environ["NEO4J_PASSWORD"],
        }
    import boto3  # lazy
    sm = boto3.client("secretsmanager", region_name=DEFAULT_REGION)
    return json.loads(sm.get_secret_value(SecretId=DEFAULT_SECRET)["SecretString"])


def _driver(creds: dict):
    """A Bolt driver tuned per DOC-D4CB8048798B (max_connection_lifetime < NAT 350s)."""
    from neo4j import GraphDatabase  # lazy
    return GraphDatabase.driver(
        creds["NEO4J_URI"],
        auth=(creds.get("NEO4J_USERNAME", "neo4j"), creds["NEO4J_PASSWORD"]),
        max_connection_lifetime=300,
        keep_alive=True,
        connection_acquisition_timeout=120,
        max_connection_pool_size=20,
    )


def _drop(session, name: str) -> None:
    session.run(
        "CALL gds.graph.exists($n) YIELD exists WITH exists WHERE exists "
        "CALL gds.graph.drop($n) YIELD graphName RETURN graphName",
        n=name,
    ).consume()


def main() -> int:
    ap = argparse.ArgumentParser(description="ENC-FTR-101 Option B live persistence probe")
    ap.add_argument("--project", default=os.environ.get("PROJECT_ID", "enceladus"))
    ap.add_argument("--anchor", default=os.environ.get("PROBE_ANCHOR", "ENC-FTR-050"))
    ap.add_argument("--memory", default=DEFAULT_MEMORY)
    ap.add_argument("--keep", action="store_true", help="do not drop the test projection")
    args = ap.parse_args()

    name = f"ftr101_probe_{args.project}_{uuid.uuid4().hex[:8]}".replace("-", "_").lower()
    report: dict = {
        "projection": name,
        "project_id": args.project,
        "anchor": args.anchor,
        "memory": args.memory,
    }

    try:
        creds = _load_creds()
    except Exception as e:
        print(json.dumps({"ok": False, "stage": "creds", "error": str(e)}, indent=2))
        return 3

    drv_a = drv_b = None
    try:
        drv_a = _driver(creds)
        drv_a.verify_connectivity()
    except Exception as e:
        print(json.dumps({"ok": False, "stage": "connect_a", "error": str(e)}, indent=2))
        return 3

    try:
        # --- Connection A: out-of-band projection build (the refresher) ---------
        t0 = time.time()
        with drv_a.session() as s:
            _drop(s, name)
            built = s.run(
                """
                MATCH (src) WHERE src.project_id = $pid AND NOT src:GdsProjectionMeta
                OPTIONAL MATCH (src)-[r]->(tgt) WHERE tgt IS NOT NULL AND tgt.project_id = $pid
                WITH gds.graph.project(
                    $n, src, tgt,
                    {relationshipProperties: {weight: 1.0, flow_weight: 1.0}},
                    {memory: $mem}
                ) AS g
                RETURN g.graphName AS graphName, g.nodeCount AS nodeCount,
                       g.relationshipCount AS relationshipCount
                """,
                n=name, pid=args.project, mem=args.memory,
            ).single()
        report["build_ms_conn_a"] = int((time.time() - t0) * 1000)
        if built is not None:
            report["node_count"] = built.get("nodeCount")
            report["relationship_count"] = built.get("relationshipCount")

        # --- Connection B: a SEPARATE driver (simulates a different warm Lambda) -
        drv_b = _driver(creds)
        drv_b.verify_connectivity()
        with drv_b.session() as s:
            ex = s.run("CALL gds.graph.exists($n) YIELD exists RETURN exists", n=name).single()
            persisted = bool(ex and ex.get("exists"))
            report["persisted_cross_connection"] = persisted
            if persisted:
                anc = s.run(
                    "MATCH (a) WHERE a.record_id = $rid AND a.project_id = $pid "
                    "RETURN id(a) AS nid LIMIT 1",
                    rid=args.anchor, pid=args.project,
                ).single()
                if anc and anc.get("nid") is not None:
                    t1 = time.time()
                    rows = s.run(
                        """
                        CALL gds.pageRank.stream($n, {
                            sourceNodes: [$nid], dampingFactor: 0.85,
                            maxIterations: 25, relationshipWeightProperty: 'weight'
                        })
                        YIELD nodeId, score RETURN nodeId, score
                        ORDER BY score DESC LIMIT 20
                        """,
                        n=name, nid=anc["nid"],
                    ).data()
                    report["warm_ppr_ms_conn_b"] = int((time.time() - t1) * 1000)
                    report["warm_ppr_rows"] = len(rows)
                else:
                    report["warm_ppr_rows"] = 0
                    report["note"] = f"anchor {args.anchor} not found in project {args.project}"

        ok = bool(report.get("persisted_cross_connection")) and report.get("warm_ppr_rows", 0) > 0
        report["ok"] = ok
        report["verdict"] = (
            "Option B raw-Cypher standing projection VALIDATED — activate via "
            "GDS_STANDING_PROJECTION_PREFIX + EventBridge refresh."
            if ok else
            "Projection did NOT persist/query cross-connection — escalate to NAMED "
            "SESSIONS (graphdatascience client, DOC-D4CB8048798B)."
        )
    except Exception as e:
        report["ok"] = False
        report["stage"] = "probe"
        report["error"] = str(e)
    finally:
        if not args.keep and drv_a is not None:
            try:
                with drv_a.session() as s:
                    _drop(s, name)
            except Exception:
                pass
        for d in (drv_a, drv_b):
            try:
                if d is not None:
                    d.close()
            except Exception:
                pass

    print(json.dumps(report, indent=2))
    return 0 if report.get("ok") else 2


if __name__ == "__main__":
    sys.exit(main())
