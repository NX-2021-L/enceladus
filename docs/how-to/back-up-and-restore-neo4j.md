# How to back up and restore Neo4j

## Overview

The Enceladus graph index (Neo4j AuraDB) is a **read-only derived projection** of
DynamoDB tracker data. DynamoDB is the source of truth. The backup strategy reflects this:

- **Daily snapshot**: the Lambda streams the current graph (nodes, relationships, schema)
  to a PRIVATE S3 bucket as gzip NDJSON plus a manifest (ENC-TSK-Q61)
- **Restore**: Re-project from DynamoDB using `tools/backfill_graph.py` (~5-10 min for ~1,420 records)
- **S3 snapshots**: disaster-recovery and audit copy, including vector properties and the
  constraint/index definitions, which a re-projection does not recover on its own
- **Freshness alarm**: `enceladus-neo4j-snapshot-freshness` (05-monitoring.yaml) pages the
  `enceladus-deploy-alerts` SNS topic when no successful prod snapshot has landed in 26 hours

## Layout

```
s3://enceladus-356364570033-us-west-2-an/neo4j-backups/<env>/latest.json
s3://enceladus-356364570033-us-west-2-an/neo4j-backups/<env>/YYYY/MM/DD/<ts>/
    nodes.ndjson.gz          one node per line: eid, labels, key_prop, key, properties
    relationships.ndjson.gz  one relationship per line: eid, type, start/end eid, start/end key + labels, properties
    schema.json              constraints, indexes (vector index options), label and type inventory, server version
    manifest.json            counts, per-label/per-type counts, bytes + sha256 per file. Written LAST.
```

`<env>` is `prod` or `gamma`. **A run directory without `manifest.json` is incomplete and must
not be used**; `latest.json` only ever points at a committed manifest. The stable application
key of a node is the first present of `record_id`, `doc_id`, `id`, `item_id`, `project_id`
(graph_sync MERGEs on `record_id`; `:Project` on `project_id`).

## List Available Backups

```bash
aws s3 ls s3://enceladus-356364570033-us-west-2-an/neo4j-backups/prod/ --recursive
aws s3 cp s3://enceladus-356364570033-us-west-2-an/neo4j-backups/prod/latest.json -
```

The pre-Q61 snapshots in `s3://jreese-net/neo4j-backups/` are in the PUBLIC site bucket; no new
objects are written there.

## Manual Trigger

```bash
aws lambda invoke \
  --function-name enceladus-neo4j-backup-gamma \
  --cli-binary-format raw-in-base64-out \
  --payload '{}' \
  /tmp/neo4j-backup-result.json \
  --region us-west-2 && cat /tmp/neo4j-backup-result.json
```

Pass `'{"dry_run": true}'` to probe AuraDB read access without writing anything (this is the
post-deploy canary in `_deploy.yml`).

## Restore Procedure (DynamoDB Re-Projection)

This is the primary restore path. It rebuilds the entire graph from DynamoDB:

```bash
NEO4J_SECRET_NAME=enceladus/neo4j/auradb-credentials \
python3 tools/backfill_graph.py --region us-west-2
```

Estimated time: 5-10 minutes for ~1,420 primary records.

Before running, optionally clear the existing graph:
```bash
# Connect to Neo4j and delete all nodes/relationships
python3 -c "
from neo4j import GraphDatabase
import boto3, json
sm = boto3.client('secretsmanager', region_name='us-west-2')
creds = json.loads(sm.get_secret_value(SecretId='enceladus/neo4j/auradb-credentials')['SecretString'])
driver = GraphDatabase.driver(creds['NEO4J_URI'], auth=(creds['NEO4J_USERNAME'], creds['NEO4J_PASSWORD']))
with driver.session() as s:
    result = s.run('MATCH (n) DETACH DELETE n')
    print(f'Deleted {result.consume().counters.nodes_deleted} nodes')
driver.close()
"
```

## Schedule

- EventBridge rule: `enceladus-neo4j-backup-daily` (or `-gamma` for gamma)
- Schedule: prod `cron(0 3 * * ? *)` (03:00 UTC); gamma `cron(20 3 * * ? *)` (staggered 20 minutes)
- Function: 2048 MB, 900 s, 2048 MB `/tmp` (the export spools compressed output to disk)

## Architecture

```
EventBridge (daily) --> Lambda --> Neo4j (keyset pages of 5000, one read tx each)
                                     |  gzip NDJSON via /tmp spool, S3 multipart
                                     v
              s3://enceladus-356364570033-us-west-2-an/neo4j-backups/<env>/YYYY/MM/DD/<ts>/
                                     |  manifest.json last, then latest.json
                                     v
              CloudWatch EnceladusBackup/Neo4jSnapshotSucceeded (Env) --> freshness alarm --> SNS
```

Restore:
```
DynamoDB (source of truth) --> backfill_graph.py --> Neo4j (MERGE upserts)
```
