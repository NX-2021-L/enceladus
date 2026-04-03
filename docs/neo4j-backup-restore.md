# Neo4j AuraDB Backup & Restore Procedures

## Overview

The Enceladus graph index (Neo4j AuraDB) is a **read-only derived projection** of
DynamoDB tracker data. DynamoDB is the source of truth. The backup strategy reflects this:

- **Daily snapshot**: Lambda exports current graph state (nodes + relationships) as JSON to S3
- **Restore**: Re-project from DynamoDB using `tools/backfill_graph.py` (~5-10 min for ~1,420 records)
- **S3 snapshots**: Audit/reference only, not the primary restore mechanism

## List Available Backups

```bash
aws s3 ls s3://jreese-net/neo4j-backups/ --recursive
```

## Manual Trigger

```bash
aws lambda invoke \
  --function-name enceladus-neo4j-backup-gamma \
  --payload '{}' \
  /tmp/neo4j-backup-result.json \
  --region us-west-2 && cat /tmp/neo4j-backup-result.json
```

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
- Schedule: `cron(0 3 * * ? *)` (daily at 03:00 UTC)

## Architecture

```
EventBridge (daily) --> Lambda --> Neo4j (bolt query) --> JSON --> S3
                                                                  |
                                                    s3://jreese-net/neo4j-backups/YYYY/MM/DD/
```

Restore:
```
DynamoDB (source of truth) --> backfill_graph.py --> Neo4j (MERGE upserts)
```
