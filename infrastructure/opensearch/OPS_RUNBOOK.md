# OpenSearch node — operations runbook (ENC-TSK-L45)

Companion to `10-opensearch-node.yaml` / `bootstrap-node.sh` (ENC-TSK-L39) and
`SECURITY_HARDENING.md` (ENC-TSK-L44). Covers DOC-77D6C714867E §14.5 AC-1/AC-2/AC-3.

## AC-1 — monitoring

Four alarms, all publishing to SNS topic `enceladus-opensearch-alerts-gamma`
(`OpenSearchAlarmTopic` — subscribe an email/Slack endpoint here; none is wired
by default):

| Alarm | Metric | Threshold | Source |
|---|---|---|---|
| `enceladus-opensearch-cpu-high` | `AWS/EC2 CPUUtilization` | >80%, 3×5min | native EC2 metric |
| `enceladus-opensearch-disk-high` | `Enceladus/OpenSearch disk_used_percent` | >80%, 3×5min | CloudWatch Agent (root volume `/`) |
| `enceladus-opensearch-jvm-heap-high` | `Enceladus/OpenSearch JVMHeapPercent` | >75%, 1×5min | `opensearch-jvm-heartbeat.sh` cron (polls `_nodes/stats/jvm`, `put-metric-data` every minute) |
| `enceladus-opensearch-node-down` | `AWS/EC2 StatusCheckFailed` | any failure, 3×1min | native EC2 metric — catches instance-level failure |
| `enceladus-opensearch-process-down` | `Enceladus/OpenSearch NodeUp` | <1 (missing data = breaching), 2×5min | heartbeat cron; catches OpenSearch-process-down while the instance itself is still up, and catches the cron/instance stopping entirely (no data points at all) |

**Synthetic breach test** (do this once after any node replacement to confirm
alarms actually fire — this task's AC-1 requirement):

```bash
# Fake a heap breach without touching the real JVM: publish one point directly
aws cloudwatch put-metric-data --region us-west-2 --namespace Enceladus/OpenSearch \
  --metric-data "MetricName=JVMHeapPercent,Value=99,Unit=Percent,Dimensions=[{Name=InstanceId,Value=<instance-id>}]"
aws cloudwatch describe-alarms --alarm-names enceladus-opensearch-jvm-heap-high-gamma --region us-west-2 \
  --query 'MetricAlarms[0].StateValue'
# Expect ALARM within one evaluation period (5 min), then it self-clears on the next real heartbeat point.
```

## AC-2 — durability / restore path

This node chose **rebuild-from-DDB**, not OpenSearch snapshot-to-S3 (either
satisfies AC-2; a self-hosted single-node snapshot repo needs its own S3
IAM role wiring and a `_snapshot` repo registration step for marginal benefit
over what already exists):

- Source of truth is DynamoDB (tracker + documents tables), not the OpenSearch
  index. The index is a derived, disposable artifact.
- Restore tool: `devops-opensearch-backfill-gamma` (ENC-TSK-L42) — paginated
  scan of both tables, bulk-indexed via the external-version idempotency
  contract. Safe to re-run; no duplicates.
- **Tested end-to-end**: the ENC-TSK-L44 deploy replaced the node (UserData
  change forces EC2 replacement; `DeleteOnTermination: true` wipes the index),
  and the backfill Lambda repopulated it from empty. See the ENC-TSK-L44
  handoff execution log (docstore) for the dry-run + live invoke evidence —
  this *is* the rebuild-from-DDB recovery drill, exercised for real, not just
  documented.
- **Recovery procedure** (node lost/corrupted for any reason):
  1. If the EC2 instance itself is gone/unhealthy: nothing to do but wait for
     or trigger the CFN stack to reconcile (UserData is unchanged so no
     automatic replacement — manually terminate the instance to force ASG-less
     CFN to notice on next stack update, or `aws ec2 terminate-instances` +
     re-run the node-stack deploy workflow).
  2. Once the node is healthy (cluster green, security roles applied — see
     SECURITY_HARDENING.md §AC-1 verification):
     ```bash
     aws lambda invoke --function-name devops-opensearch-backfill-gamma \
       --region us-west-2 --cli-binary-format raw-in-base64-out \
       --payload '{"dry_run": false}' /tmp/restore.json
     cat /tmp/restore.json   # expect errors: []
     ```
  3. Confirm `records_read` search returns results and doc count is in the
     expected ~3k order of magnitude (ISS-487 evidence).

### Failover drill (ENC-TSK-M13 / L46 AC-2)

Agent CLI sessions (`enceladus-agent-cli`) are DENIED `ssm:SendCommand` and
`ec2:StopInstances` by design (ENC-TSK-564) — do **not** try to stop the node
from a terminal session. The sanctioned executor is the
**OpenSearch Failover Drill (gamma)** workflow
(`.github/workflows/opensearch-failover-drill.yml`, `workflow_dispatch` from a
`v4/**` ref). It resolves the node by tag, SSM-stops the `opensearch` service
(process-level failover — no instance/EBS churn, so no post-drill backfill),
holds a configurable drill window (default 180s) during which the verifying
session asserts keyword fallback (Neo4j) + facet fallback (`/feed/corpus`) via
gamma search, then restarts the service and asserts recovery (`systemctl`
active + `:9200` answering). Runs as `BackendDeployRole`, which already holds
the needed `ssm:SendCommand`/`ssm:GetCommandInvocation`/`ec2:DescribeInstances`
grants — no IAM change required.

### CDC freshness (ENC-TSK-M13 / ENC-TSK-L84)

CDC is direct DynamoDB Streams → Lambda ESM (`SearchIndexTrackerStreamTrigger`
/ `SearchIndexDocumentsStreamTrigger` in `02-compute.yaml`; EventBridge Pipes
with a DDB Streams source are account-wide dead, ENC-ISS-497). Measured
delivery lag (CloudWatch `IteratorAge`, live gamma traffic): avg ~0.6s, max
~2.6s — freshness budget met with wide margin. **Gotcha:** gamma tables are a
fork snapshot fed by GDMP batch mirror; a mutation made through the *prod* MCP
(`mcp.jreese.net` → `devops-project-tracker`) will NOT appear in gamma
OpenSearch until the next mirror. Freshness probes must mutate the *gamma*
tables (gamma MCP / gamma APIs). Poisoned records are bounded by
`MaximumRetryAttempts`/`BisectBatchOnFunctionError`/`MaximumRecordAgeInSeconds`
and dead-letter to `devops-search-index-cdc-dlq-gamma` (14-day retention) —
alarm on DLQ depth if it ever goes nonzero.

## AC-3 — reindex, node replacement, cost guardrail

### Reindex (zero-downtime version bump)

Per ENC-TSK-L42/L40, `apply_records_index.py` supports a 3-step atomic swap:

```bash
python3 infrastructure/opensearch/apply_records_index.py --mode create-only --version <n+1>
aws lambda invoke --function-name devops-opensearch-backfill-gamma \
  --payload '{"dry_run": false, "target_index": "records_v<n+1>"}' /tmp/reindex.json
python3 infrastructure/opensearch/apply_records_index.py --mode swap --version <n+1>   # add --delete-old to remove records_v<n>
```

`records_read`/`records_write` repoint atomically; no read downtime; re-running
any step is idempotent.

### Node replacement

Any change to `bootstrap-node.sh` or `10-opensearch-node.yaml`'s `UserData`/AMI
forces EC2 instance replacement on the next CFN deploy. Because
`BlockDeviceMappings[].Ebs.DeleteOnTermination: true`, the index is **not**
preserved — always plan a post-deploy backfill (AC-2 procedure above) as part
of any change to those two files. `OpenSearchNodeRole`/`InstanceProfile`/
`SecurityGroup` have `DeletionPolicy: Retain` so IAM/networking survive
replacement untouched; only the instance (and its EBS volume) churns.

### Cost guardrail (locked, do not silently drift)

| Control | Value | Where enforced |
|---|---|---|
| Instance type | `t4g.small` only (`t4g.medium` allowed, never larger) | `InstanceType` param `AllowedValues` |
| Reserved capacity | 1-yr Compute Savings Plan / RI recommended (~$8/mo vs ~$13/mo on-demand) | operator action, not IaC — no RI CFN resource exists; purchase manually in Billing console if not already active |
| NAT | none — public subnet, `network.host: 0.0.0.0` reachable only via the security group | `SubnetId` param description; no `AWS::EC2::NatGateway` in this template |
| AZ | single-AZ (`SubnetId` is one subnet) | template has no multi-AZ construct |
| Replicas | 0 (`number_of_replicas: 0` in both the bootstrap-applied default template and `records-v1.json`) | `enceladus-default-replicas-zero` index template + `infrastructure/opensearch/index-templates/records-v1.json` |

Verify compliance after any change:

```bash
aws ec2 describe-instances --region us-west-2 \
  --filters "Name=tag:enceladus:component,Values=opensearch-node" "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].{Id:InstanceId,Type:InstanceType,AZ:Placement.AvailabilityZone,PublicIp:PublicIpAddress}' \
  --output table
```

Expected: exactly one running instance, `Type=t4g.small`, one AZ, a `PublicIp`
present (confirms no NAT — the node reaches the internet directly).

---

## Quick reference

| Resource | Gamma name |
|----------|------------|
| OpenSearch node stack | `enceladus-opensearch-node-gamma` |
| Alarm SNS topic | `enceladus-opensearch-alerts-gamma` |
| Backfill/reindex Lambda | `devops-opensearch-backfill-gamma` |
| Heartbeat cron (on-node) | `/etc/cron.d/opensearch-jvm-heartbeat` → `/usr/local/bin/opensearch-jvm-heartbeat.sh`, every 1 min |
| Custom metric namespace | `Enceladus/OpenSearch` (`JVMHeapPercent`, `NodeUp`, `disk_used_percent`) |
