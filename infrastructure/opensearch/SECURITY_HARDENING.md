# OpenSearch node — security, secrets & network hardening (ENC-TSK-L44)

Companion to `10-opensearch-node.yaml` / `bootstrap-node.sh` (ENC-TSK-L39). Covers
DOC-77D6C714867E §14.5 AC-1/AC-2/AC-3.

## AC-1 — fine-grained roles

Bootstrap provisions three security-plugin identities (idempotent, re-applied on
every fresh bootstrap/instance replacement — no-op if already present):

| User | Role | Permissions |
| --- | --- | --- |
| `admin` | reserved superuser | full cluster access; used only for bootstrap + operator scripts (`apply_records_index.py`) |
| `indexer` | `indexer_role` | write-only on `records_write` / `records_v*` (bulk index, create, mapping) |
| `query` | `query_role` | read-only on `records_read` / `records_v*` |

`devops-opensearch-indexer` (ENC-TSK-L41) now authenticates as `indexer`, not
`admin` — see `OPENSEARCH_USERNAME` / `OpenSearchIndexerUsername` in
`02-compute.yaml`. A future `devops-opensearch-query-api` (or ENC-TSK-L27+
query-side Lambda) should authenticate as `query`.

## AC-2 — credentials & TLS

- All three passwords are generated with `openssl rand -base64 24` on the instance
  and synced to Secrets Manager as `enceladus/opensearch/gamma-{admin,indexer,query}`,
  each `{"username": "...", "password": "..."}`. Nothing is stored in code.
- The node role (`OpenSearchNodeRole`) holds a scoped policy
  (`secretsmanager:CreateSecret/PutSecretValue/DescribeSecret/GetSecretValue` on
  `enceladus/opensearch/*` only) to sync these on boot.
- TLS: the demo installer (`opensearch-tar-install.sh`) generates self-signed
  node/admin/root certs on first bootstrap; enforced node-wide by the security
  plugin default (no `plugins.security.disabled`). Clients skip hostname/cert
  verification (`ssl.verify_mode = CERT_NONE`) since certs are self-signed and
  the boundary is VPC-private reachability + credential auth, not PKI trust.
- **Rotation path**: passwords are only (re)generated when the per-user password
  file under `/root/.opensearch-*-password` is absent. Marker-gated bootstrap
  means a normal reboot is a no-op. To rotate: `rm` the target password file(s)
  and the `/var/lib/opensearch/.bootstrap-complete` marker is *not* needed (the
  security-role block runs unconditionally after cluster health, independent of
  MARKER) — deleting just the password file and re-running
  `bootstrap-node.sh` (or via SSM Session Manager) regenerates that credential,
  re-applies it via the Security REST API, and re-syncs Secrets Manager.
  Full-node replacement (any UserData-triggering CFN change) also rotates all
  three credentials automatically.

## AC-3 — network boundary

- Primary access-control boundary is the security-plugin credential + TLS check
  (AC-1/AC-2), per design — the node's Lambda clients are not fixed-IP.
- `OpenSearchNodeSecurityGroup` allows TCP :9200 from `VpcCidr` (Lambda ENIs) and
  a single `AdminCidr` parameter (operator/direct access) only. All other ports
  are denied from 0.0.0.0/0 (no other ingress rules exist). Audit logging is on
  (`plugins.security.audit.type: internal_opensearch`, both REST and transport
  categories enabled) — audit events land in the `security-auditlog-*` index,
  queryable via the `admin` user.

### Known deviation from DOC-77D6C714867E §14.5

The design doc's AC-3 text assumes indexer/query Lambdas are **non-VPC** (reaching
the node over the public internet, matching graph_sync/graph_query_api), and
therefore expects the security group to open :9200 broadly rather than to
`VpcCidr`. **ENC-TSK-L41 shipped the indexer Lambda VPC-attached** (private IP
`172.31.28.54`, `OpenSearchIndexerSecurityGroup` + `OpenSearchIndexerSubnetIds` in
`02-compute.yaml`), which contradicts that assumption. This task (L44) hardens the
node under the **as-shipped VPC-attached topology** rather than broadening the
security group to `0.0.0.0/0` on :9200, since doing so would publicly expose a
single self-hosted node with self-signed TLS certs with no corresponding
functional need today. If a future task deliberately migrates the indexer/query
Lambdas to non-VPC (to also drop the NAT-adjacent VPC config and match the
graph_sync pattern for real), the security group's `VpcCidr` ingress rule should
be revisited at that time, not before.

## Operational note — this task replaces the running node

Any change to `bootstrap-node.sh` or `10-opensearch-node.yaml` forces EC2 instance
replacement (`UserData`/AMI changes are not in-place-updatable), and
`BlockDeviceMappings[].Ebs.DeleteOnTermination: true` means the existing index is
**not** preserved across that replacement. Re-populate via the ENC-TSK-L42
full-corpus backfill Lambda (`devops-opensearch-backfill-gamma`) immediately after
this stack's `apply` job completes.
