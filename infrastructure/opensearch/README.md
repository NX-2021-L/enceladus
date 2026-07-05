# ENC-TSK-L40 Records Index (OpenSearch)

Index schema, mappings, and alias contract for the `records_v{n}` index
backing Search2.0 (ENC-FTR-127 / ENC-TSK-B67). Applied against the gamma
single-node OpenSearch cluster provisioned by ENC-TSK-L39
(`infrastructure/cloudformation/10-opensearch-node.yaml`).

## Naming contract

- The physical index is always **versioned**: `records_v1`, `records_v2`, ...
  Never create a bare `records` index or alias — OpenSearch forbids an alias
  sharing a name with a physical index, which would block the exact
  zero-downtime reindex this scheme exists for.
- `records_read` and `records_write` are aliases, always pointing at the
  current physical index. `records_write` is the alias's `is_write_index`.
- **L41** (indexer, not yet built) must write exclusively via `records_write`.
- **L43** (query layer, not yet built) must read exclusively via `records_read`.
- To reindex (mapping change, etc.): create `records_v{n+1}`, backfill, then
  atomically repoint both aliases via `_aliases` (as `apply_records_index.py`
  does for the initial version) and delete the old physical index once
  traffic has drained.

## Schema (`index-templates/records-v1.json`)

Composable index template on pattern `records_v*`, priority 200 (above the
bootstrap-time `enceladus-default-replicas-zero` template on `enceladus-*`
from `bootstrap-node.sh`, which this deliberately does not depend on).

- Keyword facets: `project_id`, `record_type`, `status`, `priority`, `tags`.
- Text fields (`title`, `description`, `body`): `search_as_you_type` mapping
  type gives the `._2gram` / `._3gram` / `._index_prefix` subfields needed for
  prefix/autocomplete `bool_prefix` queries, analyzed with a custom
  `enceladus_text_analyzer` (standard tokenizer + lowercase + asciifolding)
  for accent-insensitive matching.
- Dates: `created_at`, `updated_at`.
- `version_seq` (long): **interim contract is `updated_at` epoch-millis**,
  written by whatever indexes into `records_write`. Cut over to a real
  monotonic sequence once ENC-TSK-L27 ships an authoritative version source;
  the field name does not need to change, only what populates it.
- 1 primary shard, 0 replicas (single-node cluster, matches L39 sizing).

## Applying (VPC/SSM-only reachable — no GitHub Actions path)

The node has no public ingress (security group only allows :9200 from the
VPC CIDR); there is no existing "apply to a private EC2 instance via SSM"
GitHub Actions pattern in this repo; the same precedent as
`tools/neo4j-migrations/` (`README.md` there) applies: ship the schema as a
versioned artifact + idempotent apply script, run manually by whoever has
AWS + SSM access, with results captured as tracker evidence rather than
piped through CI.

Run directly on the instance (session via `aws ssm start-session`, or an
`aws ssm send-command` shell-script document) using the AWS profile
sanctioned for gamma OpenSearch node access:

```bash
# From an operator session with SSM access to the gamma OpenSearch instance:
ADMIN_PASSWORD="$(tr -d '\n' < /root/.opensearch-admin-password)" \
  python3 infrastructure/opensearch/apply_records_index.py --version 1

ADMIN_PASSWORD="$(tr -d '\n' < /root/.opensearch-admin-password)" \
  python3 infrastructure/opensearch/smoke_test_records_index.py
```

After running, capture the smoke test's JSON output (exact-term hit count,
prefix/autocomplete hit count, fuzzy hit count, faceted aggregation buckets)
and attach it to ENC-TSK-L40's `live_validation_evidence`.

## Governance

This directory is not under a registered component in the component
registry (ENC-FTR-041); it pairs with `comp-search` once L41/L43 (indexer /
query layer Lambdas) are scoped, similar to how `tools/neo4j-migrations/`
pairs with `comp-graph-sync`.
