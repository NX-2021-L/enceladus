# Write-path passive-reading and counter-metric query pack

ENC-TSK-S26-0D, BRD DOC-E32D0ED08473 section 7.4 and objective O6. Reads the `[WRITE-AUDIT] {json}` lines
(contract in section 7.2) from CloudWatch Logs. Logs Insights scans are the only cost
(agents.md cost rule-block v1): the runner prints and records the `bytesScanned` total the API returns.

## Verified log groups (describe-log-groups, 2026-11-04)

prod: `/aws/lambda/enceladus-mcp-code`, `devops-tracker-mutation-api`, `devops-document-api`,
`enceladus-checkout-service` (not `devops-checkout-service`), `devops-graph-sync`, `devops-feed-publisher`,
`devops-appsync-feed-publisher`. gamma: the same with a `-gamma` suffix, except `enceladus-mcp-code-gamma`
does not exist yet (the runner warns and skips missing groups; add one with `--log-group`).

## Reading queries (section 7.4, by tool and surface)

| file | reading |
|---|---|
| `01_server_latency_by_tool_surface.query` | n, p50, p90, p95, max of `server_total_ms`, cold n, cold share |
| `02_client_latency_by_tool_surface.query` | same over `client_total_ms` (owned clients only) |
| `03_stage_p50_p95_by_tool_surface.query` | p50 and p95 of every `t_*_ms` stage plus `init_ms` |
| `04_governed_lag_by_tool.query` | `governed_lag_ms` p50, p95, max per tool and consumer |
| `07_cold_by_session.query` | cold n and cold fraction per `session_id` (the runner builds the distribution) |
| `05_extract_audit_lines.query`, `06_extract_report_init.query` | raw extracts feeding the Python merge |

Fields are pulled with a regex per key (`"key": value`), so they work whether the JSON is flat or grouped
(identity, server_side, ...) as long as key names are unique.

## The REPORT join (two queries plus a Python merge)

Logs Insights has no join. `06_extract_report_init.query` returns `request_id` and `init_duration_ms` from Lambda
`REPORT` lines that have an `Init Duration`; `05_extract_audit_lines.query` returns the audit lines. `run_queries.py`
merges them on `request_id`: an audit line with its own `init_ms` keeps it, otherwise `init_ms` is filled from the
REPORT and the line counts as cold. Both extracts are capped at 10,000 rows by Logs Insights, so the runner queries
day by day and halves any window that hits the cap (the discarded scan is included in the printed bytes).

## Governance counter-metrics (each must be 0)

| metric | Insights file | definition |
|---|---|---|
| stale_hash_acceptances | `cm1_...query` | `governance_hash_verified = false` and the write did not report `success = false` (the contract has no outcome key, so lines without `success` are treated as accepted) |
| records_without_audit_item | `cm2_audit_coverage_inputs.query` (inputs only) | write `correlation_id` never on a consumer line; computed by the Python merge. Excluded: `success=false`, `dry_run`, `idempotency_hit`, `ddb_ops=0`, and writes newer than `--grace-min` (default 15) |
| idempotent_replay_receipt_mismatch | `cm3_...query` | same `idempotency_key`, more than one `receipt_hash`. Reported as `n/a` (not computable until W2.4 emits `receipt_hash`) when no line carries it |
| dry_run_writes | `cm4_...query` | `dry_run = true` and `ddb_ops > 0` |
| unrecovered_consumer_failures | `cm5_...query` | consumer line with `attempt >= 3` and no `t_projection_done`. The runner refines this (a later line for the same correlation_id and consumer with `t_projection_done` is a recovery, reported as `literal_attempt_ge_3_without_done` vs `unrecovered_lines`) and adds the on-failure queue depth read with SQS `get-queue-attributes` (visible + in flight + delayed) over the gamma/prod DLQs, overridable with `--dlq-queue` |
| edges_skipped_missing_target | `cm6_...query` | sum of `edges_skipped_missing_target` on consumer lines (graph_sync edge order guard, ENC-TSK-S46-0D): edges not created because the target node was absent and could not be placed as a placeholder. Steady state 0; the runner also reports `placeholder_targets` (sum of `edges_placeholder_targets`, placeholders the guard materialized), which is informational, not a violation |

The `.query` counter files return a single `violations` count and can be pasted into the console; the runner
computes the same counts from the extracts without extra scans (`--insights-queries` also runs the aggregate
files and attaches their rows, at the cost of extra scans).

## Runner

```
cd tools/write-bench/queries
python3 run_queries.py --env gamma --days 7 --out-dir ./readings
python3 run_queries.py --env prod  --days 7 --out-dir ./readings
python3 run_queries.py --fixture fixtures/synthetic_audit_lines.jsonl --out-dir ./readings   # no AWS
python3 run_queries.py --env gamma --days 7 --insights-queries                               # also the aggregate .query files
```

Needs boto3 and credentials allowed to run logs `StartQuery`/`GetQueryResults`/`DescribeLogGroups` and
`sqs:GetQueueAttributes` (default profile, or `--profile`). Output: `write-path-reading-<env>-<ts>.json`
and `.md` (stage budget table in the Appendix A shape: rows = stage, columns = p50/p95 by tool; then
latency by tool and surface, governed lag, per-session cold-fraction distribution, counter-metrics).
Percentiles in the runner are exact (linear interpolation); Insights `pct()` is approximate, so expect small differences.

## Fixture and tests

```
python3 make_fixture.py                       # regenerate fixtures/synthetic_audit_lines.jsonl (seeded)
python3 -m unittest discover -s tests -v
```

The fixture plants one violation of each counter-metric (write indexes 20, 30, 40, 50, 61) and decoys the pack
must not count (rejected stale hash, idempotent-hit write, same-hash replay, zero-op dry run, consumer recovery
at attempt 4, writes inside the grace window).
