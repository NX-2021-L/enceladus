# write-bench

Write-latency benchmark harness for the Enceladus governed MCP write path
(ENC-TSK-S26-0C; BRD DOC-E32D0ED08473 sections 7.3 and 7.5). Python 3.11+, stdlib only
(boto3 only for the `in_region_lambda_client` arm; numpy is not used).

## The one command

```
python3 tools/write-bench/bench.py --env gamma \
    --arm elr_per_process|long_lived_session|in_region_lambda_client|all \
    --series warm|cold --project <bench-sink-project-id> --out results/<run_id>.json
```

Defaults: warm = 10 warmup + `--n 300` measured per operation per arm at `--pace 5` s;
cold = `--n 40`, no warmup. Operations (each one `tools/call`): `tracker_create`,
`tracker_set`, `documents_put_2kb`, `documents_put_60kb`, `execute_10_independent`,
`execute_10_chained`, `execute_20_independent` (`--ops a,b` selects a subset). Operations are
interleaved round-robin within each arm so time-of-day drift hits all of them equally.

1-minute smoke (21 calls, about 25 s plus session setup):

```
BENCH_BEARER_TOKEN=... python3 tools/write-bench/bench.py --env gamma --arm long_lived_session \
    --series warm --project <bench-sink> --n 3 --warmup 0 --pace 1 --out results/smoke.json
```

`--governance-hash <64-hex>` (or env `BENCH_GOVERNANCE_HASH`; CLI wins) skips the `system.connection_health` fetch and
uses the given hash; use it when gamma reads report the prod hash but writes validate the gamma hash (ENC-ISS-893,
writes fail GOVERNANCE_STALE). Results meta records `governance_hash_source` (`override` | `connection_health`).

`--dry-run` prints the plan and payload sizes with no network and no token.

## Prod refusal (hard allowlist)

The bench exits **2** unless `--env gamma` **and** the MCP URL is `https`, port 443, no userinfo, with
host exactly `mcp-gamma.jreese.net` (`--mcp-url` may change the path only in practice; any other host
is refused). The one-shot child process and the Lambda handler re-check the host. Lambda and
cold-bump function names must end in `-gamma`. There is no flag to override this; a prod run needs a
code change and io approval.

## Token

`BENCH_BEARER_TOKEN` (Cognito id_token for the gamma MCP) from the environment, or `--token-file`.
It is sent only as `Authorization: Bearer ...` (and in the Lambda invoke payload for the Lambda arm);
it is never printed, logged or written to results. Obtain it with the `enc-cognito-auth` flow.

## What gets measured

Before each run the bench calls `search` action `system.connection_health` to read the real
`governance_hash` and passes it on every mutation step. Per call it records `t_client_start`,
`t_client_end`, `client_total_ms`, `client_session_reused`, `client_session_init_ms`,
`client_tls_new`, `client_serialize_ms`, `response_bytes`, `correlation_id` (uuid4, sent as
`X-Correlation-Id`), `http_status`, `ok`, plus the headers `X-Enc-T-Client-Start`,
`X-Enc-Client-Session-Reused`, `X-Enc-Client-Session-Init-Ms`, `X-Enc-Client-Tls-New`,
`X-Enc-Client-Serialize-Ms`, `X-Enc-Surface: write-bench`.

Arms: `elr_per_process` spawns a fresh Python per call (new session, new TLS per HTTP request, like the
ELR runner; `client_total_ms` includes interpreter start); `long_lived_session` keeps one initialized
session on a kept-alive `http.client.HTTPSConnection`; `in_region_lambda_client` invokes
`devops-write-bench-client-gamma` (handler `backend/lambda/write_bench_client`; gamma-only CFN resource in
`02-compute.yaml`, on-demand, no idle cost) and uses the timings the Lambda measured itself
(`invoke_total_ms` is also kept). Needs `AWS_PROFILE` (or `--aws-profile`) and boto3.

## Record pool

`tracker_set` and the multi-step `execute` operations need existing records. On first run the bench
creates `--pool-size` (default 10) `[BENCH]` tasks in `--project` and stores their ids in
`results/pool-<project>.json` (next to `--out`); later runs reuse them. `tracker_create` samples and
`documents_put` samples create more scratch records/documents. **Bench records are never deleted.**
Use a dedicated sink project so they stay out of the enceladus ontology (BRD open decision D1).
Independent 20-step executes wrap around the pool (each record set twice with the same idempotent
value); chained executes all hit `pool[0]` with values derived from the previous step index.

## Cold series requirements

Cold samples are preceded by `aws lambda update-function-configuration` setting
`BENCH_COLD_NONCE=<uuid>` (existing env variables are preserved) on the gamma write-path functions
(`--cold-functions`, default `enceladus-mcp-streaming-gateway-gamma` (the function behind
`mcp-gamma.jreese.net`), `devops-tracker-mutation-api-gamma`, `devops-document-api-gamma`), then polling until `LastUpdateStatus` is `Successful`. This needs
Lambda configuration write access, so **cold runs need the `product-lead` profile**:
`--aws-profile product-lead`. Agent profiles (`enceladus-agent`) cannot do it. The bump mutates gamma
function configuration (not CFN-declared); expect drift on those env maps until the next compute deploy.

## Statistics and comparison

`stats.py`: per cell (operation x arm x series) n, p50, p90, p95, p99 (flagged `information_only`),
95% bootstrap CIs (10,000 resamples, seeded `random.Random`, percentile method) for p50 and p95; p95
is gating only when n >= 300. Warm and cold are never pooled.

```
python3 tools/write-bench/compare.py --pre pre1.json [pre2.json pre3.json] \
    --post post1.json [...] --out compare.json --md compare.md
```

Delta (post - pre) per cell with a bootstrap CI (cells paired by key, samples not paired); an
improvement requires the CI to exclude zero. Up to three runs per side are pooled within a cell after a
between-run check: a run is `divergent` if its p50 lies outside the p50 CI of every other run in that
cell. This is the implemented reading of BRD 7.5(5) ("if one run's p50 differs from the other two by more
than its own interval, investigate before pooling"): the "outside every other run" form isolates a single
outlier instead of also flagging the runs that agree with each other. Investigate divergent cells before
trusting the pooled number.

## Tests

`python3 -m unittest discover -s tools/write-bench/tests -v` (no network).
