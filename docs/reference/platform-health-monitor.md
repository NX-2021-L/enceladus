# B6-R2 platform health monitor

**DVP-TSK-665 / DVP-PLN-001.** Nine scheduled checks over the governed
warehouse, the analytics host, and the declared dependency surface. A breach
files a governed issue record; every run writes the health status surface.

Function `devops-platform-health`, `cron(0 7 * * ? *)` — one hour after
`GovernanceMartSchedule`'s 06:00 UTC refresh, because a freshness check that
runs *before* the job it observes measures yesterday's write every single day.

## The checks

| # | id | asks | governing document |
|---|---|---|---|
| 1 | `check_1_freshness` | is every registered table younger than its declared SLA, catalogued, and non-empty? | DOC-F56858AFE749 obl. 4 |
| 2 | `check_2_crawler` | does a Glue crawler exist **in any scanned region**, and does any target a governed prefix? | DOC-5E35E14DAD05 |
| 3 | `check_3_namespace_isolation` | did every table in a governed namespace arrive via a registered export job? | DOC-F56858AFE749 obl. 3 |
| 4 | `check_4_storage_format` | is every governed table's **serde** Parquet? | DOC-F56858AFE749 obl. 2 |
| 5 | `check_5_full_refresh` | is file count consistent with full-refresh overwrite? | DOC-1E1EC5B7CE02 |
| 6 | `check_6_container_health` | were Trino or Superset OOM-killed, per the **kernel log**? | DVP-ISS-095 |
| 7 | `check_7_adhoc_quota` | is `hive.adhoc` inside its declared quota? | DOC-F56858AFE749 ad-hoc §|
| 8 | `check_8_cpu_credit` | is the burstable host **billing** for surplus credits? | DVP-TSK-635 |
| 9 | `check_9_dependency_drift` | does live IAM still match the **declared** dependency surface? | DOC-132286FF074F, DVP-TSK-641 |

Checks 1–8 are the BRD B6-R2 set. Check 9 was added because DVP-TSK-641
recorded this task as OBJ-8's enforcement point and noted that 6/7/8 did not
cover it.

## Four things that are easy to get backwards

**RestartCount is not the instrument.** It reads 0 on this host and read 0
through seven `CONSTRAINT_MEMCG` kills of `trino-server`, because every kill
targeted the JVM *inside* the container rather than its PID 1. And `dmesg` alone
is not enough either: the ring buffer clears on reboot, `journalctl -k` pins the
current boot, and `--since` does not lift that filter. Check 6 reads both
sources and always reports `boot_time`, so an all-clear is qualified by *since
when*.

**The crawler sweep must be multi-region.** The ten crawlers in us-west-2 were
deleted on 2026-08-07; a single-region sweep the next morning reports a clean
estate while `daily-data-crawler` runs in us-west-1. A check that only looks
where crawlers were last deleted can only confirm its own prior.

**Credit exhaustion bills, it does not throttle.** `CpuCredits=unlimited` means
the t3.large failure mode is a cost event. T1 (`CPUSurplusCreditsCharged`) is
the breach; T2 (balance ≤ 115) is only the leading indicator.

**Growth is not a violation.** A table that genuinely grew shows file count
steady and bytes up. Only file count climbing while bytes stand still is
snapshot-per-mutation partitioning.

## The surface

Three layers, each doing something the others cannot:

- `s3://devops-agentcli-compute/platform-health/latest.json` — current state,
  one GetObject away.
- `platform-health/history/<observed_at>.json` — append-only snapshots. The
  **system of record** (T1); single writer is the scheduled Lambda.
- `hive.devops.fact_platform_health_daily` and
  `hive.devops.fact_table_freshness_daily` — the **warehouse projection** (T2),
  full-refreshed from the history each run through the B2-R2 shared library.

Both tables are at daily grain, which is DVP-TSK-666's whole point: **if this
Lambda dies, no issue is filed — because the thing that files issues is what
died.** But the daily series stops advancing, and a chart with a gap at today's
date is visibly wrong. The projection's failure is legible *without*
monitoring, which is the only kind of check that survives its own outage.

## Severity, and why warnings do not file issues

`ok` · `warning` · `breach` · `error`. Only `breach` files a governed issue
(`ISSUE_FILING_SEVERITIES`). A monitor that filed a P1 for every known legacy
condition on every daily run would reproduce the ENC-ISS-369..379 storm by a
different route.

`error` is a **third state**, distinct from both healthy and breaching: a check
that could not run is never collapsed into "nothing found". Nine independent
observations of a live estate will eventually have one fail on a transient AWS
error, and a monitor that reports nothing because its seventh check timed out
has converted a partial signal into no signal.

Finding identity is `(check, subject, kind)` and deliberately **excludes the
measurement**, so a table 27h stale on Monday and 51h stale on Tuesday bumps one
record rather than opening two.

## What it cannot do

The role is almost entirely read. It cannot delete a crawler it flags, restart a
container it finds OOM-killed, or edit the IAM policy whose drift it detects.
Those are decisions; this function is an instrument. Its only writes are its own
health surface.

## Thresholds

All in `health_contract.py`, each naming the document or task record it came
from. Change a threshold there — a reviewable diff against a declaration — never
inside a predicate. If a declared number is wrong (the ad-hoc quota is
explicitly agent-adopted and awaiting io's review), amend the declaration rather
than muting the check.
