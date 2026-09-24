# Rhythm Observability Runbook

Three read-only tools that snapshot the rhythm-cycle system, roll the raw
captures into aggregates, and render a static dashboard. They chain in order:

```
rhythm_harvest.py  ->  rhythm_analyze.py  ->  rhythm_dashboard.py
```

All output lands under `/Users/jreese/rhythm-analysis/`.

> READ-ONLY. Every tool performs only Get/List/Describe-class API calls. No
> mutations, no infra change, nothing is written to AWS. Safe to run any time.
>
> Currently targets the **gamma** account/environment.

## What each tool does

- **`rhythm_harvest.py`** — Pulls the raw state from AWS and writes it to disk:
  the tier beat artifacts and per-tenant stanzas from S3, CloudWatch metrics
  (`AWS/Lambda` + `Enceladus/Rhythm` custom metrics), DynamoDB rhythm tables,
  the AppConfig rhythm-tenants config, and the resolved IAM role policy. Each
  domain lands in its own subdirectory (`s3/`, `cloudwatch/`, `ddb/`, `config/`).

- **`rhythm_analyze.py`** — Reads the harvested bundle (no AWS calls) and
  distills it into a single flattened `dashboard_data.json` — per-tier beat
  health, per-tenant executed-vs-silent status, invocation/error counts, cost
  estimates, and the Lyapunov / backlog-convergence series — the feed the
  dashboard consumes. (The `aggregates/` rollups it reads are produced upstream
  by `rhythm_harvest.py`.)

- **`rhythm_dashboard.py`** — Reads `dashboard_data.json` (+ `INDEX.json`) and
  renders the self-contained `rhythm_dashboard.html` for viewing in a browser.

## One-command refresh

Run the full chain from the repo root (all three default to the gamma
env-prefix and the `/Users/jreese/rhythm-analysis` bundle):

```bash
python3 tools/rhythm_harvest.py && \
python3 tools/rhythm_analyze.py && \
python3 tools/rhythm_dashboard.py
```

Then open the dashboard:

```bash
open /Users/jreese/rhythm-analysis/rhythm_dashboard.html
```

`harvest` re-fetches from AWS; `analyze` and `dashboard` are pure and can be
re-run against an existing bundle without touching AWS.

## Output bundle layout

```
/Users/jreese/rhythm-analysis/
├── s3/                    raw tier beat artifacts + per-tenant stanzas
├── cloudwatch/            AWS/Lambda + Enceladus/Rhythm metric series
├── ddb/                   DynamoDB rhythm table snapshots
├── config/                AppConfig config + IAM role snapshot
├── aggregates/            flattened per-tier/tenant rollups (from rhythm_harvest.py)
├── INDEX.json             harvest manifest + counts
├── dashboard_data.json    distilled feed for the dashboard (from rhythm_analyze.py)
└── rhythm_dashboard.html  rendered static dashboard
```

## Required AWS access

Read-only credentials for the **gamma** account (e.g. an exported profile /
SSO session before running). Needed permissions:

- **S3** — `GetObject`, `ListBucket` on the rhythm-cycle bucket
- **CloudWatch** — `GetMetricStatistics`, `ListMetrics`
- **DynamoDB** — `Scan` / `Query` / `DescribeTable` on the rhythm tables
- **AppConfig** — read the rhythm-tenants application/config profile
- **IAM** — `GetRole`, `GetRolePolicy` on the rhythm role

No write, delete, or update permissions are required or used.

## S3 artifact retention (gamma)

Beat timestamped artifacts under `gamma/rhythm-cycle/{tier}/` expire after **7 days**
(equalized across all tiers by `tools/apply_rhythm_artifact_lifecycle.py`, applied
during the gamma compute-stack deploy). Prior skew (~1d for sense/decide vs ~7d for
others) truncated harvester history for the tiers ENC-ISS-553 needs most.
