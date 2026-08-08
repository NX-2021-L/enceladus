"""Declared expectations for the B6-R2 platform health monitor.

DVP-TSK-665 / DVP-PLN-001. Everything the monitor compares live state *against*
lives here, as committed values. Nothing in this module reads AWS; nothing in
the check modules hard-codes a threshold. That split is the point: a threshold
change is a reviewable diff against a declaration, not an edit buried in a
predicate.

The declarations are sourced, not invented. Each block names the governed
document or task record it was taken from, so a reader can check the number
rather than trust it.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, Tuple

# ---------------------------------------------------------------------------
# Identity of the estate under observation
# ---------------------------------------------------------------------------

#: The single analytics host. DVP-TSK-635 / DOC-132286FF074F section 1.
ANALYTICS_INSTANCE_ID = "i-0f3a4d5aa1c11dd86"

#: Home region for the warehouse, the host, and the Glue catalog that fronts it.
PRIMARY_REGION = "us-west-2"

#: Regions the CRAWLER sweep (check 2) must cover.
#:
#: This tuple is load-bearing and was paid for. On 2026-08-07 root deleted the
#: ten crawlers in us-west-2, and a single-region sweep would have reported a
#: clean estate -- while `daily-data-crawler` (database jds_scraper_db, target
#: s3://jds-scraper-output/structured/, cron(0 17 * * ? *)) was still live in
#: us-west-1 and had run that same day. A crawler check that only looks where
#: crawlers were last deleted is a check that can only ever confirm its own
#: prior. Add regions here; never narrow this to one.
CRAWLER_SCAN_REGIONS: Tuple[str, ...] = ("us-west-2", "us-west-1")

# ---------------------------------------------------------------------------
# The governed warehouse (checks 1, 3, 4, 5)
# ---------------------------------------------------------------------------

#: Bucket holding the governed T2 warehouse for project `devops`, and the
#: registration-record sibling tree the B2-R2 library writes.
WAREHOUSE_BUCKET = "devops-agentcli-compute"

#: Glue databases that are GOVERNED namespaces -- a table appearing in one of
#: these is subject to checks 3 and 4. Maps database -> the project name whose
#: registration records govern it.
#:
#: `adhoc` is deliberately INCLUDED. It is quarantine, not a governed
#: projection, so every table in it is expected to be unregistered; check 3
#: classifies it accordingly rather than pretending it is exempt from
#: observation (DOC-F56858AFE749, ad-hoc companion section).
GOVERNED_DATABASES: Dict[str, Dict[str, Any]] = {
    "devops": {
        "project": "devops",
        "bucket": WAREHOUSE_BUCKET,
        "tier": "warehouse",
    },
    "finance": {
        "project": "finance",
        "bucket": "finance-356364570033-us-west-2",
        "tier": "warehouse",
    },
    "adhoc": {
        "project": "adhoc",
        "bucket": WAREHOUSE_BUCKET,
        "tier": "quarantine",
    },
}

#: Default freshness SLA, in hours, for a registered table.
#:
#: 26h = the 24h cadence of the daily 06:00 UTC full refresh
#: (GovernanceMartSchedule) plus a 2h grace for a slow or retried run. A table
#: that has not been rewritten in 26 hours has missed a scheduled refresh, which
#: is the DVP-ISS-087 condition -- five months of stale data that still returned
#: rows and still looked correct.
DEFAULT_FRESHNESS_SLA_HOURS = 26.0

#: Per-table SLA overrides, in hours. Key is the Trino identifier.
FRESHNESS_SLA_OVERRIDES: Dict[str, float] = {}

#: Declared sharding constant per table: the number of objects a conformant
#: full-refresh table may hold. The B2-R2 library writes ONE object at a
#: constant key (`data.parquet`), so 1 is correct for every table it wrote;
#: a table that legitimately needs sharding declares it here rather than
#: having the check quietly widened.
DEFAULT_SHARDING_CONSTANT = 1
SHARDING_CONSTANT_OVERRIDES: Dict[str, int] = {}

#: Storage format every governed T2 table must declare (check 4).
REQUIRED_SERDE = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
REQUIRED_INPUT_FORMAT = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
REQUIRED_CLASSIFICATION = "parquet"

#: Tables that predate the B2-R2 shared registration library and therefore carry
#: no registration record, recorded WITH the date the baseline was taken.
#:
#: This is an observation baseline, not an exemption. Check 3 still reports every
#: one of these; membership here only downgrades the finding from `critical`
#: (a NEW unregistered table appeared -- the isolation-breach signal) to
#: `warning` (a known legacy gap). A table not on this list appearing
#: unregistered in a governed namespace is the event check 3 exists to catch.
#:
#: Baseline taken 2026-08-08 by ENC-SES-0C2 from
#: `aws glue get-tables --database-name finance`: 18 tables, all Parquet, all
#: under s3://finance-356364570033-us-west-2/warehouse/finance/, and
#: `aws s3 ls s3://finance-356364570033-us-west-2/warehouse-registrations/`
#: returned empty -- finance registers its Glue tables from its own export code
#: path (DOC-63BA1B4812C7) but predates the sidecar registration record.
LEGACY_UNREGISTERED_BASELINE: Dict[str, FrozenSet[str]] = {
    "finance": frozenset(
        {
            "accounts",
            "cash_balances",
            "cash_flow_ledger",
            "cash_forecast",
            "compensation_events",
            "credit_balances",
            "credit_scores",
            "market_prices",
            "net_worth_snapshots",
            "portfolio_holdings",
            "portfolio_orders",
            "property",
            "property_valuations",
            "recurring_charges",
            "scheduled_flows",
            "statement_lines",
            "statements",
            "vesting_schedule",
        }
    ),
}
LEGACY_BASELINE_TAKEN_AT = "2026-08-08T02:05:00Z"

# ---------------------------------------------------------------------------
# The ad-hoc quarantine quota (check 7)
# ---------------------------------------------------------------------------

#: DOC-F56858AFE749, ad-hoc companion section: "90 days retention, 50 GB / 5,000
#: objects quota". Recorded there as AGENT-ADOPTED, AWAITING IO'S REVIEW -- so
#: the monitor reports against them and says so, rather than presenting an
#: unreviewed number as settled policy.
ADHOC_PREFIX = "adhoc/"
ADHOC_QUOTA_BYTES = 50 * 1024 * 1024 * 1024
ADHOC_QUOTA_OBJECTS = 5000
ADHOC_RETENTION_DAYS = 90
ADHOC_QUOTA_PROVENANCE = (
    "DOC-F56858AFE749 ad-hoc companion section; agent-adopted, awaiting io's review"
)

#: Fraction of quota at which the check warns rather than breaches.
QUOTA_WARN_FRACTION = 0.8

# ---------------------------------------------------------------------------
# Container health (check 6)
# ---------------------------------------------------------------------------

#: Containers whose health is governed. Names are the compose-generated ones on
#: /opt/analytics/analytics-dashboard-6x.
GOVERNED_CONTAINERS: Tuple[str, ...] = (
    "analytics-dashboard-6x-trino-1",
    "analytics-dashboard-6x-superset-1",
)

#: Number of OOM kills within the lookback window that constitutes a breach.
OOM_KILL_BREACH_THRESHOLD = 1
OOM_LOOKBACK_DAYS = 7

# ---------------------------------------------------------------------------
# Burstable CPU economics (check 8)
# ---------------------------------------------------------------------------

#: The host runs CpuCredits=unlimited (verified live, DVP-TSK-635). Credit
#: exhaustion therefore does NOT throttle -- it converts to surplus credits that
#: are BILLED. The failure mode is economic, not a performance cliff, so the
#: thresholds below are written against surplus burn, not against the balance
#: reaching zero.
#:
#: T1/T2/T3 are the pre-registered escalation triggers from DVP-TSK-635 AC[1],
#: reproduced verbatim in intent.
CPU_CREDIT_T1_SURPLUS_CHARGED_HOURS = 3      # >0 charged in >=3 hours per rolling 24h
CPU_CREDIT_T2_BALANCE_FLOOR = 115.0          # 20% of the 576 t3.large earned cap
CPU_CREDIT_T2_CONSECUTIVE_DATAPOINTS = 3
CPU_CREDIT_T3_USAGE_PER_5MIN = 3.0           # the 36 credits/hr earn rate
CPU_CREDIT_T3_CONSECUTIVE_DATAPOINTS = 12    # one hour
CPU_CREDIT_BASELINE = {
    "observed_at": "2026-08-08T00:27:00Z",
    "balance": 591.322,
    "usage_peak_per_5min": 2.886,
    "surplus_charged": 0.0,
    "rolling_24h_minimum": 575.127,
    "source": "DVP-TSK-635 acceptance evidence",
}

# ---------------------------------------------------------------------------
# Declared dependency surface (check 9 -- IAM and configuration drift)
# ---------------------------------------------------------------------------

#: DOC-132286FF074F section 7, the exact field->value map. DVP-TSK-641 recorded
#: THIS task as the enforcement point and recorded why it must be SCHEDULED: the
#: 2026-08-06 severance arrived through `aws iam create-policy-version` at
#: 06:26:01Z plus a hand edit of .env at 06:35:13Z. Neither is observable to any
#: PR-triggered guard, and the deploy path /opt/analytics/analytics-dashboard-6x
#: is not a git checkout, so no pull request exists in that path at all.
#:
#: The registry fields (`required_iam_actions` / `required_env_secrets`) that the
#: existing PR-triggered auditors read are present on ZERO of 89 component rows
#: and there is no agent-accessible write path to them
#: (`execute` -> "Unknown execute action 'component.update'"). Until io applies
#: the section 7 map, the drift check reads its expected values from the
#: declaration document -- which is what this block is.
IAM_ROLE_NAME = "analytics-dashboard-ec2-role"
IAM_POLICY_NAME = "analytics-dashboard-data-access"
IAM_INSTANCE_PROFILE = "analytics-dashboard-instance-profile"

DECLARED_IAM_ACTIONS: Dict[str, Tuple[str, ...]] = {
    "comp-devops-trino": (
        "glue:GetDatabase",
        "glue:GetDatabases",
        "glue:GetTable",
        "glue:GetTables",
        "glue:GetPartition",
        "glue:GetPartitions",
        "glue:BatchGetPartition",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:PutObject",
        "kms:Decrypt",
        "kms:GenerateDataKey",
    ),
    # Superset reaches AWS only through Trino and holds no IAM actions of its own.
    "comp-devops-superset": (),
}

DECLARED_ENV_SECRETS: Dict[str, Tuple[str, ...]] = {
    "comp-devops-trino": ("AWS_REGION",),
    "comp-devops-superset": (
        "SQLALCHEMY_DATABASE_URI",
        "SUPERSET_SECRET_KEY",
        "SUPERSET_DB",
        "SUPERSET_DB_USER",
        "SUPERSET_DB_PASSWORD",
        "SUPERSET_ADMIN_USERNAME",
        "SUPERSET_ADMIN_PASSWORD",
        "SUPERSET_ADMIN_EMAIL",
        "AWS_REGION",
    ),
}

#: Glue write actions whose PRESENCE on the host role is itself the drift signal.
#:
#: DOC-132286FF074F section 2 records that ad-hoc ingest depends on
#: glue:CreateTable and that it is deliberately NOT granted. Their absence is a
#: declared property of the estate, so their sudden appearance is an
#: out-of-band widening -- the same shape of event as 2026-08-06, in the
#: opposite direction.
DECLARED_ABSENT_IAM_ACTIONS: Tuple[str, ...] = (
    "glue:CreateTable",
    "glue:UpdateTable",
    "glue:DeleteTable",
    "glue:CreateDatabase",
)

#: IMDSv2 posture recorded in DOC-132286FF074F section 1. HttpPutResponseHopLimit
#: is load-bearing: reducing it to 1 severs all Glue and S3 access for both
#: containers with NO change visible anywhere in the deploy tree.
DECLARED_METADATA_OPTIONS: Dict[str, Any] = {
    "HttpTokens": "required",
    "HttpEndpoint": "enabled",
    "HttpPutResponseHopLimit": 2,
}

#: The policy version in force when the surface was declared. A change is not by
#: itself a breach -- it is the event that must become VISIBLE within one
#: interval instead of six weeks.
DECLARED_POLICY_VERSION = "v11"
DECLARED_POLICY_UPDATED_AT = "2026-08-06T06:26:01Z"

# ---------------------------------------------------------------------------
# Severity vocabulary
# ---------------------------------------------------------------------------

SEVERITY_OK = "ok"
SEVERITY_WARNING = "warning"
SEVERITY_BREACH = "breach"
SEVERITY_ERROR = "error"

#: Severities that file a governed issue record.
ISSUE_FILING_SEVERITIES: FrozenSet[str] = frozenset({SEVERITY_BREACH})

#: Tracker priority assigned to an auto-filed issue, per check.
CHECK_PRIORITY: Dict[str, str] = {
    "check_1_freshness": "P1",
    "check_2_crawler": "P0",
    "check_3_namespace_isolation": "P1",
    "check_4_storage_format": "P1",
    "check_5_full_refresh": "P1",
    "check_6_container_health": "P1",
    "check_7_adhoc_quota": "P2",
    "check_8_cpu_credit": "P2",
    "check_9_dependency_drift": "P0",
}
DEFAULT_CHECK_PRIORITY = "P2"
