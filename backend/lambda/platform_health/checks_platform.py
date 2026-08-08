"""Checks 6, 7, 8 and 9 -- the platform, the quota, the bill, and the drift.

DVP-TSK-696 / BRD B6-R2 / DVP-PLN-001.

CHECK 6 -- CONTAINER HEALTH, AND WHY RestartCount IS NOT THE INSTRUMENT.

This is the check that encodes the single most useful operational lesson of the
whole investigation, so the reasoning is written down rather than assumed.

On this host, ``docker inspect -f '{{.RestartCount}}'`` reads **0 for every
container**, and has read 0 the whole time. It read 0 through **seven**
``CONSTRAINT_MEMCG`` OOM kills of ``trino-server`` between 2026-04-13 and
2026-08-07. Verified live on 2026-08-08: all four containers at RestartCount=0,
and ``State.OOMKilled`` false on all four.

The reason is mechanical and worth knowing. Every one of those kills targeted
``task=trino-server`` -- the JVM process **inside** the container -- not the
container's PID 1. Docker's restart counter increments when the container dies;
it has nothing to say about a process killed within a container that keeps
running. So the container stayed up, the health check kept passing, and the
instrument everyone would reach for first reported a perfectly healthy service
across five days of memory kills.

The kernel log is the instrument that actually saw them. But there is a second
trap underneath the first, and it cost a run to find:

  * ``dmesg`` reads the kernel ring buffer, which is **cleared on reboot**. This
    host rebooted at 2026-08-07T23:33:28Z for the instance resize, so ``dmesg``
    today shows ZERO OOM events despite seven having happened.
  * ``journalctl -k`` defaults to the **current boot only**. It therefore also
    returned 0 -- and, crucially, ``journalctl -k --since <date>`` does NOT
    override that implicit boot filter, so the obvious workaround silently
    returns 0 as well.
  * The events are all in ``journalctl -k -b -1``, which returns 21 matching
    lines. This host has a persistent journal (``/var/log/journal`` exists), so
    the history survived the reboot; it was simply not being asked for.

The check therefore reads BOTH: the current-boot ring buffer (works anywhere,
needs no journald) and an explicit sweep of the previous boots (survives the
reboot that would otherwise erase the evidence). It also reports the boot time,
so "no OOM kills" is always qualified by "since when" -- an unqualified all-clear
from a buffer that was emptied an hour ago is worse than no answer.

CHECK 7 -- the ad-hoc quarantine quota. Handles the empty case explicitly:
``hive.adhoc`` currently holds zero objects and zero tables, and a utilisation
ratio must not divide by a zero quota.

CHECK 8 -- burstable CPU. On this host ``CpuCredits=unlimited``, so exhausting
the credit balance does NOT throttle -- it converts to surplus credits that are
BILLED. The failure mode is economic, not a performance cliff, so the thresholds
are written against surplus burn rather than against the balance reaching zero.
The T1/T2/T3 triggers are DVP-TSK-635's pre-registered ones, unchanged.

CHECK 9 -- IAM AND CONFIGURATION DRIFT. The ninth check, added because
DVP-TSK-641 named this task as its enforcement point and recorded why it must be
SCHEDULED: the 2026-08-06 severance arrived through ``aws iam
create-policy-version`` at 06:26:01Z plus a hand edit of ``.env`` at 06:35:13Z.
No PR-triggered guard can observe either, and the deploy path
``/opt/analytics/analytics-dashboard-6x`` is not a git checkout, so there is no
pull request in that path at all. A PR-shaped control would pass green through
exactly the event it exists to catch.

Expected values come from DOC-132286FF074F section 7, because the component
registry fields the existing auditors read are present on zero of 89 rows and
have no agent-accessible write path.
"""

from __future__ import annotations

import base64
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from health_contract import (
    ADHOC_PREFIX,
    ADHOC_QUOTA_BYTES,
    ADHOC_QUOTA_OBJECTS,
    ADHOC_QUOTA_PROVENANCE,
    ANALYTICS_INSTANCE_ID,
    CPU_CREDIT_T1_SURPLUS_CHARGED_HOURS,
    CPU_CREDIT_T2_BALANCE_FLOOR,
    CPU_CREDIT_T2_CONSECUTIVE_DATAPOINTS,
    CPU_CREDIT_T3_CONSECUTIVE_DATAPOINTS,
    CPU_CREDIT_T3_USAGE_PER_5MIN,
    DECLARED_ABSENT_IAM_ACTIONS,
    DECLARED_ENV_SECRETS,
    DECLARED_IAM_ACTIONS,
    DECLARED_METADATA_OPTIONS,
    DECLARED_POLICY_UPDATED_AT,
    DECLARED_POLICY_VERSION,
    GOVERNED_CONTAINERS,
    IAM_POLICY_NAME,
    IAM_ROLE_NAME,
    OOM_KILL_BREACH_THRESHOLD,
    OOM_LOOKBACK_DAYS,
    QUOTA_WARN_FRACTION,
    SEVERITY_BREACH,
    SEVERITY_WARNING,
    WAREHOUSE_BUCKET,
)
from health_finding import CheckResult, Finding

LOGGER = logging.getLogger(__name__)

CHECK_6 = "check_6_container_health"
CHECK_7 = "check_7_adhoc_quota"
CHECK_8 = "check_8_cpu_credit"
CHECK_9 = "check_9_dependency_drift"


# ---------------------------------------------------------------------------
# Check 6 -- container health from the kernel log
# ---------------------------------------------------------------------------

#: The probe. Read-only by construction: no docker command that mutates, no
#: write to any path. Emits fenced sections so the parser never has to guess.
#:
#: `journalctl -k -b -N` is issued PER BOOT rather than once with --since,
#: because -k pins the current boot and --since does not lift that filter.
OOM_PROBE = r"""
set -uo pipefail
echo "###BOOT_TIME"
uptime -s 2>/dev/null || true
echo "###CONTAINERS"
for c in $(docker ps -a --format '{{.Names}}' 2>/dev/null); do
  printf '%s|%s|%s|%s\n' "$c" \
    "$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null)" \
    "$(docker inspect -f '{{.RestartCount}}' "$c" 2>/dev/null)" \
    "$(docker inspect -f '{{.State.OOMKilled}}' "$c" 2>/dev/null)"
done
echo "###DMESG_OOM"
sudo dmesg -T 2>/dev/null | grep -E 'oom-kill:constraint=' || true
echo "###JOURNAL_OOM"
for b in 0 -1 -2 -3; do
  sudo journalctl -k -b "$b" --no-pager -o short-iso 2>/dev/null \
    | grep -E 'oom-kill:constraint=' || true
done
echo "###END"
"""

_OOM_LINE = re.compile(
    r"oom-kill:constraint=(?P<constraint>\w+).*?task=(?P<task>[\w.\-]+)"
)
_TS_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
_TS_SYSLOG = re.compile(r"^\[?(\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4})\]?")


def run_host_probe(
    ssm_client, instance_id: str = ANALYTICS_INSTANCE_ID, timeout_seconds: int = 120
) -> str:
    """Run the read-only probe on the analytics host and return stdout.

    Refuses any instance but the declared one. A health monitor that can be
    pointed at an arbitrary host by a malformed event is a remote-execution
    surface, not an instrument.
    """
    if instance_id != ANALYTICS_INSTANCE_ID:
        raise ValueError(
            "refusing to run the host probe on %r; the declared analytics host is %r"
            % (instance_id, ANALYTICS_INSTANCE_ID)
        )
    encoded = base64.b64encode(OOM_PROBE.encode("utf-8")).decode("ascii")
    command = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={
            "commands": [
                "echo %s | base64 -d > /tmp/platform_health_probe.sh" % encoded,
                "bash /tmp/platform_health_probe.sh",
            ]
        },
    )
    command_id = command["Command"]["CommandId"]

    deadline = time.time() + timeout_seconds
    status = "Pending"
    invocation: Dict[str, Any] = {}
    while time.time() < deadline:
        time.sleep(3)
        try:
            invocation = ssm_client.get_command_invocation(
                CommandId=command_id, InstanceId=instance_id
            )
        except Exception:  # noqa: BLE001 - InvocationDoesNotExist races the send
            continue
        status = invocation.get("Status", "Pending")
        if status in ("Success", "Failed", "Cancelled", "TimedOut"):
            break
    if status != "Success":
        raise RuntimeError(
            "host probe %s ended in status %s: %s"
            % (command_id, status, invocation.get("StandardErrorContent", ""))
        )
    return invocation.get("StandardOutputContent", "")


def _sections(output: str) -> Dict[str, List[str]]:
    sections: Dict[str, List[str]] = {}
    current = None
    for line in output.splitlines():
        if line.startswith("###"):
            current = line[3:].strip()
            sections[current] = []
        elif current:
            sections[current].append(line)
    return sections


def _parse_oom_timestamp(line: str) -> Optional[datetime]:
    iso = _TS_ISO.match(line)
    if iso:
        try:
            return datetime.fromisoformat(iso.group(1)).replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    syslog = _TS_SYSLOG.match(line)
    if syslog:
        for fmt in ("%a %b %d %H:%M:%S %Y",):
            try:
                return datetime.strptime(syslog.group(1), fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def parse_oom_events(output: str) -> List[Dict[str, Any]]:
    """OOM kill events from BOTH the ring buffer and the persistent journal.

    De-duplicated on (timestamp, task), because the current boot appears in both
    sources and an event counted twice would inflate a threshold comparison.
    """
    sections = _sections(output)
    events: Dict[Tuple[Any, str], Dict[str, Any]] = {}
    for source in ("DMESG_OOM", "JOURNAL_OOM"):
        for line in sections.get(source, []):
            match = _OOM_LINE.search(line)
            if not match:
                continue
            when = _parse_oom_timestamp(line)
            key = (when.isoformat() if when else line[:32], match.group("task"))
            if key in events:
                events[key]["sources"].append(source)
                continue
            events[key] = {
                "timestamp": when.isoformat() if when else None,
                "task": match.group("task"),
                "constraint": match.group("constraint"),
                "sources": [source],
                "raw": line.strip()[:400],
            }
    return sorted(events.values(), key=lambda e: e["timestamp"] or "")


def parse_containers(output: str) -> List[Dict[str, Any]]:
    rows = []
    for line in _sections(output).get("CONTAINERS", []):
        parts = line.split("|")
        if len(parts) != 4:
            continue
        name, status, restarts, oomkilled = parts
        rows.append(
            {
                "name": name,
                "status": status,
                "restart_count": int(restarts) if restarts.isdigit() else None,
                "docker_oomkilled": oomkilled.strip().lower() == "true",
            }
        )
    return rows


def check_container_health(
    ssm_client,
    now: Optional[datetime] = None,
    instance_id: str = ANALYTICS_INSTANCE_ID,
    probe_output: Optional[str] = None,
) -> CheckResult:
    now = now or datetime.now(timezone.utc)
    result = CheckResult(
        check=CHECK_6,
        title="Trino and Superset container health, with OOM read from the kernel log",
    )
    try:
        output = probe_output if probe_output is not None else run_host_probe(
            ssm_client, instance_id
        )
    except Exception as exc:  # noqa: BLE001
        result.error = "host probe failed: %s" % exc
        LOGGER.exception("host probe failed")
        return result

    sections = _sections(output)
    boot_time = (sections.get("BOOT_TIME") or [""])[0].strip()
    containers = parse_containers(output)
    events = parse_oom_events(output)
    cutoff = now - timedelta(days=OOM_LOOKBACK_DAYS)
    recent = [
        e for e in events
        if e["timestamp"] and datetime.fromisoformat(e["timestamp"]) >= cutoff
    ]

    result.detail = {
        "boot_time": boot_time,
        "containers": containers,
        "oom_events_all_boots": events,
        "oom_events_in_window": recent,
        "lookback_days": OOM_LOOKBACK_DAYS,
        "restart_count_is_not_the_instrument": (
            "Every OOM kill on this host targeted the JVM process inside the "
            "container (task=trino-server), never the container's PID 1, so "
            "RestartCount never incremented and docker's own OOMKilled flag "
            "stayed false. RestartCount readings are reported for contrast only."
        ),
    }

    by_container = {c["name"]: c for c in containers}
    for name in GOVERNED_CONTAINERS:
        result.subjects_examined += 1
        container = by_container.get(name)
        if container is None:
            result.findings.append(
                Finding(
                    check=CHECK_6, subject=name, severity=SEVERITY_BREACH,
                    kind="container_absent",
                    summary="governed container %s is not present on the host" % name,
                    observed={"present": False},
                    expected={"present": True, "status": "running"},
                    steps_to_duplicate=["docker ps -a --format '{{.Names}}'"],
                    remediation="A governed container is missing. Bring the compose stack up.",
                )
            )
            continue
        if container["status"] != "running":
            result.findings.append(
                Finding(
                    check=CHECK_6, subject=name, severity=SEVERITY_BREACH,
                    kind="container_not_running",
                    summary="%s is %s" % (name, container["status"]),
                    observed=container,
                    expected={"status": "running"},
                    steps_to_duplicate=["docker inspect -f '{{.State.Status}}' %s" % name],
                    remediation="Container is not running; inspect its logs and restart the stack.",
                )
            )

    # The OOM finding is keyed on the TASK the kernel killed, not on a container
    # name, because that is what the kernel actually records and what makes the
    # finding traceable back to a specific process.
    tasks: Dict[str, List[Dict[str, Any]]] = {}
    for event in recent:
        tasks.setdefault(event["task"], []).append(event)

    for task, task_events in sorted(tasks.items()):
        if len(task_events) < OOM_KILL_BREACH_THRESHOLD:
            continue
        result.findings.append(
            Finding(
                check=CHECK_6,
                subject="oom:%s" % task,
                severity=SEVERITY_BREACH,
                kind="oom_kill",
                summary="%d OOM kill(s) of %s in the last %d days"
                % (len(task_events), task, OOM_LOOKBACK_DAYS),
                observed={
                    "kill_count": len(task_events),
                    "task": task,
                    "constraints": sorted({e["constraint"] for e in task_events}),
                    "timestamps": [e["timestamp"] for e in task_events],
                    "restart_counts_reported_by_docker": {
                        c["name"]: c["restart_count"] for c in containers
                    },
                    "boot_time": boot_time,
                },
                expected={"kill_count": 0},
                steps_to_duplicate=[
                    "sudo dmesg -T | grep 'oom-kill:constraint='   # CURRENT BOOT ONLY",
                    "sudo journalctl -k -b -1 --no-pager | grep 'oom-kill:constraint='",
                    "# note: `journalctl -k --since <date>` does NOT lift the implicit "
                    "current-boot filter and will return 0 matches",
                    "docker inspect -f '{{.RestartCount}}' analytics-dashboard-6x-trino-1  "
                    "# reads 0 -- NOT a usable signal on this host",
                ],
                remediation=(
                    "A process was killed by the cgroup memory limit while its container "
                    "stayed up and its health check kept passing. RestartCount and "
                    "docker's OOMKilled flag both read clean through this, because the "
                    "kernel killed the process INSIDE the container rather than its "
                    "PID 1. Raise the container's memory limit or reduce query "
                    "concurrency; do not conclude from a green container that the "
                    "service was healthy."
                ),
                references=["DVP-ISS-095", "DVP-TSK-634"],
            )
        )
    return result


# ---------------------------------------------------------------------------
# Check 7 -- ad-hoc quarantine quota
# ---------------------------------------------------------------------------


def check_adhoc_quota(
    s3_client, glue_client, bucket: str = WAREHOUSE_BUCKET
) -> CheckResult:
    result = CheckResult(check=CHECK_7, title="Ad-hoc namespace size and table count against quota")
    objects = 0
    total_bytes = 0
    token = None
    try:
        while True:
            kwargs: Dict[str, Any] = {"Bucket": bucket, "Prefix": ADHOC_PREFIX}
            if token:
                kwargs["ContinuationToken"] = token
            page = s3_client.list_objects_v2(**kwargs)
            for entry in page.get("Contents", []) or []:
                objects += 1
                total_bytes += entry.get("Size", 0)
            if not page.get("IsTruncated"):
                break
            token = page.get("NextContinuationToken")
            if not token:
                break
    except Exception as exc:  # noqa: BLE001
        result.error = "adhoc prefix listing failed: %s" % exc
        return result

    try:
        tables = glue_client.get_tables(DatabaseName="adhoc").get("TableList", []) or []
    except Exception:  # noqa: BLE001
        tables = []

    result.subjects_examined = 1
    # The empty case is explicit. hive.adhoc currently holds zero objects, and a
    # utilisation ratio computed against a zero-or-absent quota would divide by
    # zero -- so the ratio is computed only when the quota is positive, and an
    # empty namespace reports 0.0 rather than raising or reporting nothing.
    byte_ratio = (total_bytes / ADHOC_QUOTA_BYTES) if ADHOC_QUOTA_BYTES > 0 else 0.0
    object_ratio = (objects / ADHOC_QUOTA_OBJECTS) if ADHOC_QUOTA_OBJECTS > 0 else 0.0

    result.detail = {
        "objects": objects,
        "bytes": total_bytes,
        "tables": len(tables),
        "quota_bytes": ADHOC_QUOTA_BYTES,
        "quota_objects": ADHOC_QUOTA_OBJECTS,
        "byte_utilisation": round(byte_ratio, 6),
        "object_utilisation": round(object_ratio, 6),
        "empty": objects == 0 and not tables,
        "quota_provenance": ADHOC_QUOTA_PROVENANCE,
    }

    for label, used, quota, ratio in (
        ("bytes", total_bytes, ADHOC_QUOTA_BYTES, byte_ratio),
        ("objects", objects, ADHOC_QUOTA_OBJECTS, object_ratio),
    ):
        if ratio >= 1.0:
            severity, kind = SEVERITY_BREACH, "adhoc_quota_exceeded"
        elif ratio >= QUOTA_WARN_FRACTION:
            severity, kind = SEVERITY_WARNING, "adhoc_quota_approaching"
        else:
            continue
        result.findings.append(
            Finding(
                check=CHECK_7, subject="hive.adhoc:%s" % label, severity=severity, kind=kind,
                summary="ad-hoc %s at %.1f%% of quota (%s of %s)"
                % (label, ratio * 100, used, quota),
                observed={label: used, "utilisation": round(ratio, 6)},
                expected={"quota": quota, "warn_fraction": QUOTA_WARN_FRACTION},
                steps_to_duplicate=[
                    "aws s3 ls s3://%s/%s --recursive --summarize --profile product-lead "
                    "--region us-west-2 | tail -3" % (bucket, ADHOC_PREFIX),
                ],
                remediation=(
                    "Ad-hoc quarantine is at or over its declared quota. Promote the "
                    "tables that have earned a permanent home (DOC-325D4FB98208) or let "
                    "retention expire the rest. NOTE the quota itself is agent-adopted "
                    "and awaiting io's review (%s) -- if it is the wrong number, change "
                    "the declaration rather than muting the check." % ADHOC_QUOTA_PROVENANCE
                ),
                references=["DOC-F56858AFE749", "DOC-FF843F9F0E2C"],
            )
        )
    return result


# ---------------------------------------------------------------------------
# Check 8 -- burstable CPU credit, as an ECONOMIC signal
# ---------------------------------------------------------------------------


def _metric_series(cw_client, metric: str, stat: str, period: int, hours: int,
                   instance_id: str, now: datetime) -> List[Dict[str, Any]]:
    response = cw_client.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName=metric,
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=now - timedelta(hours=hours),
        EndTime=now,
        Period=period,
        Statistics=[stat],
    )
    points = sorted(response.get("Datapoints", []), key=lambda d: d["Timestamp"])
    return [{"t": p["Timestamp"], "v": float(p[stat])} for p in points]


def check_cpu_credit(
    cw_client, ec2_client, now: Optional[datetime] = None,
    instance_id: str = ANALYTICS_INSTANCE_ID,
) -> CheckResult:
    now = now or datetime.now(timezone.utc)
    result = CheckResult(check=CHECK_8, title="CPUCreditBalance while the host is burstable")
    try:
        spec = ec2_client.describe_instance_credit_specifications(InstanceIds=[instance_id])
        credits_mode = (spec.get("InstanceCreditSpecifications") or [{}])[0].get("CpuCredits", "")
    except Exception as exc:  # noqa: BLE001
        result.error = "credit specification read failed: %s" % exc
        return result

    if not credits_mode:
        # Not burstable at all -- the check does not apply, and saying so is
        # different from saying the host is healthy.
        result.detail = {"burstable": False, "note": "no credit specification; check N/A"}
        return result

    result.subjects_examined = 1
    try:
        balance = _metric_series(cw_client, "CPUCreditBalance", "Minimum", 300, 24, instance_id, now)
        usage = _metric_series(cw_client, "CPUCreditUsage", "Maximum", 300, 24, instance_id, now)
        surplus = _metric_series(
            cw_client, "CPUSurplusCreditsCharged", "Sum", 3600, 24, instance_id, now
        )
    except Exception as exc:  # noqa: BLE001
        result.error = "CloudWatch read failed: %s" % exc
        return result

    surplus_hours = sum(1 for p in surplus if p["v"] > 0)
    low_streak = _max_streak(balance, lambda v: v <= CPU_CREDIT_T2_BALANCE_FLOOR)
    usage_streak = _max_streak(usage, lambda v: v > CPU_CREDIT_T3_USAGE_PER_5MIN)

    result.detail = {
        "cpu_credits": credits_mode,
        "unlimited": credits_mode == "unlimited",
        "latest_balance": balance[-1]["v"] if balance else None,
        "min_balance_24h": min((p["v"] for p in balance), default=None),
        "max_usage_per_5min_24h": max((p["v"] for p in usage), default=None),
        "surplus_charged_total_24h": sum(p["v"] for p in surplus),
        "t1_surplus_charged_hours": surplus_hours,
        "t2_low_balance_streak": low_streak,
        "t3_high_usage_streak": usage_streak,
        "economic_not_performance": credits_mode == "unlimited",
    }

    triggers = [
        (
            "T1",
            surplus_hours >= CPU_CREDIT_T1_SURPLUS_CHARGED_HOURS,
            "cpu_surplus_charged",
            "CPUSurplusCreditsCharged > 0 in %d of the last 24 hours (threshold %d)"
            % (surplus_hours, CPU_CREDIT_T1_SURPLUS_CHARGED_HOURS),
        ),
        (
            "T2",
            low_streak >= CPU_CREDIT_T2_CONSECUTIVE_DATAPOINTS,
            "cpu_credit_balance_low",
            "CPUCreditBalance <= %.0f for %d consecutive datapoints (threshold %d)"
            % (CPU_CREDIT_T2_BALANCE_FLOOR, low_streak, CPU_CREDIT_T2_CONSECUTIVE_DATAPOINTS),
        ),
        (
            "T3",
            usage_streak >= CPU_CREDIT_T3_CONSECUTIVE_DATAPOINTS,
            "cpu_credit_usage_sustained",
            "CPUCreditUsage > %.1f/5min for %d consecutive datapoints (threshold %d)"
            % (CPU_CREDIT_T3_USAGE_PER_5MIN, usage_streak, CPU_CREDIT_T3_CONSECUTIVE_DATAPOINTS),
        ),
    ]
    for tier, fired, kind, summary in triggers:
        if not fired:
            continue
        result.findings.append(
            Finding(
                check=CHECK_8, subject="%s:%s" % (instance_id, tier),
                severity=SEVERITY_BREACH if tier == "T1" else SEVERITY_WARNING,
                kind=kind, summary="%s %s" % (tier, summary),
                observed=result.detail,
                expected={
                    "T1_surplus_charged_hours_max": CPU_CREDIT_T1_SURPLUS_CHARGED_HOURS - 1,
                    "T2_balance_floor": CPU_CREDIT_T2_BALANCE_FLOOR,
                    "T3_usage_per_5min": CPU_CREDIT_T3_USAGE_PER_5MIN,
                },
                steps_to_duplicate=[
                    "aws cloudwatch get-metric-statistics --namespace AWS/EC2 "
                    "--metric-name CPUSurplusCreditsCharged --dimensions "
                    "Name=InstanceId,Value=%s --statistics Sum --period 3600 "
                    "--start-time $(date -u -v-24H +%%Y-%%m-%%dT%%H:%%M:%%SZ) "
                    "--end-time $(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ) "
                    "--profile product-lead --region us-west-2" % instance_id,
                ],
                remediation=(
                    "This host runs CpuCredits=unlimited, so credit exhaustion does NOT "
                    "throttle -- it converts to surplus credits that are BILLED. T1 is "
                    "the economically meaningful trigger and is the D-6 evidence of "
                    "credit exhaustion; T2 is the leading indicator that should prompt "
                    "investigation BEFORE T1 costs money. Compute the m5.large cost "
                    "crossover against then-current on-demand pricing at decision time."
                ),
                references=["DVP-TSK-635"],
            )
        )
    return result


def _max_streak(points: Sequence[Dict[str, Any]], predicate) -> int:
    best = streak = 0
    for point in points:
        streak = streak + 1 if predicate(point["v"]) else 0
        best = max(best, streak)
    return best


# ---------------------------------------------------------------------------
# Check 9 -- IAM and configuration drift against the declared surface
# ---------------------------------------------------------------------------


def check_dependency_drift(
    iam_client, ec2_client, instance_id: str = ANALYTICS_INSTANCE_ID
) -> CheckResult:
    result = CheckResult(
        check=CHECK_9,
        title="Declared IAM and configuration dependency surface against live AWS",
    )
    try:
        attached = iam_client.list_attached_role_policies(RoleName=IAM_ROLE_NAME)
        policies = attached.get("AttachedPolicies", []) or []
    except Exception as exc:  # noqa: BLE001
        result.error = "IAM read failed for role %s: %s" % (IAM_ROLE_NAME, exc)
        return result

    target = next((p for p in policies if p.get("PolicyName") == IAM_POLICY_NAME), None)
    if target is None:
        result.subjects_examined += 1
        result.findings.append(
            Finding(
                check=CHECK_9, subject="iam:%s" % IAM_POLICY_NAME, severity=SEVERITY_BREACH,
                kind="declared_policy_detached",
                summary="policy %s is no longer attached to role %s"
                % (IAM_POLICY_NAME, IAM_ROLE_NAME),
                observed={"attached": [p.get("PolicyName") for p in policies]},
                expected={"attached_contains": IAM_POLICY_NAME},
                steps_to_duplicate=[
                    "aws iam list-attached-role-policies --role-name %s "
                    "--profile product-lead" % IAM_ROLE_NAME
                ],
                remediation=(
                    "Detaching this policy severs every Glue and S3 capability the "
                    "Trino container has, and therefore every Superset dashboard, with "
                    "no change visible anywhere in the deploy tree."
                ),
                references=["DOC-132286FF074F", "DVP-TSK-641"],
            )
        )
        return result

    policy = iam_client.get_policy(PolicyArn=target["PolicyArn"])["Policy"]
    version_id = policy["DefaultVersionId"]
    document = iam_client.get_policy_version(
        PolicyArn=target["PolicyArn"], VersionId=version_id
    )["PolicyVersion"]["Document"]

    granted = _granted_actions(document)
    result.detail = {
        "policy_arn": target["PolicyArn"],
        "default_version": version_id,
        "declared_version": DECLARED_POLICY_VERSION,
        "declared_version_updated_at": DECLARED_POLICY_UPDATED_AT,
        "granted_action_count": len(granted),
        "expected_source": "DOC-132286FF074F section 7",
        "why_scheduled": (
            "The 2026-08-06 severance arrived through aws iam create-policy-version "
            "plus a hand edit of .env. Neither is observable to a PR-triggered guard, "
            "and the deploy path is not a git checkout, so no pull request exists in "
            "that path at all (DVP-TSK-641)."
        ),
    }

    for component, required in sorted(DECLARED_IAM_ACTIONS.items()):
        if not required:
            continue
        result.subjects_examined += 1
        missing = [a for a in required if not _action_granted(a, granted)]
        if missing:
            result.findings.append(
                Finding(
                    check=CHECK_9, subject="iam:%s" % component, severity=SEVERITY_BREACH,
                    kind="declared_iam_action_missing",
                    summary="%s lost %d declared IAM action(s): %s"
                    % (component, len(missing), ", ".join(missing)),
                    observed={"missing": missing, "policy_version": version_id},
                    expected={"required_iam_actions": list(required)},
                    steps_to_duplicate=[
                        "aws iam get-policy --policy-arn %s --profile product-lead"
                        % target["PolicyArn"],
                        "aws iam get-policy-version --policy-arn %s --version-id %s "
                        "--profile product-lead" % (target["PolicyArn"], version_id),
                    ],
                    remediation=(
                        "A declared capability has been severed out of band. This is the "
                        "exact 2026-08-06 shape: the policy changed, nothing in the "
                        "deploy tree changed, and the break was found six weeks later by "
                        "accident. Restore the action or amend the declaration in "
                        "DOC-132286FF074F section 7 -- but do not leave live and "
                        "declared disagreeing."
                    ),
                    references=["DOC-132286FF074F", "DVP-TSK-641", "DVP-ISS-093"],
                )
            )

    result.subjects_examined += 1
    unexpected = [a for a in DECLARED_ABSENT_IAM_ACTIONS if _action_granted(a, granted)]
    if unexpected:
        result.findings.append(
            Finding(
                check=CHECK_9, subject="iam:declared-absent", severity=SEVERITY_BREACH,
                kind="declared_absent_action_granted",
                summary="%d action(s) declared ABSENT are now granted: %s"
                % (len(unexpected), ", ".join(unexpected)),
                observed={"unexpectedly_granted": unexpected, "policy_version": version_id},
                expected={"must_remain_absent": list(DECLARED_ABSENT_IAM_ACTIONS)},
                steps_to_duplicate=[
                    "aws iam get-policy-version --policy-arn %s --version-id %s "
                    "--profile product-lead" % (target["PolicyArn"], version_id),
                ],
                remediation=(
                    "Their absence is a DECLARED property of the estate (DOC-132286FF074F "
                    "section 2), so their appearance is an out-of-band widening -- the "
                    "same shape of event as 2026-08-06, in the opposite direction. It may "
                    "be intentional (ad-hoc ingest needs glue:CreateTable), in which case "
                    "the declaration should be amended so the grant is governed rather "
                    "than merely present."
                ),
                references=["DOC-132286FF074F", "DVP-TSK-641"],
            )
        )

    if version_id != DECLARED_POLICY_VERSION:
        result.findings.append(
            Finding(
                check=CHECK_9, subject="iam:%s:version" % IAM_POLICY_NAME,
                severity=SEVERITY_WARNING, kind="policy_version_changed",
                summary="policy default version is %s; the declaration records %s"
                % (version_id, DECLARED_POLICY_VERSION),
                observed={"default_version": version_id},
                expected={"declared_version": DECLARED_POLICY_VERSION},
                steps_to_duplicate=[
                    "aws iam get-policy --policy-arn %s --profile product-lead"
                    % target["PolicyArn"]
                ],
                remediation=(
                    "Not a breach on its own -- the declared actions are checked "
                    "separately. It is the event that must become VISIBLE within one "
                    "interval instead of six weeks. Reconcile the declaration."
                ),
                references=["DOC-132286FF074F"],
            )
        )

    # IMDSv2 posture. HttpPutResponseHopLimit is the load-bearing one: reducing
    # it to 1 severs all Glue and S3 access for both containers with no change
    # visible anywhere in the deploy tree.
    result.subjects_examined += 1
    try:
        reservations = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = reservations["Reservations"][0]["Instances"][0]
        options = instance.get("MetadataOptions", {})
    except Exception as exc:  # noqa: BLE001
        result.error = (result.error or "") + " instance metadata read failed: %s" % exc
        return result

    drifted = {
        key: {"observed": options.get(key), "expected": value}
        for key, value in DECLARED_METADATA_OPTIONS.items()
        if options.get(key) != value
    }
    result.detail["metadata_options"] = options
    if drifted:
        result.findings.append(
            Finding(
                check=CHECK_9, subject="imds:%s" % instance_id, severity=SEVERITY_BREACH,
                kind="imds_posture_drift",
                summary="IMDSv2 posture drifted on %d field(s): %s"
                % (len(drifted), ", ".join(sorted(drifted))),
                observed=drifted,
                expected=dict(DECLARED_METADATA_OPTIONS),
                steps_to_duplicate=[
                    "aws ec2 describe-instances --instance-ids %s --profile product-lead "
                    "--region us-west-2 --query "
                    "'Reservations[0].Instances[0].MetadataOptions'" % instance_id,
                ],
                remediation=(
                    "IMDSv2 is the credential mechanism for both containers, replacing "
                    "the static keys removed on 2026-08-06. HttpPutResponseHopLimit=2 is "
                    "load-bearing: reducing it to 1 severs all Glue and S3 access for "
                    "both containers with NO change visible in the deploy tree."
                ),
                references=["DOC-132286FF074F", "DVP-TSK-641"],
            )
        )
    return result


def _granted_actions(document: Any) -> List[str]:
    """Every Allow action in the policy document, lowercased."""
    actions: List[str] = []
    statements = document.get("Statement") if isinstance(document, dict) else None
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements or []:
        if statement.get("Effect") != "Allow":
            continue
        raw = statement.get("Action", [])
        if isinstance(raw, str):
            raw = [raw]
        actions.extend(a.lower() for a in raw)
    return actions


def _action_granted(action: str, granted: Sequence[str]) -> bool:
    """Wildcard-aware membership: ``glue:*`` and ``*`` grant ``glue:GetTable``."""
    wanted = action.lower()
    service = wanted.split(":", 1)[0]
    for raw in granted:
        # Lowercased here rather than relying on the caller. IAM action names are
        # case-insensitive and a policy may spell them any way; a comparison that
        # assumed normalised input would silently report a granted action as
        # missing, which on this check means a false severance alarm.
        entry = raw.lower()
        if entry == "*" or entry == wanted or entry == "%s:*" % service:
            return True
        if entry.endswith("*") and wanted.startswith(entry[:-1]):
            return True
    return False
