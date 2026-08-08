"""Tests for B6-R2 checks 6, 7, 8 and 9 (DVP-TSK-696).

The case to keep if these are ever pruned is
``test_restart_count_stays_zero_through_every_oom_kill``. It encodes the whole
operational lesson: the instrument everybody reaches for first reported a
perfectly healthy service across five days of memory kills, and any future
refactor that "simplifies" check 6 back onto RestartCount will fail here.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from checks_platform import (
    _action_granted,
    _granted_actions,
    check_adhoc_quota,
    check_container_health,
    check_cpu_credit,
    check_dependency_drift,
    parse_containers,
    parse_oom_events,
    run_host_probe,
)
from health_contract import ANALYTICS_INSTANCE_ID

NOW = datetime(2026, 8, 8, 2, 0, 0, tzinfo=timezone.utc)

# Verbatim shape of the real probe output from the live host on 2026-08-08.
PROBE = """###BOOT_TIME
2026-08-07 23:33:28
###CONTAINERS
analytics-dashboard-6x-superset-1|running|0|false
analytics-dashboard-6x-trino-1|running|0|false
###DMESG_OOM
###JOURNAL_OOM
2026-08-06T06:45:29+0000 host kernel: oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),task_memcg=/system.slice/docker-f5c1.scope,task=trino-server,pid=3099177,uid=1000
2026-08-07T03:58:14+0000 host kernel: oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),task_memcg=/system.slice/docker-f5c1.scope,task=trino-server,pid=3010709,uid=1000
2026-08-07T04:21:05+0000 host kernel: oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),task_memcg=/system.slice/docker-f5c1.scope,task=trino-server,pid=3168695,uid=1000
###END
"""


# ---------------------------------------------------------------------------
# Check 6 -- the instrument
# ---------------------------------------------------------------------------


def test_restart_count_stays_zero_through_every_oom_kill():
    """THE lesson. Every kill targeted the JVM inside the container, never the
    container's PID 1, so docker's restart counter and its own OOMKilled flag
    both read clean. A check built on RestartCount reports a healthy service
    across five days of memory kills."""
    containers = parse_containers(PROBE)
    assert all(c["restart_count"] == 0 for c in containers)
    assert all(c["docker_oomkilled"] is False for c in containers)
    assert all(c["status"] == "running" for c in containers)

    result = check_container_health(None, now=NOW, probe_output=PROBE)
    assert result.severity == "breach"
    assert [f.kind for f in result.findings] == ["oom_kill"]
    assert result.findings[0].observed["kill_count"] == 3
    assert result.findings[0].observed["task"] == "trino-server"


def test_dmesg_alone_would_see_nothing_after_a_reboot():
    """dmesg reads the kernel ring buffer, which the 2026-08-07T23:33:28Z resize
    reboot cleared. The persistent journal is what still holds the evidence, and
    reading only dmesg produces a confident all-clear about a buffer emptied an
    hour earlier."""
    dmesg_only = PROBE.split("###JOURNAL_OOM")[0] + "###JOURNAL_OOM\n###END\n"
    assert parse_oom_events(dmesg_only) == []
    assert len(parse_oom_events(PROBE)) == 3

    result = check_container_health(None, now=NOW, probe_output=dmesg_only)
    assert result.findings == []
    # ...but the answer is always qualified by when the buffer starts.
    assert result.detail["boot_time"] == "2026-08-07 23:33:28"


def test_events_seen_in_both_sources_are_counted_once():
    first_journal_line = next(
        line for line in PROBE.splitlines() if "oom-kill:constraint=" in line
    )
    both = PROBE.replace("###DMESG_OOM\n", "###DMESG_OOM\n" + first_journal_line + "\n")
    events = parse_oom_events(both)
    assert len(events) == 3, "the current boot appears in both sources; counting it twice would inflate the threshold"
    duplicated = next(e for e in events if len(e["sources"]) > 1)
    assert sorted(duplicated["sources"]) == ["DMESG_OOM", "JOURNAL_OOM"]


def test_old_kills_outside_the_window_do_not_breach():
    result = check_container_health(
        None, now=NOW + timedelta(days=60), probe_output=PROBE
    )
    assert [f.kind for f in result.findings] == []
    assert len(result.detail["oom_events_all_boots"]) == 3
    assert result.detail["oom_events_in_window"] == []


def test_a_missing_governed_container_is_a_breach():
    trimmed = PROBE.replace("analytics-dashboard-6x-trino-1|running|0|false\n", "")
    result = check_container_health(None, now=NOW, probe_output=trimmed)
    assert "container_absent" in [f.kind for f in result.findings]


def test_probe_refuses_any_host_but_the_declared_one():
    """A health monitor that can be pointed at an arbitrary instance by a
    malformed event is a remote-execution surface, not an instrument."""
    with pytest.raises(ValueError):
        run_host_probe(None, instance_id="i-000000000000deadb")


def test_a_failed_probe_is_an_error_state_not_a_healthy_one():
    class Boom:
        def send_command(self, **kwargs):
            raise RuntimeError("AccessDenied")

    result = check_container_health(Boom(), now=NOW)
    assert result.error is not None
    assert result.severity == "error"
    assert result.findings == []


# ---------------------------------------------------------------------------
# Check 7 -- the empty case
# ---------------------------------------------------------------------------


class FakeS3Objects:
    def __init__(self, sizes):
        self.sizes = sizes

    def list_objects_v2(self, **kwargs):
        return {
            "Contents": [{"Key": "adhoc/%d" % i, "Size": s} for i, s in enumerate(self.sizes)],
            "IsTruncated": False,
        }


class FakeGlueTables:
    def __init__(self, names):
        self.names = names

    def get_tables(self, **kwargs):
        return {"TableList": [{"Name": n} for n in self.names]}


def test_empty_adhoc_namespace_reports_zero_without_dividing_by_zero():
    result = check_adhoc_quota(FakeS3Objects([]), FakeGlueTables([]))
    assert result.findings == []
    assert result.detail["empty"] is True
    assert result.detail["byte_utilisation"] == 0.0
    assert result.detail["object_utilisation"] == 0.0


def test_quota_breach_and_warning_bands():
    warn = check_adhoc_quota(FakeS3Objects([1] * 4200), FakeGlueTables([]))
    assert [f.kind for f in warn.findings] == ["adhoc_quota_approaching"]
    assert warn.findings[0].severity == "warning"

    over = check_adhoc_quota(FakeS3Objects([1] * 5100), FakeGlueTables([]))
    assert [f.kind for f in over.findings] == ["adhoc_quota_exceeded"]
    assert over.findings[0].severity == "breach"


def test_quota_finding_says_the_number_is_awaiting_review():
    over = check_adhoc_quota(FakeS3Objects([1] * 5100), FakeGlueTables([]))
    assert "awaiting io's review" in over.findings[0].remediation


# ---------------------------------------------------------------------------
# Check 8 -- economic, not performance
# ---------------------------------------------------------------------------


class FakeCw:
    def __init__(self, series):
        self.series = series

    def get_metric_statistics(self, **kwargs):
        stat = kwargs["Statistics"][0]
        values = self.series.get(kwargs["MetricName"], [])
        return {
            "Datapoints": [
                {"Timestamp": NOW + timedelta(minutes=5 * i), stat: v}
                for i, v in enumerate(values)
            ]
        }


class FakeEc2Credits:
    def __init__(self, mode="unlimited"):
        self.mode = mode

    def describe_instance_credit_specifications(self, **kwargs):
        if self.mode is None:
            return {"InstanceCreditSpecifications": [{}]}
        return {"InstanceCreditSpecifications": [{"CpuCredits": self.mode}]}


def test_healthy_credit_state_produces_no_finding():
    cw = FakeCw({
        "CPUCreditBalance": [644.0] * 12,
        "CPUCreditUsage": [2.9] * 12,
        "CPUSurplusCreditsCharged": [0.0] * 24,
    })
    result = check_cpu_credit(cw, FakeEc2Credits(), now=NOW)
    assert result.findings == []
    assert result.detail["economic_not_performance"] is True


def test_t1_surplus_charged_is_the_breach_and_t2_is_only_a_warning():
    """With CpuCredits=unlimited the balance reaching zero does not throttle, it
    BILLS. T1 is therefore the economically meaningful trigger; T2 is the
    leading indicator that should prompt investigation before T1 costs money."""
    cw = FakeCw({
        "CPUCreditBalance": [10.0] * 6,
        "CPUCreditUsage": [1.0] * 12,
        "CPUSurplusCreditsCharged": [1.0, 1.0, 1.0] + [0.0] * 21,
    })
    result = check_cpu_credit(cw, FakeEc2Credits(), now=NOW)
    kinds = {f.kind: f.severity for f in result.findings}
    assert kinds["cpu_surplus_charged"] == "breach"
    assert kinds["cpu_credit_balance_low"] == "warning"


def test_a_non_burstable_host_is_not_reported_as_healthy():
    result = check_cpu_credit(FakeCw({}), FakeEc2Credits(mode=None), now=NOW)
    assert result.detail["burstable"] is False
    assert result.subjects_examined == 0


# ---------------------------------------------------------------------------
# Check 9 -- drift against the declared surface
# ---------------------------------------------------------------------------

_DECLARED_DOC = {
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "glue:GetDatabase", "glue:GetDatabases", "glue:GetTable", "glue:GetTables",
                "glue:GetPartition", "glue:GetPartitions", "glue:BatchGetPartition",
                "s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation", "s3:PutObject",
                "kms:Decrypt", "kms:GenerateDataKey",
            ],
            "Resource": "*",
        }
    ]
}


class FakeIam:
    def __init__(self, document, version="v11", attached=True):
        self.document = document
        self.version = version
        self.attached = attached

    def list_attached_role_policies(self, RoleName):  # noqa: N803
        if not self.attached:
            return {"AttachedPolicies": []}
        return {"AttachedPolicies": [
            {"PolicyName": "analytics-dashboard-data-access", "PolicyArn": "arn:aws:iam::1:policy/p"}
        ]}

    def get_policy(self, PolicyArn):  # noqa: N803
        return {"Policy": {"DefaultVersionId": self.version}}

    def get_policy_version(self, PolicyArn, VersionId):  # noqa: N803
        return {"PolicyVersion": {"Document": self.document}}


class FakeEc2Instance:
    def __init__(self, options=None):
        self.options = options or {
            "HttpTokens": "required", "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": 2
        }

    def describe_instances(self, InstanceIds):  # noqa: N803
        return {"Reservations": [{"Instances": [{"MetadataOptions": self.options}]}]}


def test_declared_surface_intact_produces_no_finding():
    result = check_dependency_drift(FakeIam(_DECLARED_DOC), FakeEc2Instance())
    assert result.findings == []


def test_a_severed_declared_action_is_a_breach():
    """The 2026-08-06 shape: the policy changed, nothing in the deploy tree
    changed, and the break was found six weeks later by accident."""
    stripped = {"Statement": [dict(_DECLARED_DOC["Statement"][0])]}
    stripped["Statement"][0]["Action"] = [
        a for a in _DECLARED_DOC["Statement"][0]["Action"] if a != "kms:Decrypt"
    ]
    result = check_dependency_drift(FakeIam(stripped), FakeEc2Instance())
    finding = next(f for f in result.findings if f.kind == "declared_iam_action_missing")
    assert finding.severity == "breach"
    assert finding.observed["missing"] == ["kms:Decrypt"]


def test_an_action_declared_absent_appearing_is_also_a_breach():
    """Drift runs in both directions. Their absence is a declared property of
    the estate, so their appearance is an out-of-band widening."""
    widened = {"Statement": [dict(_DECLARED_DOC["Statement"][0])]}
    widened["Statement"][0]["Action"] = (
        _DECLARED_DOC["Statement"][0]["Action"] + ["glue:CreateTable"]
    )
    result = check_dependency_drift(FakeIam(widened), FakeEc2Instance())
    finding = next(f for f in result.findings if f.kind == "declared_absent_action_granted")
    assert finding.severity == "breach"
    assert finding.observed["unexpectedly_granted"] == ["glue:CreateTable"]


def test_hop_limit_reduced_to_one_is_a_breach():
    """Load-bearing: reducing HttpPutResponseHopLimit to 1 severs all Glue and
    S3 access for both containers with NO change visible in the deploy tree."""
    result = check_dependency_drift(
        FakeIam(_DECLARED_DOC),
        FakeEc2Instance({"HttpTokens": "required", "HttpEndpoint": "enabled",
                         "HttpPutResponseHopLimit": 1}),
    )
    finding = next(f for f in result.findings if f.kind == "imds_posture_drift")
    assert finding.observed["HttpPutResponseHopLimit"] == {"observed": 1, "expected": 2}


def test_a_policy_version_bump_alone_is_a_warning_not_a_breach():
    result = check_dependency_drift(FakeIam(_DECLARED_DOC, version="v13"), FakeEc2Instance())
    assert [f.severity for f in result.findings] == ["warning"]
    assert result.findings[0].kind == "policy_version_changed"


def test_detaching_the_policy_is_a_breach():
    result = check_dependency_drift(
        FakeIam(_DECLARED_DOC, attached=False), FakeEc2Instance()
    )
    assert [f.kind for f in result.findings] == ["declared_policy_detached"]


def test_wildcards_grant_the_actions_they_cover():
    assert _action_granted("glue:GetTable", ["glue:*"])
    assert _action_granted("glue:GetTable", ["*"])
    assert _action_granted("glue:GetTable", ["glue:Get*"])
    assert not _action_granted("glue:GetTable", ["s3:*"])


def test_deny_statements_do_not_count_as_grants():
    doc = {"Statement": [{"Effect": "Deny", "Action": ["glue:CreateTable"], "Resource": "*"}]}
    assert _granted_actions(doc) == []
