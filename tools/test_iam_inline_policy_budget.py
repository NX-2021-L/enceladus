#!/usr/bin/env python3
"""Unit tests for tools/iam_inline_policy_budget.py — ENC-TSK-P99 / ENC-ISS-775."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import iam_inline_policy_budget as budget  # noqa: E402


# --- fixtures ---------------------------------------------------------------

POLICY_A = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AppConfigOps",
            "Effect": "Allow",
            "Action": ["appconfig:GetConfiguration", "appconfig:StartDeployment"],
            "Resource": "*",
        }
    ],
}

POLICY_B = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EventBridgeOps",
            "Effect": "Allow",
            "Action": ["events:ListRules", "events:PutRule", "events:DescribeRule"],
            "Resource": [
                "arn:aws:events:us-west-2:356364570033:rule/enceladus-*",
            ],
        }
    ],
}

POLICY_C = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SchedulerOps",
            "Effect": "Allow",
            "Action": "scheduler:GetSchedule",
            "Resource": "*",
        }
    ],
}

POLICY_D = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "GammaCloudWatchDashboardBootstrap",
            "Effect": "Allow",
            "Action": [
                "cloudwatch:PutDashboard",
                "cloudwatch:GetDashboard",
                "cloudwatch:DeleteDashboards",
                "cloudwatch:ListDashboards",
            ],
            "Resource": "arn:aws:cloudwatch::356364570033:dashboard/enceladus-v4-architecture-gamma",
        }
    ],
}

FIXTURE_POLICIES = {
    "enceladus-cfn-deploy-appconfig-v1": POLICY_A,
    "enceladus-cfn-deploy-eventbridge-v1": POLICY_B,
    "enceladus-cfn-deploy-scheduler-v1": POLICY_C,
    "enceladus-cfn-deploy-gamma-cloudwatch-dashboard-v1": POLICY_D,
}


def fixture_fetcher(role: str):
    assert role == "enceladus-cloudformation-deploy-github-role"
    return dict(FIXTURE_POLICIES)


def _expected_size(doc: dict) -> int:
    compact = json.dumps(doc, separators=(",", ":"))
    return len(re.sub(r"\s", "", compact))


# --- size rule ---------------------------------------------------------------


def test_policy_size_matches_whitespace_stripped_compact_json():
    for doc in (POLICY_A, POLICY_B, POLICY_C, POLICY_D):
        assert budget.policy_size(doc) == _expected_size(doc)


def test_policy_size_ignores_key_order_whitespace_variance():
    spaced = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AppConfigOps",
                "Effect": "Allow",
                "Action": ["appconfig:GetConfiguration", "appconfig:StartDeployment"],
                "Resource": "*",
            }
        ],
    }
    # Same structure/content as POLICY_A -> identical size regardless of the
    # dict object identity or incidental formatting differences upstream.
    assert budget.policy_size(spaced) == budget.policy_size(POLICY_A)


# --- ordering + headroom math -------------------------------------------------


def test_compute_budget_orders_sizes_descending():
    result = budget.compute_budget(FIXTURE_POLICIES, limit=budget.DEFAULT_LIMIT)
    sizes = result["sizes"]
    assert [name for name, _ in sizes] == sorted(
        FIXTURE_POLICIES, key=lambda n: (-budget.policy_size(FIXTURE_POLICIES[n]), n)
    )
    # strictly non-increasing
    values = [size for _, size in sizes]
    assert values == sorted(values, reverse=True)


def test_compute_budget_total_and_headroom():
    limit = 10240
    result = budget.compute_budget(FIXTURE_POLICIES, limit=limit)
    expected_total = sum(budget.policy_size(d) for d in FIXTURE_POLICIES.values())
    assert result["total"] == expected_total
    assert result["headroom"] == limit - expected_total


def test_headroom_can_go_negative_when_over_limit():
    tiny_limit = 5
    result = budget.compute_budget(FIXTURE_POLICIES, limit=tiny_limit)
    assert result["headroom"] < 0
    assert result["total"] > tiny_limit


# --- merge delta + fits/does-not-fit exit behaviour --------------------------


def test_merge_onto_existing_policy_computes_delta_and_fits():
    # Replacing the gamma dashboard policy with a slightly larger merged doc
    # that still fits comfortably within a generous limit.
    merged_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CloudWatchDashboardOps",
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:PutDashboard",
                    "cloudwatch:GetDashboard",
                    "cloudwatch:DeleteDashboards",
                    "cloudwatch:ListDashboards",
                ],
                "Resource": [
                    "arn:aws:cloudwatch::356364570033:dashboard/enceladus-v4-architecture-gamma",
                    "arn:aws:cloudwatch::356364570033:dashboard/enceladus-v4-architecture",
                ],
            }
        ],
    }
    result = budget.compute_budget(
        FIXTURE_POLICIES,
        limit=10240,
        merge_policy="enceladus-cfn-deploy-gamma-cloudwatch-dashboard-v1",
        merge_document=merged_doc,
    )
    existing_size = budget.policy_size(POLICY_D)
    merged_size = budget.policy_size(merged_doc)
    assert result["existing_size"] == existing_size
    assert result["merged_size"] == merged_size
    assert result["delta"] == merged_size - existing_size
    assert result["fits"] is True


def test_merge_that_exceeds_headroom_does_not_fit():
    # Nearly-full budget: headroom is small, so even a modest merged doc
    # blows through it.
    tight_limit = budget.compute_budget(FIXTURE_POLICIES, limit=budget.DEFAULT_LIMIT)[
        "total"
    ] + 5
    huge_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Huge",
                "Effect": "Allow",
                "Action": ["s3:GetObject"] * 200,
                "Resource": "*",
            }
        ],
    }
    result = budget.compute_budget(
        FIXTURE_POLICIES,
        limit=tight_limit,
        merge_policy="enceladus-cfn-deploy-gamma-cloudwatch-dashboard-v1",
        merge_document=huge_doc,
    )
    assert result["fits"] is False


def test_merge_onto_missing_policy_name_delta_is_full_size():
    new_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BrandNew",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
            }
        ],
    }
    result = budget.compute_budget(
        FIXTURE_POLICIES,
        limit=budget.DEFAULT_LIMIT,
        merge_policy="enceladus-cfn-deploy-does-not-exist-v1",
        merge_document=new_doc,
    )
    assert result["existing_size"] == 0
    assert result["merged_size"] == budget.policy_size(new_doc)
    assert result["delta"] == budget.policy_size(new_doc)


# --- CLI exit-code behaviour via main() with an injected fetcher ------------


def test_main_exits_zero_without_merge_policy(capsys):
    rc = budget.main(
        ["--role", "enceladus-cloudformation-deploy-github-role"],
        fetcher=fixture_fetcher,
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "BUDGET total=" in out
    assert "fits=n/a" in out


def test_main_exits_zero_when_merge_fits(tmp_path, capsys):
    merged_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CloudWatchDashboardOps",
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:PutDashboard",
                    "cloudwatch:GetDashboard",
                    "cloudwatch:DeleteDashboards",
                    "cloudwatch:ListDashboards",
                ],
                "Resource": [
                    "arn:aws:cloudwatch::356364570033:dashboard/enceladus-v4-architecture-gamma",
                    "arn:aws:cloudwatch::356364570033:dashboard/enceladus-v4-architecture",
                ],
            }
        ],
    }
    doc_path = tmp_path / "merged.json"
    doc_path.write_text(json.dumps(merged_doc))

    rc = budget.main(
        [
            "--role",
            "enceladus-cloudformation-deploy-github-role",
            "--merge-policy",
            "enceladus-cfn-deploy-gamma-cloudwatch-dashboard-v1",
            "--merge-document",
            str(doc_path),
        ],
        fetcher=fixture_fetcher,
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "fits=true" in out


def test_main_exits_one_when_merge_does_not_fit(tmp_path, capsys):
    huge_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Huge",
                "Effect": "Allow",
                "Action": ["s3:GetObject"] * 2000,
                "Resource": "*",
            }
        ],
    }
    doc_path = tmp_path / "huge.json"
    doc_path.write_text(json.dumps(huge_doc))

    rc = budget.main(
        [
            "--role",
            "enceladus-cloudformation-deploy-github-role",
            "--merge-policy",
            "enceladus-cfn-deploy-gamma-cloudwatch-dashboard-v1",
            "--merge-document",
            str(doc_path),
            "--limit",
            "1000",
        ],
        fetcher=fixture_fetcher,
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "fits=false" in out


def test_main_requires_merge_document_with_merge_policy():
    try:
        budget.main(
            [
                "--role",
                "enceladus-cloudformation-deploy-github-role",
                "--merge-policy",
                "enceladus-cfn-deploy-gamma-cloudwatch-dashboard-v1",
            ],
            fetcher=fixture_fetcher,
        )
        assert False, "expected SystemExit from argparse.error"
    except SystemExit as exc:
        assert exc.code == 2
