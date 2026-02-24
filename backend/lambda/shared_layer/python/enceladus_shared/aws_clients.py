"""enceladus_shared.aws_clients — Lazy-singleton AWS service clients.

Provides factory functions that create boto3 clients on first call and
cache them for subsequent invocations. This avoids paying the boto3 client
construction cost on cold starts until the client is actually needed.

Part of ENC-TSK-525: Extract shared Lambda layer.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple

import boto3
from botocore.config import Config

# ---------------------------------------------------------------------------
# Default region (overridable via env)
# ---------------------------------------------------------------------------

DYNAMODB_REGION: str = os.environ.get("DYNAMODB_REGION", "us-west-2")
SSM_REGION: str = os.environ.get("SSM_REGION", os.environ.get("DYNAMODB_REGION", "us-west-2"))
SECRETS_REGION: str = os.environ.get("SECRETS_REGION", os.environ.get("DYNAMODB_REGION", "us-west-2"))

# ---------------------------------------------------------------------------
# Client singletons
# ---------------------------------------------------------------------------

_ddb = None
_ssm = None
_ec2 = None
_eb = None
_sqs = None
_sns = None
_logs = None
_s3 = None
_secretsmanager = None


def _get_ddb(region: Optional[str] = None):
    """Get (or create) the DynamoDB client singleton."""
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb",
            region_name=region or DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 5, "mode": "standard"}),
        )
    return _ddb


def _get_ssm(region: Optional[str] = None):
    """Get (or create) the SSM client singleton."""
    global _ssm
    if _ssm is None:
        _ssm = boto3.client(
            "ssm",
            region_name=region or SSM_REGION,
            config=Config(retries={"max_attempts": 5, "mode": "standard"}),
        )
    return _ssm


def _get_ec2(region: Optional[str] = None):
    """Get (or create) the EC2 client singleton."""
    global _ec2
    if _ec2 is None:
        _ec2 = boto3.client(
            "ec2",
            region_name=region or SSM_REGION,
            config=Config(retries={"max_attempts": 5, "mode": "standard"}),
        )
    return _ec2


def _get_eb(region: Optional[str] = None):
    """Get (or create) the EventBridge client singleton."""
    global _eb
    if _eb is None:
        _eb = boto3.client(
            "events",
            region_name=region or DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _eb


def _get_sqs(region: Optional[str] = None):
    """Get (or create) the SQS client singleton."""
    global _sqs
    if _sqs is None:
        _sqs = boto3.client(
            "sqs",
            region_name=region or DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _sqs


def _get_sns(region: Optional[str] = None):
    """Get (or create) the SNS client singleton."""
    global _sns
    if _sns is None:
        _sns = boto3.client(
            "sns",
            region_name=region or DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _sns


def _get_logs(region: Optional[str] = None):
    """Get (or create) the CloudWatch Logs client singleton."""
    global _logs
    if _logs is None:
        _logs = boto3.client(
            "logs",
            region_name=region or DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _logs


def _get_s3(region: Optional[str] = None):
    """Get (or create) the S3 client singleton."""
    global _s3
    if _s3 is None:
        _s3 = boto3.client(
            "s3",
            region_name=region or DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _s3


def _get_secretsmanager(region: Optional[str] = None):
    """Get (or create) the Secrets Manager client singleton."""
    global _secretsmanager
    if _secretsmanager is None:
        _secretsmanager = boto3.client(
            "secretsmanager",
            region_name=region or SECRETS_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _secretsmanager
