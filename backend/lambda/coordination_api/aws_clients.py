"""aws_clients.py — Singleton AWS service clients (DynamoDB, SSM, EC2, EventBridge, SQS, SNS, etc.).

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import importlib.util
import logging
import os
import pathlib
from typing import Any, Dict, Optional, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

try:
    from mcp_client import CoordinationMcpClient
except ModuleNotFoundError:
    import importlib.util as _ilu
    _MCP_MODULE_PATH = pathlib.Path(__file__).with_name("mcp_client.py")
    _MCP_SPEC = _ilu.spec_from_file_location("coordination_mcp_client", _MCP_MODULE_PATH)
    if _MCP_SPEC is None or _MCP_SPEC.loader is None:
        raise
    _MCP_MODULE = _ilu.module_from_spec(_MCP_SPEC)
    _MCP_SPEC.loader.exec_module(_MCP_MODULE)
    CoordinationMcpClient = _MCP_MODULE.CoordinationMcpClient

from config import DYNAMODB_REGION, FEED_SUBSCRIPTIONS_TABLE, SECRETS_REGION, SSM_REGION, logger

__all__ = [
    "_cloudwatch_sequence_tokens",
    "_ddb",
    "_eb",
    "_ec2",
    "_feed_subscriptions_enabled",
    "_feed_subscriptions_table_available",
    "_get_ddb",
    "_get_eb",
    "_get_ec2",
    "_get_logs",
    "_get_secretsmanager",
    "_get_sns",
    "_get_sqs",
    "_get_ssm",
    "_logs",
    "_mcp",
    "_secretsmanager",
    "_sns",
    "_sqs",
    "_ssm",
]

# ---------------------------------------------------------------------------
# AWS client singletons
# ---------------------------------------------------------------------------

_ddb = None
_ssm = None
_ec2 = None
_eb = None
_sqs = None
_sns = None
_logs = None
_mcp = CoordinationMcpClient()
_secretsmanager = None
_cloudwatch_sequence_tokens: Dict[Tuple[str, str], str] = {}
_feed_subscriptions_table_available: Optional[bool] = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 5, "mode": "standard"}),
        )
    return _ddb


def _get_ssm():
    global _ssm
    if _ssm is None:
        _ssm = boto3.client(
            "ssm",
            region_name=SSM_REGION,
            config=Config(retries={"max_attempts": 5, "mode": "standard"}),
        )
    return _ssm


def _get_ec2():
    global _ec2
    if _ec2 is None:
        _ec2 = boto3.client(
            "ec2",
            region_name=SSM_REGION,
            config=Config(retries={"max_attempts": 5, "mode": "standard"}),
        )
    return _ec2


def _get_eb():
    global _eb
    if _eb is None:
        _eb = boto3.client(
            "events",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _eb


def _get_sqs():
    global _sqs
    if _sqs is None:
        _sqs = boto3.client(
            "sqs",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _sqs


def _get_sns():
    global _sns
    if _sns is None:
        _sns = boto3.client(
            "sns",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _sns


def _get_logs():
    global _logs
    if _logs is None:
        _logs = boto3.client(
            "logs",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _logs


def _feed_subscriptions_enabled() -> bool:
    global _feed_subscriptions_table_available
    if _feed_subscriptions_table_available is not None:
        return _feed_subscriptions_table_available

    if not FEED_SUBSCRIPTIONS_TABLE:
        _feed_subscriptions_table_available = False
        logger.info("[INFO] Feed subscription operations disabled: FEED_SUBSCRIPTIONS_TABLE unset.")
        return False

    try:
        _get_ddb().describe_table(TableName=FEED_SUBSCRIPTIONS_TABLE)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        if code == "ResourceNotFoundException":
            _feed_subscriptions_table_available = False
            logger.info(
                "[INFO] Feed subscription operations disabled: table '%s' not found.",
                FEED_SUBSCRIPTIONS_TABLE,
            )
            return False
        if code in {"AccessDeniedException", "UnauthorizedOperation"}:
            _feed_subscriptions_table_available = False
            logger.warning(
                "Feed subscription operations disabled: missing DescribeTable access for '%s'.",
                FEED_SUBSCRIPTIONS_TABLE,
            )
            return False
        raise

    _feed_subscriptions_table_available = True
    return True


def _get_secretsmanager():
    global _secretsmanager
    if _secretsmanager is None:
        _secretsmanager = boto3.client(
            "secretsmanager",
            region_name=SECRETS_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _secretsmanager


