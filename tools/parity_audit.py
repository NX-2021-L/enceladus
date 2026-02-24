#!/usr/bin/env python3
"""Nightly Enceladus AWS parity audit (ENC-TSK-508).

Inventory scope:
  - Lambda (us-west-2 + us-east-1)
  - DynamoDB tables
  - S3 buckets
  - SQS queues
  - SNS topics
  - EventBridge rules
  - EventBridge Pipes
  - API Gateway HTTP APIs

Parity scope:
  - Downloads live Lambda code for mapped functions
  - Hashes mapped entry file from live zip and repo source
  - Flags MATCH / DIFF / missing coverage
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import boto3
from botocore.exceptions import ClientError


DEFAULT_MAP_FILE = "infrastructure/parity/lambda_function_map.json"
DEFAULT_OUTPUT_DIR = "infrastructure/parity/out"
DEFAULT_REGIONS = ("us-west-2", "us-east-1")
DEFAULT_FILTER_REGEX = r"(devops|enceladus|coordination-requests|documents|projects)"


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _json_write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _iter_pages(func):
    marker = None
    while True:
        kwargs = {}
        if marker:
            kwargs["NextToken"] = marker
        resp = func(**kwargs)
        yield resp
        marker = resp.get("NextToken")
        if not marker:
            break


def _resource_matches(name: str, resource_re: re.Pattern[str], include_names: set[str]) -> bool:
    return name in include_names or bool(resource_re.search(name))


def _is_access_denied(err: ClientError) -> bool:
    code = str(err.response.get("Error", {}).get("Code", "")).strip().lower()
    if not code:
        return False
    return any(
        token in code
        for token in (
            "accessdenied",
            "unauthorized",
            "notauthorized",
            "authorizationerror",
            "forbidden",
        )
    )


def _append_inventory_warning(
    inventory: Dict[str, Any],
    *,
    service: str,
    operation: str,
    exc: ClientError,
    region: str = "",
) -> None:
    warning = {
        "service": service,
        "operation": operation,
        "error_code": str(exc.response.get("Error", {}).get("Code", "")),
        "message": str(exc.response.get("Error", {}).get("Message", "")),
    }
    if region:
        warning["region"] = region
    inventory.setdefault("inventory_warnings", []).append(warning)


def _inventory_resources(
    regions: Iterable[str],
    resource_re: re.Pattern[str],
    include_names: set[str],
) -> Dict[str, Any]:
    inventory: Dict[str, Any] = {
        "generated_at": _utc_now(),
        "regions": list(regions),
        "filter_regex": resource_re.pattern,
        "forced_include_names": sorted(include_names),
        "dynamodb_tables": [],
        "s3_buckets": [],
        "sqs_queues": [],
        "sns_topics": [],
        "eventbridge_rules": [],
        "eventbridge_pipes": [],
        "apigw_v2_apis": [],
        "lambda_functions": [],
        "inventory_warnings": [],
    }

    # S3 is global.
    s3 = boto3.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            name = str(b.get("Name") or "")
            if _resource_matches(name, resource_re, include_names):
                inventory["s3_buckets"].append({"name": name, "created": str(b.get("CreationDate") or "")})
    except ClientError as exc:
        if _is_access_denied(exc):
            _append_inventory_warning(
                inventory,
                service="s3",
                operation="ListBuckets",
                exc=exc,
            )
        else:
            raise

    for region in regions:
        ddb = boto3.client("dynamodb", region_name=region)
        sqs = boto3.client("sqs", region_name=region)
        sns = boto3.client("sns", region_name=region)
        events = boto3.client("events", region_name=region)
        pipes = boto3.client("pipes", region_name=region)
        apigw = boto3.client("apigatewayv2", region_name=region)
        lam = boto3.client("lambda", region_name=region)

        # DynamoDB
        try:
            start = None
            while True:
                kwargs = {}
                if start:
                    kwargs["ExclusiveStartTableName"] = start
                resp = ddb.list_tables(**kwargs)
                for table in resp.get("TableNames", []):
                    if _resource_matches(table, resource_re, include_names):
                        inventory["dynamodb_tables"].append({"region": region, "name": table})
                start = resp.get("LastEvaluatedTableName")
                if not start:
                    break
        except ClientError as exc:
            if _is_access_denied(exc):
                _append_inventory_warning(
                    inventory,
                    service="dynamodb",
                    operation="ListTables",
                    exc=exc,
                    region=region,
                )
            else:
                raise

        # SQS
        try:
            next_token = None
            while True:
                kwargs = {"MaxResults": 1000}
                if next_token:
                    kwargs["NextToken"] = next_token
                resp = sqs.list_queues(**kwargs)
                for url in resp.get("QueueUrls", []):
                    name = url.rsplit("/", 1)[-1]
                    if _resource_matches(name, resource_re, include_names):
                        inventory["sqs_queues"].append({"region": region, "name": name, "url": url})
                next_token = resp.get("NextToken")
                if not next_token:
                    break
        except ClientError as exc:
            if _is_access_denied(exc):
                _append_inventory_warning(
                    inventory,
                    service="sqs",
                    operation="ListQueues",
                    exc=exc,
                    region=region,
                )
            else:
                raise

        # SNS
        try:
            token = None
            while True:
                kwargs = {}
                if token:
                    kwargs["NextToken"] = token
                resp = sns.list_topics(**kwargs)
                for topic in resp.get("Topics", []):
                    arn = str(topic.get("TopicArn") or "")
                    name = arn.rsplit(":", 1)[-1]
                    if _resource_matches(name, resource_re, include_names):
                        inventory["sns_topics"].append({"region": region, "name": name, "arn": arn})
                token = resp.get("NextToken")
                if not token:
                    break
        except ClientError as exc:
            if _is_access_denied(exc):
                _append_inventory_warning(
                    inventory,
                    service="sns",
                    operation="ListTopics",
                    exc=exc,
                    region=region,
                )
            else:
                raise

        # EventBridge rules
        try:
            token = None
            while True:
                kwargs = {}
                if token:
                    kwargs["NextToken"] = token
                resp = events.list_rules(**kwargs)
                for rule in resp.get("Rules", []):
                    name = str(rule.get("Name") or "")
                    if _resource_matches(name, resource_re, include_names):
                        inventory["eventbridge_rules"].append(
                            {"region": region, "name": name, "arn": str(rule.get("Arn") or "")}
                        )
                token = resp.get("NextToken")
                if not token:
                    break
        except ClientError as exc:
            if _is_access_denied(exc):
                _append_inventory_warning(
                    inventory,
                    service="events",
                    operation="ListRules",
                    exc=exc,
                    region=region,
                )
            else:
                raise

        # EventBridge pipes
        try:
            token = None
            while True:
                kwargs = {}
                if token:
                    kwargs["NextToken"] = token
                resp = pipes.list_pipes(**kwargs)
                for pipe in resp.get("Pipes", []):
                    name = str(pipe.get("Name") or "")
                    if _resource_matches(name, resource_re, include_names):
                        inventory["eventbridge_pipes"].append(
                            {"region": region, "name": name, "arn": str(pipe.get("Arn") or "")}
                        )
                token = resp.get("NextToken")
                if not token:
                    break
        except ClientError as exc:
            if _is_access_denied(exc):
                _append_inventory_warning(
                    inventory,
                    service="pipes",
                    operation="ListPipes",
                    exc=exc,
                    region=region,
                )
            else:
                raise

        # API Gateway v2
        try:
            token = None
            while True:
                kwargs = {"MaxResults": "500"}
                if token:
                    kwargs["NextToken"] = token
                resp = apigw.get_apis(**kwargs)
                for api in resp.get("Items", []):
                    name = str(api.get("Name") or "")
                    api_id = str(api.get("ApiId") or "")
                    if _resource_matches(name, resource_re, include_names) or _resource_matches(api_id, resource_re, include_names):
                        inventory["apigw_v2_apis"].append(
                            {"region": region, "name": name, "api_id": api_id, "protocol_type": str(api.get("ProtocolType") or "")}
                        )
                token = resp.get("NextToken")
                if not token:
                    break
        except ClientError as exc:
            if _is_access_denied(exc):
                _append_inventory_warning(
                    inventory,
                    service="apigatewayv2",
                    operation="GetApis",
                    exc=exc,
                    region=region,
                )
            else:
                raise

        # Lambda inventory
        try:
            marker = None
            while True:
                kwargs = {}
                if marker:
                    kwargs["Marker"] = marker
                resp = lam.list_functions(**kwargs)
                for fn in resp.get("Functions", []):
                    name = str(fn.get("FunctionName") or "")
                    if _resource_matches(name, resource_re, include_names):
                        inventory["lambda_functions"].append(
                            {
                                "region": region,
                                "name": name,
                                "runtime": str(fn.get("Runtime") or ""),
                                "last_modified": str(fn.get("LastModified") or ""),
                                "code_sha256": str(fn.get("CodeSha256") or ""),
                            }
                        )
                marker = resp.get("NextMarker")
                if not marker:
                    break
        except ClientError as exc:
            if _is_access_denied(exc):
                _append_inventory_warning(
                    inventory,
                    service="lambda",
                    operation="ListFunctions",
                    exc=exc,
                    region=region,
                )
            else:
                raise

    return inventory


def _find_entry_in_zip(zip_path: Path, entry_file: str) -> Tuple[str, bytes]:
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        if entry_file in names:
            payload = zf.read(entry_file)
            return entry_file, payload

        # Fallback: match by basename.
        basename = entry_file.rsplit("/", 1)[-1]
        candidates = [name for name in names if name.rsplit("/", 1)[-1] == basename]
        if len(candidates) == 1:
            payload = zf.read(candidates[0])
            return candidates[0], payload
        if len(candidates) > 1:
            candidates = sorted(candidates, key=lambda value: (value.count("/"), len(value)))
            payload = zf.read(candidates[0])
            return candidates[0], payload

    raise FileNotFoundError(f"entry file '{entry_file}' not found in zip")


def _download_code_zip(code_url: str, target_zip: Path) -> None:
    try:
        with urllib.request.urlopen(code_url, timeout=30) as resp:
            payload = resp.read()
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", None)
        should_retry_insecure = isinstance(reason, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(exc)
        if not should_retry_insecure:
            raise
        # Some runner/local environments miss CA roots for presigned URLs.
        # Fallback keeps audit coverage deterministic.
        context = ssl._create_unverified_context()
        with urllib.request.urlopen(code_url, timeout=30, context=context) as resp:
            payload = resp.read()
    target_zip.write_bytes(payload)


def _audit_lambda_parity(
    mappings: List[Dict[str, str]],
    repo_root: Path,
) -> Dict[str, Any]:
    temp_dir = Path(tempfile.mkdtemp(prefix="enceladus-parity-"))
    results: List[Dict[str, Any]] = []
    stats = {
        "MATCH": 0,
        "DIFF": 0,
        "MISSING_LIVE_FUNCTION": 0,
        "MISSING_REPO_ENTRY": 0,
        "MISSING_LIVE_ENTRY": 0,
        "ERROR": 0,
    }

    try:
        for mapping in mappings:
            fn = str(mapping.get("function_name") or "")
            region = str(mapping.get("region") or "us-west-2")
            repo_entry = str(mapping.get("repo_entry_path") or "")
            entry_file = str(mapping.get("entry_file") or "")

            result: Dict[str, Any] = {
                "function_name": fn,
                "region": region,
                "repo_entry_path": repo_entry,
                "entry_file": entry_file,
                "status": "",
            }

            local_path = repo_root / repo_entry
            if not local_path.exists():
                result["status"] = "MISSING_REPO_ENTRY"
                stats["MISSING_REPO_ENTRY"] += 1
                results.append(result)
                continue

            result["repo_entry_sha256"] = _sha256_file(local_path)

            lam = boto3.client("lambda", region_name=region)
            try:
                live = lam.get_function(FunctionName=fn)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    result["status"] = "MISSING_LIVE_FUNCTION"
                    stats["MISSING_LIVE_FUNCTION"] += 1
                    results.append(result)
                    continue
                raise

            cfg = live.get("Configuration", {})
            code = live.get("Code", {})
            code_url = str(code.get("Location") or "")
            result["live_function_arn"] = str(cfg.get("FunctionArn") or "")
            result["live_runtime"] = str(cfg.get("Runtime") or "")
            result["live_handler"] = str(cfg.get("Handler") or "")
            result["live_code_sha256"] = str(cfg.get("CodeSha256") or "")

            if not code_url:
                result["status"] = "ERROR"
                result["error"] = "Missing code location URL"
                stats["ERROR"] += 1
                results.append(result)
                continue

            zip_path = temp_dir / f"{fn}-{region}.zip"
            _download_code_zip(code_url, zip_path)
            try:
                matched_entry, live_payload = _find_entry_in_zip(zip_path, entry_file)
            except FileNotFoundError as exc:
                result["status"] = "MISSING_LIVE_ENTRY"
                result["error"] = str(exc)
                stats["MISSING_LIVE_ENTRY"] += 1
                results.append(result)
                continue

            result["live_entry_path"] = matched_entry
            result["live_entry_sha256"] = _sha256_bytes(live_payload)
            if result["live_entry_sha256"] == result["repo_entry_sha256"]:
                result["status"] = "MATCH"
                stats["MATCH"] += 1
            else:
                result["status"] = "DIFF"
                stats["DIFF"] += 1
            results.append(result)

    except Exception as exc:
        stats["ERROR"] += 1
        results.append({"status": "ERROR", "error": str(exc)})
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return {"generated_at": _utc_now(), "results": results, "stats": stats}


def _emit_markdown_summary(
    output_path: Path,
    parity: Dict[str, Any],
    inventory: Dict[str, Any],
) -> None:
    stats = parity.get("stats", {})
    lines = [
        "# Enceladus Nightly Parity Audit",
        "",
        f"- Generated: {parity.get('generated_at')}",
        "",
        "## Lambda Parity",
        f"- MATCH: {stats.get('MATCH', 0)}",
        f"- DIFF: {stats.get('DIFF', 0)}",
        f"- MISSING_REPO_ENTRY: {stats.get('MISSING_REPO_ENTRY', 0)}",
        f"- MISSING_LIVE_FUNCTION: {stats.get('MISSING_LIVE_FUNCTION', 0)}",
        f"- MISSING_LIVE_ENTRY: {stats.get('MISSING_LIVE_ENTRY', 0)}",
        f"- ERROR: {stats.get('ERROR', 0)}",
        "",
        "## Inventory Counts",
        f"- Lambda functions (filtered): {len(inventory.get('lambda_functions', []))}",
        f"- DynamoDB tables (filtered): {len(inventory.get('dynamodb_tables', []))}",
        f"- S3 buckets (filtered): {len(inventory.get('s3_buckets', []))}",
        f"- SQS queues (filtered): {len(inventory.get('sqs_queues', []))}",
        f"- SNS topics (filtered): {len(inventory.get('sns_topics', []))}",
        f"- EventBridge rules (filtered): {len(inventory.get('eventbridge_rules', []))}",
        f"- EventBridge pipes (filtered): {len(inventory.get('eventbridge_pipes', []))}",
        f"- API Gateway v2 APIs (filtered): {len(inventory.get('apigw_v2_apis', []))}",
        "",
        "## Inventory Warnings",
        f"- Count: {len(inventory.get('inventory_warnings', []))}",
        "",
    ]

    warnings = inventory.get("inventory_warnings", [])
    if warnings:
        lines.append("### Warning Details")
        for warning in warnings:
            lines.append(
                "- "
                f"{warning.get('service', '?')}:{warning.get('operation', '?')} "
                f"{warning.get('error_code', '')} {warning.get('message', '')}".strip()
            )
        lines.append("")

    mismatches = [r for r in parity.get("results", []) if r.get("status") != "MATCH"]
    if mismatches:
        lines.append("## Action Required")
        for item in mismatches:
            lines.append(
                f"- {item.get('function_name', 'unknown')} [{item.get('region', '?')}]: {item.get('status')}"
            )
    else:
        lines.append("## Action Required")
        lines.append("- None")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _publish_sns_alert(sns_topic_arn: str, parity: Dict[str, Any], output_dir: Path) -> None:
    stats = parity.get("stats", {})
    failing = int(stats.get("DIFF", 0)) + int(stats.get("MISSING_REPO_ENTRY", 0)) + int(stats.get("MISSING_LIVE_FUNCTION", 0)) + int(stats.get("MISSING_LIVE_ENTRY", 0)) + int(stats.get("ERROR", 0))
    if failing <= 0:
        return
    sns = boto3.client("sns", region_name=sns_topic_arn.split(":")[3])
    message = (
        "Enceladus parity audit detected drift or coverage gaps.\n"
        f"Generated: {parity.get('generated_at')}\n"
        f"Stats: {json.dumps(stats, sort_keys=True)}\n"
        f"Output dir: {output_dir}"
    )
    sns.publish(
        TopicArn=sns_topic_arn,
        Subject="Enceladus Parity Audit Alert",
        Message=message,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Nightly Enceladus AWS parity audit")
    parser.add_argument("--map-file", default=DEFAULT_MAP_FILE)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--regions", default=",".join(DEFAULT_REGIONS))
    parser.add_argument("--filter-regex", default=DEFAULT_FILTER_REGEX)
    parser.add_argument("--sns-topic-arn", default=os.environ.get("PARITY_AUDIT_SNS_TOPIC_ARN", ""))
    parser.add_argument("--fail-on-drift", action=argparse.BooleanOptionalAction, default=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    output_dir = (repo_root / args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    regions = [item.strip() for item in str(args.regions).split(",") if item.strip()]
    resource_re = re.compile(args.filter_regex, re.IGNORECASE)

    map_path = (repo_root / args.map_file).resolve()
    if not map_path.exists():
        print(f"[ERROR] mapping file not found: {map_path}", file=sys.stderr)
        return 1

    mapping_payload = json.loads(map_path.read_text(encoding="utf-8"))
    mappings = mapping_payload.get("functions", [])
    if not isinstance(mappings, list) or not mappings:
        print(f"[ERROR] mapping file has no functions: {map_path}", file=sys.stderr)
        return 1

    include_names = {str(item.get("function_name") or "") for item in mappings if str(item.get("function_name") or "")}
    inventory = _inventory_resources(regions=regions, resource_re=resource_re, include_names=include_names)
    parity = _audit_lambda_parity(mappings=mappings, repo_root=repo_root)

    _json_write(output_dir / "resource_inventory.json", inventory)
    _json_write(output_dir / "lambda_parity.json", parity)
    _emit_markdown_summary(output_dir / "summary.md", parity=parity, inventory=inventory)

    if args.sns_topic_arn:
        _publish_sns_alert(args.sns_topic_arn, parity=parity, output_dir=output_dir)

    stats = parity.get("stats", {})
    failures = int(stats.get("DIFF", 0)) + int(stats.get("MISSING_REPO_ENTRY", 0)) + int(stats.get("MISSING_LIVE_FUNCTION", 0)) + int(stats.get("MISSING_LIVE_ENTRY", 0)) + int(stats.get("ERROR", 0))
    print(json.dumps({"output_dir": str(output_dir), "stats": stats}, indent=2, sort_keys=True))
    if args.fail_on_drift and failures > 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
