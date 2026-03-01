"""deploy_orchestrator/lambda_function.py

SQS FIFO-triggered Lambda that orchestrates deployments.

Triggered after the 60-second debounce window expires. Reads ALL pending
deployment requests for the project from DynamoDB and performs integration
analysis.

Execution branches:
- UI deployment types: resolve semver, write spec, start CodeBuild.
- Non-UI deployment types: validate service-group-specific config and write a
  queued_non_ui spec for downstream execution.

Flow:
    SQS FIFO (devops-deploy-queue.fifo, 60s visibility timeout)
    → This Lambda
    → Read pending requests from DDB
    → Integration analysis
    → Semver resolution
    → Write deployment spec to DDB
    → Start CodeBuild (devops-ui-deploy-builder)

Environment variables:
    DEPLOY_TABLE           default: devops-deployment-manager
    DEPLOY_REGION          default: us-west-2
    CONFIG_BUCKET          default: jreese-net
    CONFIG_PREFIX          default: deploy-config
    CODEBUILD_PROJECT      default: devops-ui-deploy-builder
    PROJECTS_TABLE         default: projects

Related: DVP-FTR-028
"""

from __future__ import annotations

import datetime as dt
import io
import json
import logging
import os
import re
import secrets
import time
import zipfile
from collections import defaultdict
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from boto3.dynamodb.types import TypeDeserializer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEPLOY_TABLE = os.environ.get("DEPLOY_TABLE", "devops-deployment-manager")
DEPLOY_REGION = os.environ.get("DEPLOY_REGION", "us-west-2")
CONFIG_BUCKET = os.environ.get("CONFIG_BUCKET", "jreese-net")
CONFIG_PREFIX = os.environ.get("CONFIG_PREFIX", "deploy-config")
CODEBUILD_PROJECT = os.environ.get("CODEBUILD_PROJECT", "devops-ui-deploy-builder")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
NON_UI_INLINE_LAMBDA_UPDATE = (
    os.environ.get("NON_UI_INLINE_LAMBDA_UPDATE", "true").strip().lower() not in {"0", "false", "no"}
)
DEFAULT_VERSION_FILE = os.environ.get("DEFAULT_VERSION_FILE", "frontend/ui/src/lib/version.ts")

UI_DEPLOYMENT_TYPES = {
    "github_public_static",
    "github_private_sst",
    "github_public_workers",
    "github_private_workers",
}
NON_UI_SERVICE_GROUP_BY_TYPE = {
    "lambda_update": "lambda",
    "lambda_layer": "lambda",
    "container_template": "container",
    "glue_crawler_update": "glue",
    "glue_job_update": "glue",
    "eventbridge_rule": "eventbridge",
    "s3_asset_sync": "s3",
    "cloudfront_config": "cloudfront",
    "step_function_update": "step_function",
}
SERVICE_GROUP_TARGET_ARN_PREFIXES = {
    "lambda": ("arn:aws:lambda:",),
    "container": ("arn:aws:ecs:", "arn:aws:ecr:", "arn:aws:codebuild:"),
    "glue": ("arn:aws:glue:",),
    "eventbridge": ("arn:aws:events:",),
    "s3": ("arn:aws:s3:::",),
    "cloudfront": ("arn:aws:cloudfront::",),
    "step_function": ("arn:aws:states:",),
}
SERVICE_GROUP_REQUIRED_CHECKS = {
    "lambda": {"cold_start_regression_check", "runtime_compatibility_check"},
    "container": {"image_architecture_check", "resource_limits_check"},
    "glue": {"timeout_config_check", "worker_type_check"},
    "eventbridge": {"schedule_safety_check"},
    "s3": {"bucket_policy_check"},
    "cloudfront": {"cache_behavior_check"},
    "step_function": {"state_machine_validation_check"},
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_deser = TypeDeserializer()

# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------

_ddb = None
_s3 = None
_cb = None
_lambda = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb", region_name=DEPLOY_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb


def _get_s3():
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3", region_name=DEPLOY_REGION)
    return _s3


def _get_codebuild():
    global _cb
    if _cb is None:
        _cb = boto3.client("codebuild", region_name=DEPLOY_REGION)
    return _cb


def _get_lambda():
    global _lambda
    if _lambda is None:
        _lambda = boto3.client(
            "lambda",
            region_name=DEPLOY_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _lambda


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ddb_deser(item: Dict) -> Dict[str, Any]:
    return {k: _deser.deserialize(v) for k, v in item.items()}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_now_compact() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def _get_pending_requests(project_id: str) -> List[Dict[str, Any]]:
    """Query all pending deployment requests for a project."""
    ddb = _get_ddb()
    results = []
    kwargs = {
        "TableName": DEPLOY_TABLE,
        "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :prefix)",
        "FilterExpression": "#st = :pending",
        "ExpressionAttributeNames": {"#st": "status"},
        "ExpressionAttributeValues": {
            ":pid": {"S": project_id},
            ":prefix": {"S": "request#"},
            ":pending": {"S": "pending"},
        },
    }
    while True:
        resp = ddb.query(**kwargs)
        results.extend([_ddb_deser(item) for item in resp.get("Items", [])])
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return sorted(results, key=lambda r: r.get("submitted_at", ""))


def _check_deploy_state(project_id: str) -> str:
    """Read the PAUSED/ACTIVE state from S3."""
    try:
        s3 = _get_s3()
        key = f"{CONFIG_PREFIX}/{project_id}/state.json"
        resp = s3.get_object(Bucket=CONFIG_BUCKET, Key=key)
        data = json.loads(resp["Body"].read().decode("utf-8"))
        return data.get("state", "ACTIVE")
    except ClientError:
        return "ACTIVE"


def _default_deploy_config(project_id: str) -> Dict[str, Any]:
    """Synthesize a minimal deploy config when deploy.json is missing."""
    return {
        "source": {
            "source_s3_bucket": CONFIG_BUCKET,
            "source_s3_prefix": f"deploy-sources/{project_id}",
        },
        "build": {
            "version_file": DEFAULT_VERSION_FILE,
        },
    }


def _read_project_deploy_config(project_id: str) -> Optional[Dict[str, Any]]:
    """Best-effort fallback for deploy config from projects table metadata."""
    try:
        ddb = _get_ddb()
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": project_id}},
        )
        item = resp.get("Item")
        if not item:
            return None
        project = _ddb_deser(item)
    except Exception:
        logger.warning("[WARNING] Failed reading project metadata for %s", project_id, exc_info=True)
        return None

    raw = project.get("deploy_config")
    config: Dict[str, Any] = {}
    if isinstance(raw, dict):
        config = raw
    elif isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                config = parsed
        except json.JSONDecodeError:
            logger.warning("[WARNING] Invalid deploy_config JSON for %s", project_id)

    parent_project = str(project.get("parent") or "").strip()
    default_source_prefix = f"deploy-sources/{parent_project}" if parent_project else f"deploy-sources/{project_id}"

    source = config.get("source")
    if not isinstance(source, dict):
        source = {}
        config["source"] = source
    if not source.get("source_s3_bucket"):
        source["source_s3_bucket"] = str(
            project.get("source_s3_bucket")
            or project.get("deploy_source_bucket")
            or CONFIG_BUCKET
        )
    if not source.get("source_s3_prefix"):
        source["source_s3_prefix"] = str(
            project.get("source_s3_prefix")
            or project.get("deploy_source_prefix")
            or default_source_prefix
        )

    build = config.get("build")
    if not isinstance(build, dict):
        build = {}
        config["build"] = build
    if not build.get("version_file"):
        build["version_file"] = str(
            project.get("version_file")
            or DEFAULT_VERSION_FILE
        )

    return config


def _read_deploy_config(project_id: str) -> Dict[str, Any]:
    """Read deploy config with fallbacks for missing deploy.json."""
    s3 = _get_s3()
    key = f"{CONFIG_PREFIX}/{project_id}/deploy.json"
    try:
        resp = s3.get_object(Bucket=CONFIG_BUCKET, Key=key)
        return json.loads(resp["Body"].read().decode("utf-8"))
    except ClientError as e:
        code = (e.response or {}).get("Error", {}).get("Code", "")
        if code not in {"NoSuchKey", "404", "NotFound"}:
            raise
        logger.warning(
            "[WARNING] Missing deploy config at s3://%s/%s for %s; falling back",
            CONFIG_BUCKET,
            key,
            project_id,
        )
    except json.JSONDecodeError:
        logger.warning(
            "[WARNING] Invalid deploy.json at s3://%s/%s for %s; falling back",
            CONFIG_BUCKET,
            key,
            project_id,
        )

    project_cfg = _read_project_deploy_config(project_id)
    if project_cfg:
        logger.info("[INFO] Using project metadata fallback deploy config for %s", project_id)
        return project_cfg

    logger.info("[INFO] Using synthesized default deploy config for %s", project_id)
    return _default_deploy_config(project_id)


def _get_current_version(project_id: str, config: Dict) -> str:
    """Read the current deployed version.

    Primary source: deploy-config/{project}/current-version.json (written by
    deploy_finalize after each successful deployment — DVP-TSK-323).

    Fallback: parse APP_VERSION from version.ts inside the latest source zip
    (legacy path retained for first-time bootstrapping or missing version file).
    """
    s3 = _get_s3()

    # --- Primary: current-version.json ---
    try:
        version_key = f"{CONFIG_PREFIX}/{project_id}/current-version.json"
        resp = s3.get_object(Bucket=CONFIG_BUCKET, Key=version_key)
        data = json.loads(resp["Body"].read().decode("utf-8"))
        version = data.get("version", "")
        if version and re.match(r"^\d+\.\d+\.\d+$", version):
            logger.info(f"[INFO] Current version from current-version.json: {version}")
            return version
        logger.warning(f"[WARNING] current-version.json has invalid version: {version!r}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            logger.info("[INFO] No current-version.json found — falling back to source zip")
        else:
            logger.warning(f"[WARNING] Failed to read current-version.json: {e}")
    except Exception as e:
        logger.warning(f"[WARNING] Unexpected error reading current-version.json: {e}")

    # --- Fallback: parse version.ts from latest source zip ---
    source_prefix = str(config.get("source", {}).get("source_s3_prefix", f"deploy-sources/{project_id}")).strip()
    source_bucket = str(config.get("source", {}).get("source_s3_bucket", CONFIG_BUCKET)).strip()
    version_file = config.get("build", {}).get("version_file", "")

    if not version_file:
        return "0.0.0"

    try:
        source_bucket, source_prefixes = _candidate_source_locations(
            project_id=project_id,
            preferred_bucket=source_bucket,
            preferred_prefix=source_prefix,
        )
        archive_keys = list(_iter_source_archive_keys(source_bucket, source_prefixes))
        if not archive_keys:
            logger.warning(
                "No source archives found at s3://%s/(%s)/",
                source_bucket,
                " | ".join(source_prefixes),
            )
            return "0.0.0"

        for key in archive_keys:
            logger.info("Source archive candidate (fallback): %s", key)
            obj = s3.get_object(Bucket=source_bucket, Key=key)
            with zipfile.ZipFile(io.BytesIO(obj["Body"].read())) as zf:
                if version_file not in zf.namelist():
                    continue
                content = zf.read(version_file).decode("utf-8")
                m = re.search(r"export\s+const\s+APP_VERSION\s*=\s*['\"](\d+\.\d+\.\d+)['\"]", content)
                if m:
                    return m.group(1)

    except Exception as e:
        logger.warning(f"Failed to read current version from source zip: {e}")

    return "0.0.0"


def _parse_semver(version_str: str) -> Tuple[int, int, int]:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version_str.strip())
    if not m:
        raise ValueError(f"Invalid semver: {version_str}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _resolve_version(current: str, requests: List[Dict]) -> Tuple[str, str]:
    """Resolve next version. Returns (new_version, change_type)."""
    major, minor, patch = _parse_semver(current)
    types = [r.get("change_type", "patch") for r in requests]

    if "major" in types:
        return f"{major + 1}.0.0", "major"
    elif "minor" in types:
        return f"{major}.{minor + 1}.0", "minor"
    else:
        return f"{major}.{minor}.{patch + 1}", "patch"


def _analyze_integration(requests: List[Dict]) -> Dict[str, Any]:
    """Lightweight integration analysis."""
    file_to_reqs: Dict[str, List[str]] = defaultdict(list)
    for req in requests:
        for f in req.get("files_changed", []):
            file_to_reqs[f].append(req.get("request_id", "unknown"))

    file_overlaps = [
        {"file": f, "request_ids": rids}
        for f, rids in file_to_reqs.items()
        if len(rids) > 1
    ]

    # Check related record conflicts
    record_to_summaries: Dict[str, List[str]] = defaultdict(list)
    for req in requests:
        for rid in req.get("related_record_ids", []):
            record_to_summaries[rid].append(req.get("summary", ""))

    warnings = []
    for overlap in file_overlaps:
        warnings.append(f"File '{overlap['file']}' modified by: {', '.join(overlap['request_ids'])}")
    for rid, sums in record_to_summaries.items():
        if len(sums) > 1:
            warnings.append(f"Record {rid} referenced by {len(sums)} requests")

    has_version_overlap = any("version.ts" in o["file"].lower() for o in file_overlaps)
    if has_version_overlap:
        warnings.append(
            "Detected overlapping version.ts updates across pending requests; "
            "continuing with warning to avoid deadlocking pending UI deployments."
        )

    return {
        "status": "warning" if warnings else "pass",
        "file_overlaps": file_overlaps,
        "warnings": warnings,
    }


def _aggregate_requests(requests: List[Dict]) -> Tuple[List[str], str, List[str]]:
    """Aggregate changes, summary, related IDs from requests."""
    all_changes = []
    summaries = []
    all_related: Set[str] = set()

    for req in requests:
        all_changes.extend(req.get("changes", []))
        s = req.get("summary", "")
        if s:
            summaries.append(s)
        for r in req.get("related_record_ids", []):
            all_related.add(r)

    agg_summary = "; ".join(summaries) if summaries else "Automated deployment"
    return all_changes, agg_summary, sorted(all_related)


def _resolve_batch_deployment_type(requests: List[Dict[str, Any]]) -> Optional[str]:
    types = {
        str(req.get("deployment_type") or "github_public_static").strip()
        for req in requests
        if req.get("request_id")
    }
    if not types:
        return "github_public_static"
    if len(types) > 1:
        logger.error("[ERROR] Mixed deployment types in one batch: %s", sorted(types))
        return None
    return next(iter(types))


def _group_requests_by_type(
    requests: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """Group pending requests by deployment_type so mixed batches can be
    processed in separate passes instead of being rejected outright."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for req in requests:
        if not req.get("request_id"):
            continue
        dtype = str(req.get("deployment_type") or "github_public_static").strip()
        groups.setdefault(dtype, []).append(req)
    return groups


def _parse_non_ui_config(req: Dict[str, Any]) -> Dict[str, Any]:
    raw = req.get("non_ui_config")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        raw = raw.strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _validate_non_ui_requests(
    deployment_type: str, requests: List[Dict[str, Any]]
) -> Tuple[bool, List[Dict[str, Any]], List[str]]:
    errors: List[str] = []
    targets: List[Dict[str, Any]] = []

    expected_group = NON_UI_SERVICE_GROUP_BY_TYPE.get(deployment_type)
    if not expected_group:
        return False, targets, [f"Unknown non-UI deployment_type: {deployment_type}"]

    for req in requests:
        req_id = req.get("request_id", "unknown")
        cfg = _parse_non_ui_config(req)
        if not cfg:
            errors.append(f"{req_id}: missing non_ui_config")
            continue

        service_group = str(cfg.get("service_group", "")).strip()
        if service_group != expected_group:
            errors.append(
                f"{req_id}: service_group '{service_group}' does not match expected '{expected_group}'"
            )
            continue

        target_arn = str(cfg.get("target_arn", "")).strip()
        if not target_arn:
            errors.append(f"{req_id}: missing non_ui_config.target_arn")
            continue
        expected_prefixes = SERVICE_GROUP_TARGET_ARN_PREFIXES.get(expected_group, ())
        if expected_prefixes and not any(target_arn.startswith(prefix) for prefix in expected_prefixes):
            errors.append(
                f"{req_id}: target_arn '{target_arn}' does not match expected prefixes "
                f"for service_group '{expected_group}'"
            )
            continue

        target_region = str(cfg.get("target_region", DEPLOY_REGION)).strip() or DEPLOY_REGION
        rollback_on_failure = bool(cfg.get("rollback_on_failure", True))
        validation_checks = cfg.get("validation_checks", [])
        if not isinstance(validation_checks, list):
            validation_checks = []
        validation_checks = [str(v).strip() for v in validation_checks if str(v).strip()]
        required_checks = SERVICE_GROUP_REQUIRED_CHECKS.get(expected_group, set())
        missing_checks = sorted(required_checks - set(validation_checks))
        if missing_checks:
            errors.append(
                f"{req_id}: missing required validation_checks for {expected_group}: "
                f"{', '.join(missing_checks)}"
            )
            continue

        hooks = req.get("pre_deploy_hooks", [])
        if isinstance(hooks, str):
            hooks = [hooks]
        if not isinstance(hooks, list):
            hooks = []
        hooks = [str(h).strip() for h in hooks if str(h).strip()]
        if "doc_prep" in hooks:
            raw_results = req.get("pre_deploy_results")
            parsed_results: List[Dict[str, Any]] = []
            if isinstance(raw_results, str):
                try:
                    loaded = json.loads(raw_results)
                    if isinstance(loaded, list):
                        parsed_results = [r for r in loaded if isinstance(r, dict)]
                except json.JSONDecodeError:
                    parsed_results = []
            elif isinstance(raw_results, list):
                parsed_results = [r for r in raw_results if isinstance(r, dict)]
            doc_prep_result = next((r for r in parsed_results if r.get("hook") == "doc_prep"), None)
            if not doc_prep_result or not bool(doc_prep_result.get("success")):
                errors.append(f"{req_id}: pre_deploy hook 'doc_prep' did not complete successfully")
                continue

        targets.append(
            {
                "request_id": req_id,
                "service_group": service_group,
                "target_arn": target_arn,
                "target_region": target_region,
                "rollback_on_failure": rollback_on_failure,
                "validation_checks": validation_checks,
                "source_s3_bucket": str(cfg.get("source_s3_bucket", "")).strip(),
                "source_s3_prefix": str(cfg.get("source_s3_prefix", "")).strip(),
                "source_dir": str(cfg.get("source_dir", "")).strip(),
            }
        )

    return len(errors) == 0, targets, errors


def _mark_requests(project_id: str, request_ids: List[str], status: str, spec_id: str = None):
    """Batch update request statuses."""
    ddb = _get_ddb()
    for rid in request_ids:
        expr = "SET #st = :status"
        names = {"#st": "status"}
        values = {":status": {"S": status}}
        if spec_id:
            expr += ", spec_id = :sid"
            values[":sid"] = {"S": spec_id}

        ddb.update_item(
            TableName=DEPLOY_TABLE,
            Key={"project_id": {"S": project_id}, "record_id": {"S": f"request#{rid}"}},
            UpdateExpression=expr,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )


def _write_spec(project_id: str, spec_id: str, status: str = "building", **kwargs) -> None:
    """Write a deployment spec to DDB."""
    ddb = _get_ddb()
    now = _utc_now()
    item = {
        "project_id": {"S": project_id},
        "record_id": {"S": f"spec#{spec_id}"},
        "spec_id": {"S": spec_id},
        "record_type": {"S": "spec"},
        "status": {"S": status},
        "created_at": {"S": now},
    }
    for k, v in kwargs.items():
        if isinstance(v, str):
            item[k] = {"S": v}
        elif isinstance(v, list):
            item[k] = {"L": [{"S": str(i)} for i in v]}
        elif isinstance(v, dict):
            item[k] = {"S": json.dumps(v)}
        elif isinstance(v, (int, float)):
            item[k] = {"N": str(v)}

    ddb.put_item(TableName=DEPLOY_TABLE, Item=item)


def _latest_source_archive_key(source_bucket: str, source_prefix: str) -> str:
    """Return latest source zip key under the prefix."""
    s3 = _get_s3()
    resp = s3.list_objects_v2(Bucket=source_bucket, Prefix=f"{source_prefix}/", MaxKeys=100)
    zips = [o for o in resp.get("Contents", []) if o["Key"].endswith(".zip")]
    if not zips:
        raise RuntimeError(f"No source archives found at s3://{source_bucket}/{source_prefix}/")
    return sorted(zips, key=lambda o: o["Key"], reverse=True)[0]["Key"]


def _normalize_source_prefix(prefix: str) -> str:
    return str(prefix or "").strip().strip("/")


def _candidate_source_locations(
    project_id: str,
    preferred_bucket: str,
    preferred_prefix: str,
) -> Tuple[str, List[str]]:
    """Build ordered source bucket/prefix candidates for archive lookup."""
    project_cfg = _read_project_deploy_config(project_id) or {}
    project_source = project_cfg.get("source", {}) if isinstance(project_cfg, dict) else {}

    bucket = (
        str(preferred_bucket or "").strip()
        or str(project_source.get("source_s3_bucket") or "").strip()
        or CONFIG_BUCKET
    )

    prefixes: List[str] = []

    def _add_prefix(value: Any) -> None:
        candidate = _normalize_source_prefix(str(value or ""))
        if candidate and candidate not in prefixes:
            prefixes.append(candidate)

    _add_prefix(preferred_prefix)
    _add_prefix(project_source.get("source_s3_prefix"))
    _add_prefix(f"deploy-sources/{project_id}")
    return bucket, prefixes


def _list_source_archive_keys(source_bucket: str, source_prefix: str) -> List[str]:
    s3 = _get_s3()
    resp = s3.list_objects_v2(Bucket=source_bucket, Prefix=f"{source_prefix}/", MaxKeys=100)
    zips = [str(obj.get("Key", "")) for obj in resp.get("Contents", []) if str(obj.get("Key", "")).endswith(".zip")]
    return sorted(zips, reverse=True)


def _iter_source_archive_keys(source_bucket: str, source_prefixes: List[str]) -> Iterator[str]:
    seen: Set[str] = set()
    for prefix in source_prefixes:
        for key in _list_source_archive_keys(source_bucket, prefix):
            if key in seen:
                continue
            seen.add(key)
            yield key


def _resolve_latest_source_archive(
    project_id: str,
    preferred_bucket: str,
    preferred_prefix: str,
) -> Tuple[str, str]:
    """Resolve latest archive key from preferred and fallback source prefixes."""
    source_bucket, source_prefixes = _candidate_source_locations(
        project_id=project_id,
        preferred_bucket=preferred_bucket,
        preferred_prefix=preferred_prefix,
    )
    for key in _iter_source_archive_keys(source_bucket, source_prefixes):
        return source_bucket, key

    raise RuntimeError(
        "No source archives found at "
        f"s3://{source_bucket}/({' | '.join(source_prefixes)})/"
    )


def _normalize_lambda_source_dir(target_arn: str, cfg: Dict[str, Any]) -> str:
    source_dir = str(cfg.get("source_dir", "")).strip()
    if source_dir:
        return source_dir.strip("/").replace("\\", "/")

    fn = str(target_arn).split(":function:")[-1].split(":")[0].strip()
    for prefix in ("devops-", "enceladus-"):
        if fn.startswith(prefix):
            fn = fn[len(prefix):]
            break
    return fn.replace("-", "_")


def _build_lambda_zip_from_source(project_id: str, target: Dict[str, Any]) -> bytes:
    """Build an in-memory Lambda package zip from latest source archive."""
    project_cfg = _read_project_deploy_config(project_id) or {}
    project_source = project_cfg.get("source", {}) if isinstance(project_cfg, dict) else {}
    preferred_bucket = (
        str(target.get("source_s3_bucket") or "").strip()
        or str(project_source.get("source_s3_bucket") or "").strip()
        or CONFIG_BUCKET
    )
    preferred_prefix = (
        str(target.get("source_s3_prefix") or "").strip()
        or str(project_source.get("source_s3_prefix") or "").strip()
        or f"deploy-sources/{project_id}"
    )
    source_bucket, source_prefixes = _candidate_source_locations(
        project_id=project_id,
        preferred_bucket=preferred_bucket,
        preferred_prefix=preferred_prefix,
    )
    source_dir = _normalize_lambda_source_dir(target.get("target_arn", ""), target)
    marker = f"backend/lambda/{source_dir}/"

    s3 = _get_s3()
    archive_keys = list(_iter_source_archive_keys(source_bucket, source_prefixes))
    if not archive_keys:
        raise RuntimeError(
            "No source archives found at "
            f"s3://{source_bucket}/({' | '.join(source_prefixes)})/"
        )

    attempted: List[str] = []
    for source_key in archive_keys:
        attempted.append(source_key)
        logger.info("[INFO] Building inline Lambda package from s3://%s/%s (%s)", source_bucket, source_key, marker)
        src_obj = s3.get_object(Bucket=source_bucket, Key=source_key)

        written = 0
        out_bytes = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(src_obj["Body"].read())) as source_zip:
            with zipfile.ZipFile(out_bytes, mode="w", compression=zipfile.ZIP_DEFLATED) as out_zip:
                for name in source_zip.namelist():
                    idx = name.find(marker)
                    if idx < 0 or name.endswith("/"):
                        continue
                    rel = name[idx + len(marker):].strip("/")
                    if not rel:
                        continue
                    out_zip.writestr(rel, source_zip.read(name))
                    written += 1

        if written > 0:
            return out_bytes.getvalue()

    raise RuntimeError(
        f"No files found for source_dir '{source_dir}' in source archives "
        f"s3://{source_bucket}/({' | '.join(source_prefixes)})/; attempted keys: {attempted[:5]}"
    )


def _wait_for_lambda_update(function_name: str, timeout_seconds: int = 90) -> Tuple[str, str]:
    """Wait until Lambda update completes; returns (status, reason)."""
    client = _get_lambda()
    deadline = time.time() + timeout_seconds
    status = "InProgress"
    reason = ""
    while time.time() < deadline:
        cfg = client.get_function_configuration(FunctionName=function_name)
        status = str(cfg.get("LastUpdateStatus") or "")
        reason = str(cfg.get("LastUpdateStatusReason") or "")
        if status in {"Successful", "Failed"}:
            return status, reason
        time.sleep(2)
    return status, reason or "Timed out waiting for LastUpdateStatus terminal state"


def _execute_lambda_update_targets(project_id: str, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Execute lambda_update targets inline by pushing package zip to target Lambda."""
    client = _get_lambda()
    results: List[Dict[str, Any]] = []
    for target in targets:
        request_id = str(target.get("request_id") or "")
        target_arn = str(target.get("target_arn") or "")
        function_name = target_arn.split(":function:")[-1].split(":")[0] if ":function:" in target_arn else target_arn
        package_bytes = _build_lambda_zip_from_source(project_id, target)
        update_resp = client.update_function_code(
            FunctionName=target_arn,
            ZipFile=package_bytes,
            Publish=True,
        )
        version = str(update_resp.get("Version") or "")
        status, reason = _wait_for_lambda_update(function_name=function_name)
        result = {
            "request_id": request_id,
            "target_arn": target_arn,
            "version": version,
            "status": status,
            "reason": reason,
        }
        if status != "Successful":
            raise RuntimeError(f"Inline lambda_update failed for {target_arn}: {status} ({reason})")
        results.append(result)
    return results


def _is_retryable_inline_lambda_error(error_message: str) -> bool:
    """Classify inline lambda_update failures for requeue behavior."""
    terminal_markers = (
        "No source archives found",
        "No files found for source_dir",
    )
    return not any(marker in error_message for marker in terminal_markers)


def _start_codebuild(
    project_id: str,
    spec_id: str,
    config: Dict,
) -> str:
    """Start a CodeBuild build, returns build ID."""
    cb = _get_codebuild()
    source_prefix = str(config.get("source", {}).get("source_s3_prefix", f"deploy-sources/{project_id}")).strip()
    source_bucket = str(config.get("source", {}).get("source_s3_bucket", CONFIG_BUCKET)).strip()

    # Find latest source archive with fallback to parent/project metadata source prefixes.
    source_bucket, latest_key = _resolve_latest_source_archive(
        project_id=project_id,
        preferred_bucket=source_bucket,
        preferred_prefix=source_prefix,
    )
    logger.info(f"Starting CodeBuild with source: s3://{source_bucket}/{latest_key}")

    build_resp = cb.start_build(
        projectName=CODEBUILD_PROJECT,
        environmentVariablesOverride=[
            {"name": "DEPLOY_SPEC_ID", "value": spec_id, "type": "PLAINTEXT"},
            {"name": "DEPLOY_PROJECT_ID", "value": project_id, "type": "PLAINTEXT"},
            {"name": "DEPLOY_TABLE", "value": DEPLOY_TABLE, "type": "PLAINTEXT"},
            {"name": "DEPLOY_CONFIG_BUCKET", "value": CONFIG_BUCKET, "type": "PLAINTEXT"},
            {"name": "DEPLOY_CONFIG_PREFIX", "value": CONFIG_PREFIX, "type": "PLAINTEXT"},
            {"name": "DEPLOY_SOURCE_KEY", "value": f"{source_bucket}/{latest_key}", "type": "PLAINTEXT"},
        ],
    )

    build_id = build_resp["build"]["id"]
    logger.info(f"CodeBuild started: {build_id}")
    return build_id


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------


def handler(event: Dict[str, Any], context: Any) -> None:
    """SQS FIFO Lambda handler."""
    logger.info(f"deploy_orchestrator: received {len(event.get('Records', []))} SQS message(s)")

    # Extract project IDs from SQS messages
    project_ids: Set[str] = set()
    for record in event.get("Records", []):
        try:
            body = json.loads(record.get("body", "{}"))
            pid = body.get("project_id")
            if pid:
                project_ids.add(pid)
        except (json.JSONDecodeError, TypeError):
            logger.warning(f"Failed to parse SQS message body")

    if not project_ids:
        logger.warning("No valid project IDs found in SQS messages")
        return

    for project_id in project_ids:
        try:
            _orchestrate_deployment(project_id)
        except Exception as e:
            logger.error(f"Orchestration failed for {project_id}: {e}", exc_info=True)


def _orchestrate_deployment(project_id: str) -> None:
    """Orchestrate a deployment for a single project.

    When pending requests span multiple deployment types (e.g. a
    ``github_public_static`` UI deploy **and** a ``lambda_update`` in the same
    batch), the orchestrator processes each type in a separate pass rather than
    rejecting the entire batch.  This prevents a deadlock where neither type
    can proceed.
    """
    logger.info(f"[START] Orchestrating deployment for project: {project_id}")

    # Check state — don't deploy if PAUSED
    state = _check_deploy_state(project_id)
    if state == "PAUSED":
        logger.info(f"[SKIP] Project {project_id} is PAUSED — skipping deployment")
        return

    # Read pending requests
    pending = _get_pending_requests(project_id)
    if not pending:
        logger.info(f"[SKIP] No pending requests for {project_id}")
        return

    logger.info(f"[INFO] Found {len(pending)} pending request(s) for {project_id}")

    # Group by deployment type so mixed batches are processed separately.
    groups = _group_requests_by_type(pending)
    if len(groups) > 1:
        logger.info(
            "[INFO] Mixed deployment types detected: %s — processing each type separately",
            sorted(groups.keys()),
        )

    for deployment_type, group_requests in groups.items():
        try:
            _orchestrate_typed_batch(project_id, deployment_type, group_requests)
        except Exception as e:
            logger.error(
                "[ERROR] Orchestration failed for %s type=%s: %s",
                project_id,
                deployment_type,
                e,
                exc_info=True,
            )

    logger.info(f"[END] Orchestration complete for {project_id}")


def _orchestrate_typed_batch(
    project_id: str,
    deployment_type: str,
    requests: List[Dict[str, Any]],
) -> None:
    """Orchestrate a single deployment-type batch within a project."""
    logger.info(f"[INFO] Deployment type batch: {deployment_type} ({len(requests)} request(s))")

    # Integration analysis
    analysis = _analyze_integration(requests)
    logger.info(f"[INFO] Integration analysis: {analysis['status']}")
    for w in analysis.get("warnings", []):
        logger.warning(f"[WARNING] {w}")

    if analysis["status"] == "fail":
        logger.error(f"[ERROR] Integration analysis FAILED — deployment blocked")
        # Don't mark requests as anything — they stay pending for manual review
        return

    # Aggregate
    all_changes, agg_summary, all_related = _aggregate_requests(requests)
    request_ids = [r["request_id"] for r in requests]

    # Generate spec ID
    spec_id = f"SPEC-{_utc_now_compact()}"
    logger.info(f"[INFO] Spec ID: {spec_id}")

    if deployment_type in NON_UI_SERVICE_GROUP_BY_TYPE:
        valid, targets, errors = _validate_non_ui_requests(deployment_type, requests)
        if not valid:
            logger.error("[ERROR] Non-UI validation failed for %s", deployment_type)
            for err in errors:
                logger.error("[ERROR] %s", err)
            return

        _write_spec(
            project_id,
            spec_id,
            status="queued_non_ui",
            deployment_type=deployment_type,
            deployment_category="non_ui",
            non_ui_service_group=NON_UI_SERVICE_GROUP_BY_TYPE[deployment_type],
            non_ui_targets={"targets": targets},
            non_ui_target_arns=[t["target_arn"] for t in targets],
            included_request_ids=request_ids,
            aggregated_changes=all_changes,
            aggregated_release_summary=agg_summary,
            integration_analysis=analysis,
            all_related_record_ids=all_related,
        )
        _mark_requests(project_id, request_ids, "included", spec_id)
        logger.info("[INFO] Non-UI deployment spec created: %s (%s)", spec_id, deployment_type)

        if deployment_type == "lambda_update" and NON_UI_INLINE_LAMBDA_UPDATE:
            ddb = _get_ddb()
            try:
                execution_results = _execute_lambda_update_targets(project_id, targets)
                now = _utc_now()
                ddb.update_item(
                    TableName=DEPLOY_TABLE,
                    Key={"project_id": {"S": project_id}, "record_id": {"S": f"spec#{spec_id}"}},
                    UpdateExpression=(
                        "SET #st = :deployed, completed_at = :now, non_ui_execution_results = :results"
                    ),
                    ExpressionAttributeNames={"#st": "status"},
                    ExpressionAttributeValues={
                        ":deployed": {"S": "deployed"},
                        ":now": {"S": now},
                        ":results": {"S": json.dumps(execution_results)},
                    },
                )
                logger.info(
                    "[SUCCESS] Inline lambda_update execution completed for spec %s (%d target(s))",
                    spec_id,
                    len(execution_results),
                )
                return
            except Exception as e:
                error_message = str(e)
                retryable = _is_retryable_inline_lambda_error(error_message)
                logger.error(
                    "[ERROR] Inline lambda_update execution failed for %s: %s",
                    spec_id,
                    e,
                    exc_info=True,
                )
                _mark_requests(project_id, request_ids, "pending" if retryable else "failed")
                ddb.update_item(
                    TableName=DEPLOY_TABLE,
                    Key={"project_id": {"S": project_id}, "record_id": {"S": f"spec#{spec_id}"}},
                    UpdateExpression="SET #st = :failed, error_message = :err",
                    ExpressionAttributeNames={"#st": "status"},
                    ExpressionAttributeValues={
                        ":failed": {"S": "failed"},
                        ":err": {"S": error_message[:500]},
                    },
                )
                raise

        logger.info(
            "[SUCCESS] Non-UI deployment spec queued for downstream executor: %s (%s)",
            spec_id,
            deployment_type,
        )
        return

    if deployment_type not in UI_DEPLOYMENT_TYPES:
        logger.error("[ERROR] Unsupported deployment type '%s'", deployment_type)
        return

    # UI deployment flow: read deploy config and run semver resolution + CodeBuild.
    config = _read_deploy_config(project_id)
    current_version = _get_current_version(project_id, config)
    logger.info(f"[INFO] Current version: {current_version}")
    new_version, change_type = _resolve_version(current_version, requests)
    logger.info(f"[INFO] Resolved version: {current_version} → {new_version} ({change_type})")

    # Write deployment spec
    _write_spec(
        project_id,
        spec_id,
        deployment_type=deployment_type,
        deployment_category="ui",
        previous_version=current_version,
        resolved_version=new_version,
        resolved_change_type=change_type,
        included_request_ids=request_ids,
        aggregated_changes=all_changes,
        aggregated_release_summary=agg_summary,
        integration_analysis=analysis,
        all_related_record_ids=all_related,
    )

    # Mark requests as included
    _mark_requests(project_id, request_ids, "included", spec_id)

    # Start CodeBuild
    try:
        build_id = _start_codebuild(project_id, spec_id, config)

        # Update spec with build ID
        ddb = _get_ddb()
        ddb.update_item(
            TableName=DEPLOY_TABLE,
            Key={"project_id": {"S": project_id}, "record_id": {"S": f"spec#{spec_id}"}},
            UpdateExpression="SET codebuild_build_id = :bid",
            ExpressionAttributeValues={":bid": {"S": build_id}},
        )
        logger.info(f"[SUCCESS] CodeBuild started for {project_id}: {build_id}")

    except Exception as e:
        logger.error(f"[ERROR] CodeBuild start failed: {e}", exc_info=True)
        # Reset requests to pending so they can be retried
        _mark_requests(project_id, request_ids, "pending")
        # Update spec status to failed
        ddb = _get_ddb()
        ddb.update_item(
            TableName=DEPLOY_TABLE,
            Key={"project_id": {"S": project_id}, "record_id": {"S": f"spec#{spec_id}"}},
            UpdateExpression="SET #st = :failed, error_message = :err",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":failed": {"S": "failed"},
                ":err": {"S": str(e)[:500]},
            },
        )
        raise
