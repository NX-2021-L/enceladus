import json
import os
from datetime import datetime, timezone

import boto3

GLUE = boto3.client("glue")
CRAWLER_PREFIX = os.environ.get("CRAWLER_PREFIX", "")
MIN_CRAWL_INTERVAL_SECONDS = int(os.environ.get("MIN_CRAWL_INTERVAL_SECONDS", "7200"))
ACTIVE_STATES = {"RUNNING", "STOPPING"}
DEFAULT_MAP = {
    "features": "features-sync",
    "tasks": "tasks-sync",
    "issues": "issues-sync",
}


def resolve_crawler(log_type: str) -> str:
    mapping = json.loads(os.environ.get("CRAWLER_MAP", "{}"))
    if not mapping:
        mapping = DEFAULT_MAP
    crawler = mapping.get(log_type)
    if not crawler:
        raise ValueError(f"Unknown log_type {log_type}")
    if CRAWLER_PREFIX:
        return f"{CRAWLER_PREFIX}{crawler}"
    return crawler


def _normalize_message(event):
    detail = event.get("detail") or event
    message = detail.get("Message", detail)
    if isinstance(message, str):
        message = json.loads(message)
    if not isinstance(message, dict):
        raise ValueError(f"Unsupported payload type: {type(message)}")
    return message


def _seconds_since_last_crawl(crawler):
    last_crawl = (crawler or {}).get("LastCrawl") or {}
    start_time = last_crawl.get("StartTime")
    if not isinstance(start_time, datetime):
        return None
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - start_time).total_seconds()))


def lambda_handler(event, _context):
    message = _normalize_message(event)
    log_type = message.get("log_type")
    if not log_type:
        raise ValueError("Missing log_type in SNS payload")

    crawler_name = resolve_crawler(log_type)
    crawler = GLUE.get_crawler(Name=crawler_name).get("Crawler", {})
    crawler_state = crawler.get("State")

    if crawler_state in ACTIVE_STATES:
        return {
            "status": "skipped",
            "reason": "crawler_active",
            "crawler": crawler_name,
            "crawler_state": crawler_state,
            "min_interval_seconds": MIN_CRAWL_INTERVAL_SECONDS,
            "project": message.get("project"),
            "sync_run_id": message.get("sync_run_id"),
        }

    seconds_since_last_crawl = _seconds_since_last_crawl(crawler)
    if (
        seconds_since_last_crawl is not None
        and seconds_since_last_crawl < MIN_CRAWL_INTERVAL_SECONDS
    ):
        return {
            "status": "skipped",
            "reason": "cadence_guard",
            "crawler": crawler_name,
            "crawler_state": crawler_state,
            "seconds_since_last_crawl": seconds_since_last_crawl,
            "min_interval_seconds": MIN_CRAWL_INTERVAL_SECONDS,
            "project": message.get("project"),
            "sync_run_id": message.get("sync_run_id"),
        }

    GLUE.start_crawler(Name=crawler_name)

    return {
        "status": "started",
        "reason": "started",
        "crawler": crawler_name,
        "crawler_state": crawler_state,
        "seconds_since_last_crawl": seconds_since_last_crawl,
        "min_interval_seconds": MIN_CRAWL_INTERVAL_SECONDS,
        "project": message.get("project"),
        "sync_run_id": message.get("sync_run_id"),
    }
