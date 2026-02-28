#!/usr/bin/env python3
"""Capture PWA diagnostic evidence using coordination_cognito_session cookies.

This tool consumes the payload returned by the MCP tool
`coordination_cognito_session` (or the nested `session` object), loads
Cognito-authenticated cookies into Playwright, and captures evidence for one
or more protected Enceladus PWA routes.

Examples:
  python3 tools/pwa_cognito_evidence_capture.py \
    --session-file /tmp/coordination_cognito_session.json \
    --route /enceladus/ \
    --route /enceladus/terminal/manage \
    --output-dir /tmp/enceladus-pwa-evidence

  cat /tmp/coordination_cognito_session.json | \
    python3 tools/pwa_cognito_evidence_capture.py --route /enceladus/
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

DEFAULT_ROUTES = ["/enceladus/", "/enceladus/terminal/manage"]
DEFAULT_TIMEOUT_MS = 20_000
DEFAULT_OUTPUT_DIR = "/tmp/enceladus-pwa-evidence"

JWT_PATTERN = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
COOKIE_TOKEN_PATTERN = re.compile(
    r"(?i)(enceladus_(?:id|refresh)_token=)[^;\s]+"
)
BEARER_PATTERN = re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s]+")


@dataclass
class SessionPayload:
    target_origin: str
    playwright_cookies: List[Dict[str, Any]]


class EvidenceCaptureError(RuntimeError):
    """Raised when input payload or capture settings are invalid."""


def _now_z() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_compact() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _read_json_payload(args: argparse.Namespace) -> Dict[str, Any]:
    if args.session_json:
        try:
            loaded = json.loads(args.session_json)
        except json.JSONDecodeError as exc:
            raise EvidenceCaptureError(f"--session-json must be valid JSON: {exc}") from exc
        if not isinstance(loaded, dict):
            raise EvidenceCaptureError("--session-json must decode to a JSON object")
        return loaded

    if args.session_file:
        try:
            text = pathlib.Path(args.session_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise EvidenceCaptureError(f"failed to read --session-file: {exc}") from exc
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError as exc:
            raise EvidenceCaptureError(f"--session-file must contain valid JSON: {exc}") from exc
        if not isinstance(loaded, dict):
            raise EvidenceCaptureError("--session-file JSON must be an object")
        return loaded

    if not sys.stdin.isatty():
        text = sys.stdin.read().strip()
        if not text:
            raise EvidenceCaptureError("stdin is empty; provide session payload JSON")
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError as exc:
            raise EvidenceCaptureError(f"stdin must contain valid JSON: {exc}") from exc
        if not isinstance(loaded, dict):
            raise EvidenceCaptureError("stdin JSON must be an object")
        return loaded

    raise EvidenceCaptureError(
        "provide session payload via --session-file, --session-json, or stdin"
    )


def _extract_session_payload(raw: Dict[str, Any]) -> SessionPayload:
    payload = raw.get("session") if isinstance(raw.get("session"), dict) else raw
    if not isinstance(payload, dict):
        raise EvidenceCaptureError("session payload must be a JSON object")

    origin = str(payload.get("target_origin") or "").strip()
    parsed_origin = urllib.parse.urlparse(origin)
    if not origin or parsed_origin.scheme != "https" or not parsed_origin.netloc:
        raise EvidenceCaptureError(
            "session payload must include 'target_origin' as a valid https origin"
        )
    normalized_origin = f"{parsed_origin.scheme}://{parsed_origin.netloc}"

    cookies = payload.get("playwright_cookies")
    if not isinstance(cookies, list) or not cookies:
        raise EvidenceCaptureError(
            "session payload must include non-empty 'playwright_cookies'"
        )

    normalized_cookies: List[Dict[str, Any]] = []
    for idx, cookie in enumerate(cookies):
        if not isinstance(cookie, dict):
            raise EvidenceCaptureError(f"playwright_cookies[{idx}] must be an object")

        name = str(cookie.get("name") or "").strip()
        value = str(cookie.get("value") or "")
        if not name or not value:
            raise EvidenceCaptureError(
                f"playwright_cookies[{idx}] requires non-empty name/value"
            )

        normalized: Dict[str, Any] = {
            "name": name,
            "value": value,
            "url": str(cookie.get("url") or normalized_origin).strip() or normalized_origin,
            "path": str(cookie.get("path") or "/").strip() or "/",
            "secure": bool(cookie.get("secure", True)),
            "httpOnly": bool(cookie.get("httpOnly", False)),
        }
        same_site = str(cookie.get("sameSite") or "").strip()
        if same_site:
            normalized["sameSite"] = same_site
        expires = cookie.get("expires")
        if isinstance(expires, (int, float)) and expires > 0:
            normalized["expires"] = float(expires)

        normalized_cookies.append(normalized)

    return SessionPayload(
        target_origin=normalized_origin,
        playwright_cookies=normalized_cookies,
    )


def _normalize_routes(
    routes: Iterable[str],
    target_origin: str,
) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    seen: set[str] = set()
    origin_parsed = urllib.parse.urlparse(target_origin)

    for raw_route in routes:
        route = str(raw_route or "").strip()
        if not route:
            continue

        if route.startswith("http://") or route.startswith("https://"):
            parsed = urllib.parse.urlparse(route)
            if parsed.scheme != "https" or not parsed.netloc:
                raise EvidenceCaptureError(f"invalid route URL: {route}")
            if parsed.netloc != origin_parsed.netloc:
                raise EvidenceCaptureError(
                    f"route origin mismatch: {route} does not match {target_origin}"
                )
            canonical_url = route
            canonical_route = parsed.path or "/"
            if parsed.query:
                canonical_route += f"?{parsed.query}"
        else:
            canonical_route = route if route.startswith("/") else f"/{route}"
            canonical_url = f"{target_origin}{canonical_route}"

        if canonical_url in seen:
            continue
        seen.add(canonical_url)
        out.append((canonical_route, canonical_url))

    if not out:
        raise EvidenceCaptureError("no routes specified for evidence capture")

    return out


def _slugify(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    return cleaned or "route"


def _redact_text(value: str) -> str:
    redacted = JWT_PATTERN.sub("[REDACTED_JWT]", str(value))
    redacted = COOKIE_TOKEN_PATTERN.sub(r"\1[REDACTED_TOKEN]", redacted)
    redacted = BEARER_PATTERN.sub(r"\1[REDACTED_TOKEN]", redacted)
    return redacted


def _redact_url(raw_url: str) -> str:
    raw_url = str(raw_url or "")
    parsed = urllib.parse.urlparse(raw_url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    redacted_query = []
    for key, value in query:
        lowered = key.lower()
        if any(token in lowered for token in ("token", "code", "secret", "password")):
            redacted_query.append((key, "[REDACTED]"))
        else:
            redacted_query.append((key, value))
    rebuilt_query = urllib.parse.urlencode(redacted_query)
    sanitized = parsed._replace(query=rebuilt_query)
    return _redact_text(urllib.parse.urlunparse(sanitized))


def _capture_route(
    context: Any,
    route_label: str,
    target_url: str,
    output_dir: pathlib.Path,
    timeout_ms: int,
) -> Dict[str, Any]:
    page = context.new_page()

    console_events: List[Dict[str, Any]] = []
    network_events: List[Dict[str, Any]] = []

    def on_console(msg: Any) -> None:
        try:
            entry = {
                "timestamp": _now_z(),
                "type": str(msg.type),
                "text": _redact_text(msg.text()),
            }
            console_events.append(entry)
        except Exception:
            pass

    def on_request_failed(req: Any) -> None:
        try:
            failure = req.failure
            reason = ""
            if isinstance(failure, dict):
                reason = str(failure.get("errorText") or "")
            elif failure is not None:
                reason = str(failure)
            network_events.append(
                {
                    "timestamp": _now_z(),
                    "kind": "request_failed",
                    "method": str(req.method),
                    "url": _redact_url(req.url),
                    "failure": _redact_text(reason),
                }
            )
        except Exception:
            pass

    def on_response(resp: Any) -> None:
        try:
            status = int(resp.status)
            if status < 400:
                return
            network_events.append(
                {
                    "timestamp": _now_z(),
                    "kind": "response_error",
                    "status": status,
                    "method": str(resp.request.method),
                    "url": _redact_url(resp.url),
                }
            )
        except Exception:
            pass

    def on_page_error(err: Any) -> None:
        network_events.append(
            {
                "timestamp": _now_z(),
                "kind": "page_error",
                "error": _redact_text(str(err)),
            }
        )

    page.on("console", on_console)
    page.on("requestfailed", on_request_failed)
    page.on("response", on_response)
    page.on("pageerror", on_page_error)

    slug = _slugify(route_label.replace("/", "-"))
    screenshot_name = f"{slug}.png"
    html_name = f"{slug}.html"

    result: Dict[str, Any] = {
        "route": route_label,
        "target_url": _redact_url(target_url),
        "final_url": "",
        "title": "",
        "http_status": None,
        "ok": False,
        "error": "",
        "artifacts": {
            "screenshot": screenshot_name,
            "html": html_name,
        },
        "console_events": console_events,
        "network_events": network_events,
    }

    try:
        response = page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)
        try:
            page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 7000))
        except Exception:
            pass

        result["final_url"] = _redact_url(page.url)
        result["title"] = _redact_text(page.title())
        if response is not None:
            result["http_status"] = int(response.status)
            result["ok"] = bool(response.ok)

        page.screenshot(path=str(output_dir / screenshot_name), full_page=True)
        page_html = page.content()
        (output_dir / html_name).write_text(page_html, encoding="utf-8")
    except Exception as exc:
        result["error"] = _redact_text(str(exc))
    finally:
        page.close()

    return result


def _masked_cookie_summary(cookies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "name": str(cookie.get("name") or ""),
            "url": _redact_url(str(cookie.get("url") or "")),
            "path": str(cookie.get("path") or "/"),
            "secure": bool(cookie.get("secure", True)),
            "httpOnly": bool(cookie.get("httpOnly", False)),
            "sameSite": str(cookie.get("sameSite") or ""),
        }
        for cookie in cookies
    ]


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Capture Cognito-authenticated PWA evidence using "
            "coordination_cognito_session.playwright_cookies"
        )
    )
    parser.add_argument("--session-file", help="Path to JSON payload from coordination_cognito_session")
    parser.add_argument("--session-json", help="Inline JSON payload from coordination_cognito_session")
    parser.add_argument(
        "--route",
        action="append",
        default=[],
        help="Route path or full URL to capture (repeatable)",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output artifact directory base (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=DEFAULT_TIMEOUT_MS,
        help=f"Navigation timeout in milliseconds (default: {DEFAULT_TIMEOUT_MS})",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Run browser in headed mode (default: headless)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any route capture fails or returns HTTP >= 400",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        raw_payload = _read_json_payload(args)
        session_payload = _extract_session_payload(raw_payload)
    except EvidenceCaptureError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    route_inputs = args.route or list(DEFAULT_ROUTES)
    try:
        routes = _normalize_routes(route_inputs, session_payload.target_origin)
    except EvidenceCaptureError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    run_dir = pathlib.Path(args.output_dir) / f"evidence-{_now_compact()}"
    run_dir.mkdir(parents=True, exist_ok=True)

    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception:
        print(
            "[ERROR] Playwright is not installed. Install with:\n"
            "  python3 -m pip install playwright\n"
            "  python3 -m playwright install chromium",
            file=sys.stderr,
        )
        return 2

    results: List[Dict[str, Any]] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not args.headed)
        context = browser.new_context(ignore_https_errors=False)
        context.add_cookies(session_payload.playwright_cookies)

        for route_label, target_url in routes:
            results.append(
                _capture_route(
                    context=context,
                    route_label=route_label,
                    target_url=target_url,
                    output_dir=run_dir,
                    timeout_ms=max(1_000, args.timeout_ms),
                )
            )

        context.close()
        browser.close()

    success_count = sum(1 for row in results if not row.get("error") and (row.get("http_status") or 0) < 400)
    failure_count = len(results) - success_count

    summary = {
        "generated_at": _now_z(),
        "target_origin": session_payload.target_origin,
        "routes_requested": [route for route, _ in routes],
        "cookie_summary": _masked_cookie_summary(session_payload.playwright_cookies),
        "results": results,
        "stats": {
            "total": len(results),
            "success": success_count,
            "failed": failure_count,
        },
    }
    summary_path = run_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"[INFO] Evidence capture complete: {run_dir}")
    print(f"[INFO] Summary: {summary_path}")

    if args.strict and failure_count > 0:
        print("[ERROR] One or more route captures failed in --strict mode", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
