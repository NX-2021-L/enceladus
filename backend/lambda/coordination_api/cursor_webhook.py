"""cursor_webhook.py — Cursor Cloud Agents completion webhook (ADE Component C).

Part of the Enceladus Autonomous Dispatch Engine (ADE). Handles the
``POST /api/v1/cursor/webhook`` route inside the coordination_api Lambda.

Design notes
------------
Every function here is PURE and dependency-injected so it can be unit tested
without network, AWS, or the coordination_api monolith's global state:

* ``verify_signature`` — HMAC-SHA256 over the RAW request body, compared in
  constant time. Accepts both ``sha256=<hex>`` and bare-hex forms.
* ``parse_event`` — tolerant extraction of the Cursor payload fields.
* ``derive_task_id`` — ``claude/{task_id}`` branch -> ``{TASK_ID}`` (uppercased).
* ``build_evidence_doc_payload`` / ``build_finished_issue_payload`` /
  ``build_error_issue_payload`` — construct the document/issue create payloads.
* ``handle(event, context, deps)`` — orchestrates the flow. ``deps`` bundles the
  side-effecting callables (``create_document``, ``create_issue``,
  ``resolve_governance_hash``) so tests inject fakes and the monolith injects the
  real internal create mechanisms.

The handler returns ``(status_code, body_dict)``. Cursor retries non-2xx
responses, so a valid-signature request that then fails *internally* still
returns 200 (the error is logged). Only a missing/invalid signature (401) or an
unparseable body (400) short-circuit to a non-2xx status.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

__all__ = [
    "CursorWebhookDeps",
    "DEFAULT_SIGNATURE_HEADER",
    "build_error_issue_payload",
    "build_evidence_doc_payload",
    "build_finished_issue_payload",
    "derive_task_id",
    "extract_raw_body",
    "extract_signature_header",
    "handle",
    "parse_event",
    "verify_signature",
]

# Cursor delivers the HMAC in this header (see assumptions in the task report).
# Both this canonical name and a couple of common casings are checked by
# ``extract_signature_header`` so we are tolerant of API Gateway header
# normalization.
DEFAULT_SIGNATURE_HEADER = "X-Webhook-Signature"

# Pattern for the Enceladus task id embedded in the Cursor target branch name:
# ``claude/{task_id}`` -> ``{task_id}`` (then uppercased by the caller).
_BRANCH_TASK_ID_RE = re.compile(r"^claude/(?P<task_id>.+)$")


# ---------------------------------------------------------------------------
# Dependency bundle
# ---------------------------------------------------------------------------


class CursorWebhookDeps:
    """Side-effecting callables injected into :func:`handle`.

    Keeping these on a small struct (rather than free function args) lets the
    monolith build one ``deps`` object that closes over its boto3 clients /
    config, while tests pass fakes. All three are required.

    * ``create_document(payload: dict) -> dict`` must return a mapping that
      contains the server-assigned ``document_id``.
    * ``create_issue(payload: dict) -> dict`` must return a mapping that
      contains the server-assigned ``record_id``.
    * ``resolve_governance_hash() -> str`` returns the current governance hash
      (resolved the same way existing handlers do).
    """

    __slots__ = ("create_document", "create_issue", "resolve_governance_hash")

    def __init__(
        self,
        create_document: Callable[[Dict[str, Any]], Dict[str, Any]],
        create_issue: Callable[[Dict[str, Any]], Dict[str, Any]],
        resolve_governance_hash: Callable[[], str],
    ) -> None:
        self.create_document = create_document
        self.create_issue = create_issue
        self.resolve_governance_hash = resolve_governance_hash


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def _normalize_signature(signature_header: Optional[str]) -> Optional[str]:
    """Return the bare lowercase hex digest from a signature header, or None.

    Accepts both ``sha256=<hexdigest>`` and a bare ``<hexdigest>``. Returns
    ``None`` when the header is missing/empty or is not valid hex.
    """
    if not signature_header:
        return None
    candidate = str(signature_header).strip()
    if not candidate:
        return None
    if candidate.lower().startswith("sha256="):
        candidate = candidate.split("=", 1)[1].strip()
    candidate = candidate.lower()
    if not candidate:
        return None
    # Must be valid hex of even length for a SHA-256 digest comparison.
    if len(candidate) % 2 != 0:
        return None
    try:
        binascii.unhexlify(candidate)
    except (binascii.Error, ValueError):
        return None
    return candidate


def verify_signature(
    raw_body: bytes,
    signature_header: Optional[str],
    secret: str,
) -> bool:
    """Validate the Cursor webhook HMAC-SHA256 signature over the RAW body.

    ``raw_body`` MUST be the exact bytes Cursor signed (decode base64 first if
    the API Gateway delivered an ``isBase64Encoded`` body, but do NOT JSON
    round-trip — re-serialization would change the bytes). Comparison uses
    :func:`hmac.compare_digest` to avoid timing leaks.

    Returns ``False`` (never raises) when the secret is unset, the header is
    missing/malformed, or the digest does not match.
    """
    if not secret:
        # Fail closed: without a configured secret we cannot authenticate.
        logger.error("cursor_webhook: CURSOR_WEBHOOK_SECRET is not configured; rejecting")
        return False

    provided = _normalize_signature(signature_header)
    if provided is None:
        return False

    if isinstance(raw_body, str):
        raw_body = raw_body.encode("utf-8")
    elif raw_body is None:
        raw_body = b""

    expected = hmac.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, provided)


# ---------------------------------------------------------------------------
# Event / payload extraction
# ---------------------------------------------------------------------------


def extract_signature_header(event: Dict[str, Any]) -> Optional[str]:
    """Return the webhook signature header value from an API Gateway event.

    API Gateway lowercases header keys for HTTP API (payload v2.0) but not
    always for REST; we check a few casings to be safe.
    """
    headers = event.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    for key in (
        DEFAULT_SIGNATURE_HEADER,
        DEFAULT_SIGNATURE_HEADER.lower(),
        "x-webhook-signature",
        "X-Webhook-Signature",
    ):
        if key in headers and headers[key]:
            return str(headers[key])
    # Last resort: case-insensitive scan.
    for key, value in headers.items():
        if str(key).lower() == DEFAULT_SIGNATURE_HEADER.lower() and value:
            return str(value)
    return None


def extract_raw_body(event: Dict[str, Any]) -> bytes:
    """Return the RAW request body bytes, decoding base64 if needed.

    The signature is computed over these exact bytes, so this must run BEFORE
    any JSON parsing. API Gateway may base64-encode the body (binary media or
    certain content types) — honor ``event['isBase64Encoded']``.
    """
    raw = event.get("body")
    if raw is None:
        return b""
    if event.get("isBase64Encoded"):
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        return base64.b64decode(raw)
    if isinstance(raw, bytes):
        return raw
    return str(raw).encode("utf-8")


def _get_nested(mapping: Any, *keys: str) -> Any:
    """Safely walk nested dict keys, returning None on any miss/non-dict."""
    cur = mapping
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def parse_event(body: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the Cursor webhook fields from a parsed JSON body.

    Tolerates missing / nested keys. Returns a flat dict with normalized
    string values (empty string when absent):

        cursor_agent_id, status, repository, ref, branch_name, pr_url, summary
    """
    if not isinstance(body, dict):
        body = {}

    def _s(value: Any) -> str:
        return "" if value is None else str(value)

    status = _s(body.get("status")).strip().upper()

    return {
        "cursor_agent_id": _s(body.get("id")).strip(),
        "status": status,
        "repository": _s(_get_nested(body, "source", "repository")).strip(),
        "ref": _s(_get_nested(body, "source", "ref")).strip(),
        "branch_name": _s(_get_nested(body, "target", "branchName")).strip(),
        "pr_url": _s(_get_nested(body, "target", "prUrl")).strip(),
        "summary": _s(body.get("summary")),
    }


def derive_task_id(branch_name: Optional[str]) -> str:
    """Derive the Enceladus task id from a Cursor target branch name.

    ``claude/{task_id}`` -> ``{task_id}`` uppercased
    (e.g. ``claude/enc-tsk-i40`` -> ``ENC-TSK-I40``).

    Returns ``""`` when the branch does not match the ``claude/`` convention or
    is empty. The captured task id is stripped of surrounding slashes/whitespace.
    """
    if not branch_name:
        return ""
    candidate = str(branch_name).strip()
    match = _BRANCH_TASK_ID_RE.match(candidate)
    if not match:
        return ""
    task_id = match.group("task_id").strip().strip("/").strip()
    return task_id.upper()


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def build_evidence_doc_payload(parsed: Dict[str, Any], timestamp: str) -> Dict[str, Any]:
    """Build the deploy-evidence document create payload (status FINISHED).

    The ``content`` is a markdown block embedding the task id, cursor agent id,
    PR url, branch, completion timestamp, status, and the agent summary.
    """
    task_id = derive_task_id(parsed.get("branch_name")) or "UNKNOWN"
    cursor_agent_id = parsed.get("cursor_agent_id") or ""
    pr_url = parsed.get("pr_url") or ""
    branch = parsed.get("branch_name") or ""
    summary = parsed.get("summary") or ""

    title = f"Cursor Deploy Evidence — {task_id} — {timestamp}"

    content = (
        f"# Cursor Deploy Evidence — {task_id}\n\n"
        f"- **task_id:** {task_id}\n"
        f"- **cursor_agent_id:** {cursor_agent_id}\n"
        f"- **pr_url:** {pr_url}\n"
        f"- **branch:** {branch}\n"
        f"- **completed_at:** {timestamp}\n"
        f"- **status:** FINISHED\n\n"
        f"## Summary\n\n"
        f"{summary}\n"
    )

    return {
        "title": title,
        "document_subtype": "doc",
        "subtypepattern": "deploy-evidence",
        "content": content,
    }


def build_finished_issue_payload(parsed: Dict[str, Any], document_id: str) -> Dict[str, Any]:
    """Build the P2 close-out issue create payload (status FINISHED)."""
    task_id = derive_task_id(parsed.get("branch_name")) or "UNKNOWN"
    cursor_agent_id = parsed.get("cursor_agent_id") or ""
    pr_url = parsed.get("pr_url") or ""

    title = f"Close-out ready: {task_id} — Cursor agent FINISHED, PR open"
    hypothesis = (
        f"Cursor agent {cursor_agent_id} completed {task_id} and opened PR {pr_url}. "
        f"Deploy evidence is recorded at {document_id}. A governed close-out session "
        f"should review the evidence and advance the task."
    )
    technical_notes = (
        f"Auto-filed by Enceladus Cursor webhook handler. Evidence doc: {document_id}."
    )

    return {
        "title": title,
        "priority": "P2",
        "hypothesis": hypothesis,
        "technical_notes": technical_notes,
    }


def build_error_issue_payload(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Build the P1 manual-intervention issue create payload (status ERROR)."""
    task_id = derive_task_id(parsed.get("branch_name")) or "UNKNOWN"
    cursor_agent_id = parsed.get("cursor_agent_id") or ""
    summary = parsed.get("summary") or ""

    title = f"Cursor agent ERROR on {task_id} — manual intervention required"
    hypothesis = (
        f"Cursor agent {cursor_agent_id} failed on {task_id}. "
        f"Conversation: https://cursor.com/agents/{cursor_agent_id}. "
        f"Summary: {summary}"
    )
    technical_notes = (
        "Auto-filed by Enceladus Cursor webhook handler. "
        "Review the agent conversation log."
    )

    return {
        "title": title,
        "priority": "P1",
        "hypothesis": hypothesis,
        "technical_notes": technical_notes,
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _safe_resolve_governance_hash(deps: CursorWebhookDeps) -> str:
    try:
        value = deps.resolve_governance_hash()
        return str(value or "")
    except Exception:  # pragma: no cover - defensive; logged for operators
        logger.exception("cursor_webhook: governance hash resolution failed")
        return ""


def handle(
    event: Dict[str, Any],
    context: Any,
    deps: CursorWebhookDeps,
    *,
    secret: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Process a Cursor completion webhook.

    Returns ``(status_code, body_dict)``.

    Contract (from the ADE design spec):
      * 401 when the signature is missing/invalid.
      * 400 when the (signature-valid) body is not parseable JSON.
      * 200 on the happy path AND on any internal error after a valid signature
        (Cursor retries non-2xx, so we swallow internal failures and log them).

    ``secret`` defaults to ``None`` and MUST be supplied by the caller from the
    ``CURSOR_WEBHOOK_SECRET`` env var; verification fails closed if empty.
    ``timestamp`` is injectable for deterministic tests.
    """
    raw_body = extract_raw_body(event)
    signature_header = extract_signature_header(event)

    # 1. Signature verification over RAW bytes -> 401 on miss/invalid.
    if not verify_signature(raw_body, signature_header, secret or ""):
        logger.warning("cursor_webhook: signature verification failed")
        return 401, {"success": False, "error": "Invalid or missing webhook signature"}

    # 2. Parse JSON body -> 400 on unparseable.
    try:
        decoded = raw_body.decode("utf-8") if raw_body else "{}"
        body = json.loads(decoded) if decoded.strip() else {}
        if not isinstance(body, dict):
            raise ValueError("JSON body must be an object")
    except (ValueError, UnicodeDecodeError) as exc:
        logger.warning("cursor_webhook: unparseable body: %s", exc)
        return 400, {"success": False, "error": f"Invalid JSON body: {exc}"}

    parsed = parse_event(body)

    if timestamp is None:
        # Imported lazily so the module has no hard datetime dependency at import
        # time and tests can fully control the value via the kwarg.
        import datetime as _dt

        timestamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 3..5. Dispatch by status. Any internal failure past this point still
    # returns 200 so Cursor does not retry — the error is logged.
    try:
        status = parsed.get("status") or ""
        task_id = derive_task_id(parsed.get("branch_name"))
        governance_hash = _safe_resolve_governance_hash(deps)

        if status == "FINISHED":
            return _handle_finished(parsed, task_id, governance_hash, timestamp, deps)
        if status == "ERROR":
            return _handle_error(parsed, task_id, governance_hash, deps)

        # Unknown/missing status: acknowledge (200) but record that we no-op'd so
        # Cursor does not retry a benign event.
        logger.info(
            "cursor_webhook: ignoring event with unhandled status=%r (agent_id=%s, task_id=%s)",
            status,
            parsed.get("cursor_agent_id"),
            task_id,
        )
        return 200, {
            "success": True,
            "ignored": True,
            "reason": f"unhandled status: {status!r}",
            "task_id": task_id,
        }
    except Exception as exc:  # pragma: no cover - exercised via injected failures
        # Valid signature but internal failure -> 200 + log (Cursor retries non-2xx).
        logger.exception("cursor_webhook: internal error after valid signature")
        return 200, {
            "success": False,
            "error": f"Internal error (logged; not retried): {exc}",
            "task_id": derive_task_id(parsed.get("branch_name")),
        }


def _handle_finished(
    parsed: Dict[str, Any],
    task_id: str,
    governance_hash: str,
    timestamp: str,
    deps: CursorWebhookDeps,
) -> Tuple[int, Dict[str, Any]]:
    # a. Create the deploy-evidence document.
    doc_payload = build_evidence_doc_payload(parsed, timestamp)
    doc_payload["governance_hash"] = governance_hash
    doc_result = deps.create_document(doc_payload) or {}
    document_id = str(doc_result.get("document_id") or "")

    # b. Create the P2 close-out issue referencing the evidence doc.
    issue_payload = build_finished_issue_payload(parsed, document_id)
    issue_payload["governance_hash"] = governance_hash
    issue_result = deps.create_issue(issue_payload) or {}
    record_id = str(issue_result.get("record_id") or "")

    logger.info(
        "cursor_webhook: FINISHED handled task_id=%s document_id=%s issue=%s",
        task_id,
        document_id,
        record_id,
    )
    # c. Return 200.
    return 200, {
        "success": True,
        "status": "FINISHED",
        "task_id": task_id,
        "document_id": document_id,
        "record_id": record_id,
    }


def _handle_error(
    parsed: Dict[str, Any],
    task_id: str,
    governance_hash: str,
    deps: CursorWebhookDeps,
) -> Tuple[int, Dict[str, Any]]:
    # a. Create the P1 manual-intervention issue.
    issue_payload = build_error_issue_payload(parsed)
    issue_payload["governance_hash"] = governance_hash
    issue_result = deps.create_issue(issue_payload) or {}
    record_id = str(issue_result.get("record_id") or "")

    logger.info(
        "cursor_webhook: ERROR handled task_id=%s issue=%s",
        task_id,
        record_id,
    )
    # b. Return 200.
    return 200, {
        "success": True,
        "status": "ERROR",
        "task_id": task_id,
        "record_id": record_id,
    }
