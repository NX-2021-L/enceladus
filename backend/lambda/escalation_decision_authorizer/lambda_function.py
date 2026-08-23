"""escalation_decision_authorizer/lambda_function.py

ENC-TSK-L95 / ENC-ISS-501 (SEV-1): standalone API Gateway v2 REQUEST authorizer
for the escalation approve/deny decision routes only:

    POST /api/v1/coordination/escalations/{projectId}/{escalationId}/approve
    POST /api/v1/coordination/escalations/{projectId}/{escalationId}/deny

Root cause being closed: coordination_api's in-Lambda `_is_cognito_session`
check is a fail-open BLOCKLIST (it excludes only auth_mode in {"internal-key",
"managed-token"} -- any other or absent auth_mode passes as "human"), which
let a non-human Cognito-authenticated identity self-approve governance-bypass
escalations within seconds of filing, with no human review.

Design: this is a brand-new, self-contained Lambda -- it does NOT modify or
depend on coordination_api/lambda_function.py in any way, and shares nothing
with the gamma-side fix (ENC-TSK-L92) except the S3 allowlist document. It
sits in FRONT of the two decision routes as an API Gateway authorizer, so an
unauthorized request is rejected before it ever reaches coordination_api --
the existing (unmodified) in-Lambda check still runs afterward as a second,
independent layer for any request that does reach it.

Two checks, both required:
  1. A genuine Cognito ID token (RS256-verified against the human user pool's
     JWKS), via the same enceladus_shared.auth verifier every other Enceladus
     Lambda already uses -- no bespoke crypto written here.
  2. The verified token's `email` claim must appear in a Console-edit-only S3
     allowlist document. No Lambda role, including this one, has write access
     to that document -- only s3:GetObject. Any fetch/parse error fails
     CLOSED (denies the request) rather than falling back to "allow".

Environment variables:
    COGNITO_USER_POOL_ID              (enceladus_shared.auth)
    COGNITO_CLIENT_ID                 (enceladus_shared.auth)
    ESCALATION_APPROVER_ALLOWLIST_BUCKET   default: enceladus-356364570033-us-west-2-an
    ESCALATION_APPROVER_ALLOWLIST_KEY      default: security/escalation-approvers.md

ENC-ISS-505 (SEV-1): originally defaulted to jreese-net, which is served
publicly on the open web via CloudFront (multiple distributions, one with a
broad, path-unrestricted s3:GetObject grant on jreese-net/*) -- the allowlist
was readable by anyone at https://jreese.net/security/escalation-approvers.md
with no auth. Relocated to a private bucket with no CloudFront origin and
full S3 Public Access Block enabled.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Set

import boto3

from enceladus_shared.auth import _authenticate

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ESCALATION_APPROVER_ALLOWLIST_BUCKET = os.environ.get(
    "ESCALATION_APPROVER_ALLOWLIST_BUCKET", "enceladus-356364570033-us-west-2-an"
)
ESCALATION_APPROVER_ALLOWLIST_KEY = os.environ.get(
    "ESCALATION_APPROVER_ALLOWLIST_KEY", "security/escalation-approvers.md"
)

_ALLOWLIST_CACHE_TTL = 60.0
_allowlist_cache: Dict[str, Any] = {"emails": None, "fetched_at": 0.0}


def _load_escalation_approver_allowlist() -> Set[str]:
    """Fetch and parse the escalation-approver allowlist S3 document, cached 60s.

    Fails CLOSED: any fetch or parse error returns an empty set (nobody is
    authorized) rather than silently falling back to "allow everyone".
    """
    now = time.time()
    cached = _allowlist_cache.get("emails")
    fetched_at = _allowlist_cache.get("fetched_at") or 0.0
    if cached is not None and (now - fetched_at) < _ALLOWLIST_CACHE_TTL:
        return cached
    try:
        s3 = boto3.client("s3", region_name=os.environ.get("AWS_REGION"))
        obj = s3.get_object(Bucket=ESCALATION_APPROVER_ALLOWLIST_BUCKET, Key=ESCALATION_APPROVER_ALLOWLIST_KEY)
        body = obj["Body"].read().decode("utf-8")
        emails: Set[str] = set()
        # Parsed without a yaml dependency: the document's fenced yaml block
        # uses `- email: "..."` list entries; pull the value off any such
        # line regardless of the leading "- " list marker.
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("- "):
                stripped = stripped[2:].strip()
            if stripped.startswith("email:"):
                value = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                if value:
                    emails.add(value.lower())
        _allowlist_cache["emails"] = emails
        _allowlist_cache["fetched_at"] = now
        return emails
    except Exception as exc:  # noqa: BLE001 — fail closed on any fetch/parse error
        logger.error(
            "escalation approver allowlist fetch failed (fail-closed, denying all): %s", exc
        )
        return set()


# ENC-TSK-M12 / ENC-ISS-501: structural human-principal enforcement.
# The email allowlist authorizes WHICH identities may decide; this predicate
# enforces WHAT KIND of token may decide at all. Machine-operated Cognito
# users in the human pool (e.g. terminal-agent@enceladus.internal, mintable
# via coordination auth.cognito_session) carry genuine ID tokens that pass
# JWKS verification, and access-token/M2M shapes must never qualify either --
# the allowlist must not be the only barrier between a machine principal and
# an escalation approval. Fail-closed on every absent or unrecognized claim.
def _escalation_human_client_ids() -> Set[str]:
    """App clients whose ID tokens may represent a human escalation decider.

    ESCALATION_HUMAN_CLIENT_IDS (comma-separated) when set; otherwise the
    interactive PWA client (COGNITO_CLIENT_ID). Read per-call so tests and
    live config changes take effect without module reload.
    """
    raw = (
        os.environ.get("ESCALATION_HUMAN_CLIENT_IDS", "")
        or os.environ.get("COGNITO_CLIENT_ID", "")
    )
    return {part.strip() for part in raw.split(",") if part.strip()}


def _escalation_machine_email_domains() -> Set[str]:
    """Email domains that mark a machine-operated Cognito principal."""
    raw = os.environ.get("ESCALATION_MACHINE_EMAIL_DOMAINS", "enceladus.internal")
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def _is_human_cognito_principal(claims: Dict[str, Any]) -> bool:
    """True only for an interactive human Cognito ID-token principal.

    Rejects (fail-closed, in order):
      - anything but a Cognito ID token (token_use != "id"): access tokens,
        client_credentials/M2M grants, internal-key mode (no token_use);
      - bare machine-client shapes (client_id claim without an aud claim);
      - ID tokens minted for an app client outside the human-client allowlist
        (e.g. the agent M2M client) or when no allowlist is configured;
      - identities whose email is absent or under a machine principal domain
        (e.g. *@enceladus.internal).
    """
    claims = claims or {}
    if str(claims.get("token_use") or "").strip().lower() != "id":
        return False
    if claims.get("client_id") and not claims.get("aud"):
        return False
    aud = claims.get("aud")
    if isinstance(aud, (list, tuple, set)):
        aud_values = {str(a or "").strip() for a in aud}
    else:
        aud_values = {str(aud or "").strip()}
    aud_values.discard("")
    allowed_clients = _escalation_human_client_ids()
    if not allowed_clients or not (aud_values & allowed_clients):
        return False
    email = str(claims.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return False
    domain = email.rsplit("@", 1)[1]
    if domain in _escalation_machine_email_domains():
        return False
    return True


def _deny() -> Dict[str, Any]:
    return {"isAuthorized": False}


def _allow(email: str) -> Dict[str, Any]:
    return {"isAuthorized": True, "context": {"email": email}}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """API Gateway v2 HTTP API Lambda REQUEST authorizer (simple response format)."""
    request_id = (event.get("requestContext") or {}).get("requestId", "")

    claims, error = _authenticate(event)
    if error is not None:
        logger.warning("escalation authorizer: authentication failed (requestId=%s)", request_id)
        return _deny()

    # ENC-TSK-M12 / ENC-ISS-501: structural principal-type gate. Only an
    # interactive human Cognito ID token (token_use=id, human app client,
    # non-machine email domain) may reach the allowlist check at all --
    # access tokens, client_credentials/M2M grants, and machine-operated
    # Cognito users (e.g. terminal-agent@enceladus.internal) are denied
    # here regardless of allowlist contents.
    if not _is_human_cognito_principal(claims):
        logger.warning(
            "escalation authorizer: non-human principal rejected "
            "(requestId=%s, token_use=%r, aud=%r, client_id=%r, email=%r)",
            request_id, (claims or {}).get("token_use"), (claims or {}).get("aud"),
            (claims or {}).get("client_id"), (claims or {}).get("email"),
        )
        return _deny()

    # internal-key / any non-Cognito auth mode carries no email claim and is
    # correctly denied here -- this authorizer only recognizes genuine
    # Cognito-verified human sessions as eligible deciders at all.
    email = str((claims or {}).get("email") or "").strip().lower()
    if not email:
        logger.warning(
            "escalation authorizer: no email claim on verified identity (requestId=%s, auth_mode=%s)",
            request_id, (claims or {}).get("auth_mode"),
        )
        return _deny()

    if email not in _load_escalation_approver_allowlist():
        logger.warning(
            "escalation authorizer: decider email %r not on approver allowlist (requestId=%s)",
            email, request_id,
        )
        return _deny()

    return _allow(email)
