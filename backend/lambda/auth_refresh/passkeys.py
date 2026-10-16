"""ENC-TSK-Q83 (ruling ES-D2, DOC-DFA5289CA94D): thin passkey management routes.

Hosted by auth_refresh's lambda_function via a one-line hook; the host module is
injected (``d``) so this file never imports lambda_function (no circular import).
"""
import hashlib
import hmac
import re
import time
from typing import Any, Dict, Optional
from urllib.parse import unquote

from botocore.exceptions import BotoCoreError, ClientError

d: Any = None  # hosting module, bound by handle()

# ENC-TSK-Q83 (ruling ES-D2, DOC-DFA5289CA94D): thin passkey management routes
# GET    /api/v1/auth/passkeys              list the user's WebAuthn credentials
# GET    /api/v1/auth/passkeys/fresh-auth   {fresh, auth_time, proof}
# DELETE /api/v1/auth/passkeys/{id}         needs X-Fresh-Auth; never the last passkey
#
# Cognito's list/delete_web_authn_credential take the user's ACCESS token, so the
# HttpOnly refresh cookie is exchanged through the existing refresh grant
# (_refresh_tokens). NOTE: these Cognito APIs require the app-client scope
# `aws.cognito.signin.user.admin` (applied separately, not in this change).
# Same CSRF/origin gate as logout (io-kit header + allow-listed Origin).
#
# Fresh-auth proof = "<issued_at>.<hex HMAC-SHA256>" over sub|auth_time|issued_at,
# keyed with sha256("passkey-fresh-auth:" + refresh_token). The lambda holds no
# other signing secret; the refresh token is an HttpOnly per-user secret the
# client can never read, so the proof is unforgeable by script and stateless.
# It is valid for FRESH_AUTH_WINDOW seconds and only issued when the session's
# Cognito auth_time (unchanged by refresh) is itself within that window.


def handle(host: Any, event: Dict, method: str, path: str) -> Dict:
    global d
    d = host
    return _handle_passkeys(event, method, path)


FRESH_AUTH_WINDOW = 300
_PASSKEY_ID_RE = re.compile(r"^[A-Za-z0-9_\-=.]{1,512}$")


def _fresh_auth_proof(refresh_token: str, sub: str, auth_time: int, issued_at: int) -> str:
    key = hashlib.sha256(("passkey-fresh-auth:" + refresh_token).encode("utf-8")).digest()
    mac = hmac.new(key, f"{sub}|{auth_time}|{issued_at}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{issued_at}.{mac}"


def _fresh_auth_valid(proof: str, refresh_token: str, sub: str, auth_time: int, now: float) -> bool:
    try:
        issued_s, _mac = proof.split(".", 1)
        issued_at = int(issued_s)
    except (ValueError, AttributeError):
        return False
    if not 0 <= now - issued_at <= FRESH_AUTH_WINDOW:
        return False
    return hmac.compare_digest(proof, _fresh_auth_proof(refresh_token, sub, auth_time, issued_at))


def _passkey_session(event: Dict):
    """Returns (ctx, None) or (None, error response). ctx: refresh_token, access_token, sub, auth_time."""
    origin = d._header(event, "origin")
    if origin not in d.ALLOWED_ORIGINS or not d._is_kit_request(event):
        return None, d._kit_error(403, "AUTH_FORBIDDEN", "origin or request header not allowed")
    refresh_token = d._extract_refresh_token(event)
    if not refresh_token:
        return None, d._kit_error(401, "AUTH_REFRESH_FAILED", "no refresh token", cookies=d._clear_cookies())
    try:
        tokens = d._refresh_tokens(refresh_token)
    except d.RefreshNetwork:
        return None, d._kit_error(503, "AUTH_NETWORK", "identity provider unreachable")
    except ValueError:
        return None, d._kit_error(401, "AUTH_REFRESH_FAILED", "refresh rejected", cookies=d._clear_cookies())
    claims = d._jwt_claims(tokens["id_token"])
    auth_time = claims.get("auth_time")
    return {
        "origin": origin, "refresh_token": refresh_token, "access_token": tokens.get("access_token") or "",
        "sub": str(claims.get("sub") or ""),
        "auth_time": int(auth_time) if isinstance(auth_time, (int, float)) and not isinstance(auth_time, bool) else 0,
    }, None


def _passkey_json(ctx: Dict, status: int, body: Any) -> Dict:
    return d._response(status, body, {"Cache-Control": "no-store", "Access-Control-Allow-Origin": ctx["origin"]})


def _list_passkeys(access_token: str) -> list:
    out, token = [], None
    while True:
        kwargs = {"AccessToken": access_token, "MaxResults": 20}
        if token:
            kwargs["NextToken"] = token
        resp = d._get_cognito().list_web_authn_credentials(**kwargs)
        out.extend(resp.get("Credentials") or [])
        token = resp.get("NextToken")
        if not token:
            return out


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if hasattr(value, "isoformat") else (str(value) if value else None)


def _handle_passkeys(event: Dict, method: str, path: str) -> Dict:
    ctx, err = _passkey_session(event)
    if err:
        return err
    tail = path.rstrip("/").split("/auth/passkeys", 1)[1].strip("/")
    try:
        if tail == "" and method == "GET":
            creds = _list_passkeys(ctx["access_token"])
            return _passkey_json(ctx, 200, {"passkeys": [
                {"credential_id": c.get("CredentialId"), "friendly_name": c.get("FriendlyCredentialName"),
                 "created_at": _iso(c.get("CreatedAt")),
                 "last_used_at": _iso(c.get("LastUsedAt"))}  # Cognito exposes no last-used; null today
                for c in creds]})
        if tail == "fresh-auth" and method == "GET":
            now = int(time.time())
            fresh = ctx["auth_time"] > 0 and 0 <= now - ctx["auth_time"] <= FRESH_AUTH_WINDOW
            proof = _fresh_auth_proof(ctx["refresh_token"], ctx["sub"], ctx["auth_time"], now) if fresh else None
            return _passkey_json(ctx, 200, {"fresh": fresh, "auth_time": ctx["auth_time"] or None, "proof": proof})
        if tail and "/" not in tail and tail != "fresh-auth" and method == "DELETE":
            credential_id = unquote(tail)
            if not _PASSKEY_ID_RE.match(credential_id):
                return _passkey_json(ctx, 400, {"error": "invalid_credential_id"})
            if not _fresh_auth_valid(d._header(event, "x-fresh-auth"), ctx["refresh_token"], ctx["sub"],
                                     ctx["auth_time"], time.time()):
                return _passkey_json(ctx, 401, {"error": "fresh_auth_required", "code": "fresh_auth_required"})
            creds = _list_passkeys(ctx["access_token"])
            ids = [c.get("CredentialId") for c in creds]
            if credential_id not in ids:
                return _passkey_json(ctx, 404, {"error": "passkey_not_found"})
            if len(ids) <= 1:
                return _passkey_json(ctx, 409, {"error": "last_passkey", "code": "last_passkey"})
            d._get_cognito().delete_web_authn_credential(AccessToken=ctx["access_token"], CredentialId=credential_id)
            out = _passkey_json(ctx, 204, None)
            out["body"] = ""
            return out
    except (BotoCoreError, ClientError) as exc:
        d.logger.warning("passkey operation failed: %s", exc)
        return _passkey_json(ctx, 502, {"error": "identity_provider_error"})
    return d._kit_error(405, "METHOD_NOT_ALLOWED", "method not allowed")
