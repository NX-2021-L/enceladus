"""auth_refresh/lambda_function.py

Lambda endpoint for refreshing Cognito tokens and vending GitHub App tokens.

Routes (via API Gateway proxy):
    POST /api/v1/auth/refresh          — Cognito token refresh
    POST /api/v1/auth/logout           — revoke the refresh token, clear the auth cookies (DVP-TSK-B41)
    GET  /api/v1/auth/github-token     — GitHub App installation access token
    OPTIONS /api/v1/auth/*             (CORS preflight)

Auth (POST /refresh):
    Reads the `enceladus_refresh_token` cookie from the Cookie header.
    Calls Cognito InitiateAuth with REFRESH_TOKEN_AUTH flow.
    Returns new id_token as an HttpOnly cookie + session timestamp cookie.

Auth (GET /github-token):
    Requires valid Cognito session cookie (enceladus_id_token).
    Returns a short-lived GitHub App installation access token for
    direct api.github.com reads (read:deployments, actions scopes).

Environment variables:
    COGNITO_USER_POOL_ID        us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID           6q607dk3liirhtecgps7hifmlk
    COGNITO_REGION              default: us-east-1
    COGNITO_HOSTED_LOGOUT       optional kill-switch for the Hosted-UI logout hop: unset/'true' = on,
                                'false' = POST /auth/logout returns logout_url null (DVP-TSK-B41)
    GITHUB_APP_ID               GitHub App numeric ID
    GITHUB_INSTALLATION_ID      Installation ID for NX-2021-L org
    GITHUB_PRIVATE_KEY_SECRET   Secrets Manager secret name (default: devops/github-app/private-key)

CORS:
    Allows https://jreese.net only. Returns CORS headers on every response.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.request
import urllib.error
from typing import Any, Dict, Optional
from urllib.parse import quote, unquote, urlencode, urlparse

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from enceladus_shared.github_app_auth import (
    GitHubAppConfig,
    generate_app_jwt as _shared_generate_app_jwt,
    get_installation_token as _shared_get_installation_token,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

COGNITO_REGION = os.environ.get("COGNITO_REGION", "us-east-1")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "us-east-1_b2D0V3E1k")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "6q607dk3liirhtecgps7hifmlk")
# Lambda deployment region — used for Secrets Manager (secret lives co-located with Lambda)
LAMBDA_REGION = os.environ.get("AWS_REGION", "us-west-2")
CORS_ORIGIN = "https://jreese.net"
ID_TOKEN_MAX_AGE = 3600       # 1 hour
SESSION_COOKIE_MAX_AGE = 3600  # 1 hour
REFRESH_TOKEN_MAX_AGE = 2592000  # 30 days

# ENC-TSK-K95 — gamma cockpit OAuth2 authorization-code callback (GET
# /api/v1/auth/callback). Mirrors the prod auth_edge Lambda@Edge exchange, but
# same-origin behind the gamma API so the v4 cockpit (frontend/ui-v2) can log
# in without a Lambda@Edge. Public app client (no secret). The redirect_uri is
# a FIXED registered Cognito callback (the durable vanity URL); the post-login
# 302 uses a relative Location so the browser returns to whatever host it is
# on. Prod is untouched (it keeps its own edge + jreese.net callback).
#
# DVP-TSK-B24: the PWA login + token exchange run on the managed-login v2
# custom domain (the domain that carries Cognito-native passkeys, WebAuthn RP =
# auth.enceladus.jreese.net). The classic prefix domain stays what the MCP /
# Claude-connector DCR clients use and is kept here ONLY as the token-exchange
# fallback (COGNITO_PREFIX_DOMAIN below); never point the PWA login at it.
COGNITO_CUSTOM_DOMAIN = "https://auth.enceladus.jreese.net"
COGNITO_PREFIX_DOMAIN = "https://enceladus-status-356364570033.auth.us-east-1.amazoncognito.com"
COGNITO_HOSTED_UI_DOMAIN = os.environ.get(
    "COGNITO_HOSTED_UI_DOMAIN",
    COGNITO_CUSTOM_DOMAIN,
)
# DVP-TSK-B41: kill-switch for the Hosted-UI logout hop. The post-logout
# landing URI is derived from WEBUI_OAUTH_REDIRECT_URI (scheme://host/), which
# the PWA app client has registered as a LogoutURL on prod and gamma, so no
# per-environment setting is needed. 'false' makes logout_url null (the SPA
# then just goes to '/'); unset or anything else keeps the hop on.
COGNITO_HOSTED_LOGOUT = os.environ.get("COGNITO_HOSTED_LOGOUT", "")
WEBUI_OAUTH_REDIRECT_URI = os.environ.get(
    "WEBUI_OAUTH_REDIRECT_URI",
    "https://enceladus-gamma.jreese.net/api/v1/auth/callback",
)
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "")
GITHUB_INSTALLATION_ID = os.environ.get("GITHUB_INSTALLATION_ID", "")
GITHUB_PRIVATE_KEY_SECRET = os.environ.get("GITHUB_PRIVATE_KEY_SECRET", "devops/github-app/private-key")
GITHUB_API_BASE = "https://api.github.com"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Cognito client (module-level for container reuse)
# ---------------------------------------------------------------------------

_cognito = None


def _get_cognito():
    global _cognito
    if _cognito is None:
        _cognito = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    return _cognito


# ---------------------------------------------------------------------------
# Cookie extraction
# ---------------------------------------------------------------------------

def _iter_cookie_pairs(event: Dict) -> list[str]:
    """Return normalized cookie key=value entries from headers and API Gateway v2 cookies."""
    pairs: list[str] = []

    headers = event.get("headers") or {}
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    if cookie_header:
        for part in cookie_header.split(";"):
            part = part.strip()
            if part and "=" in part:
                pairs.append(part)

    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        for item in event_cookies:
            if isinstance(item, str) and "=" in item:
                pairs.append(item.strip())
    elif isinstance(event_cookies, str) and "=" in event_cookies:
        pairs.append(event_cookies.strip())

    return pairs


def _extract_refresh_token(event: Dict) -> Optional[str]:
    """Extract enceladus_refresh_token from either Cookie header or event.cookies."""
    for pair in _iter_cookie_pairs(event):
        if not pair.startswith("enceladus_refresh_token="):
            continue
        raw = pair[len("enceladus_refresh_token="):]
        return unquote(raw)
    return None


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie, Authorization, X-Requested-With, X-Io-Mode",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any, extra_headers: Optional[Dict] = None) -> Dict:
    headers = {**_cors_headers(), "Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    return {
        "statusCode": status_code,
        "headers": headers,
        "body": json.dumps(body),
    }


def _error(status_code: int, message: str) -> Dict:
    return _response(status_code, {"success": False, "error": message})


# ---------------------------------------------------------------------------
# GitHub App token vending
# ---------------------------------------------------------------------------

# ENC-TSK-O07 (ENC-ISS-621 C4): minting/caching/retry hardening now lives in
# enceladus_shared.github_app_auth. These wrappers keep the local call
# signatures call sites already use.
_GITHUB_APP_CONFIG = GitHubAppConfig(
    app_id=GITHUB_APP_ID,
    installation_id=GITHUB_INSTALLATION_ID,
    private_key_secret=GITHUB_PRIVATE_KEY_SECRET,
    region=LAMBDA_REGION,
    api_base=GITHUB_API_BASE,
)


def _generate_app_jwt() -> str:
    return _shared_generate_app_jwt(_GITHUB_APP_CONFIG)


def _get_installation_token() -> str:
    return _shared_get_installation_token(_GITHUB_APP_CONFIG)


def _extract_id_token(event: Dict) -> Optional[str]:
    """Extract enceladus_id_token from Cookie header or event.cookies."""
    for pair in _iter_cookie_pairs(event):
        if pair.startswith("enceladus_id_token="):
            return pair[len("enceladus_id_token="):]
    return None


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------

class RefreshRejected(ValueError):
    """Cognito rejected the refresh token (revoked/expired): sign in again."""


class RefreshNetwork(ValueError):
    """Cognito unreachable / transient error: the session is kept (AUTH_NETWORK)."""


def _refresh_tokens(refresh_token: str) -> Dict[str, str]:
    """Call Cognito InitiateAuth with REFRESH_TOKEN_AUTH.

    Returns dict with 'id_token' and 'access_token' on success.
    Raises ValueError on failure.
    """
    cognito = _get_cognito()
    try:
        resp = cognito.initiate_auth(
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={
                "REFRESH_TOKEN": refresh_token,
            },
            ClientId=COGNITO_CLIENT_ID,
        )
    except cognito.exceptions.NotAuthorizedException as exc:
        raise RefreshRejected(f"Refresh token rejected: {exc}") from exc
    except (BotoCoreError, ClientError) as exc:
        raise RefreshNetwork(f"Cognito API error: {exc}") from exc

    result = resp.get("AuthenticationResult") or {}
    id_token = result.get("IdToken")
    if not id_token:
        raise ValueError("No id_token in Cognito response")

    return {
        "id_token": id_token,
        "access_token": result.get("AccessToken", ""),
    }


# ---------------------------------------------------------------------------
# GitHub token handler
# ---------------------------------------------------------------------------

def _handle_github_token(event: Dict) -> Dict:
    id_token = _extract_id_token(event)
    if not id_token:
        return _error(401, "Not authenticated. Sign in first.")

    try:
        gh_token = _get_installation_token()
    except ValueError as exc:
        logger.error("github token vend failed: %s", exc)
        return _error(502, "GitHub token unavailable")

    logger.info("github installation token vended")
    return _response(200, {"token": gh_token, "expires_in": 3600})


# ---------------------------------------------------------------------------
# OAuth2 authorization-code callback (ENC-TSK-K95)
# ---------------------------------------------------------------------------

import base64  # noqa: E402  (grouped with the callback feature)

_AUTH_LOOP_PATHS = ("/api/v1/auth/callback", "/api/v1/auth/login")
# DVP-TSK-B28: fixed OAuth `state` path the SPA sends for "Add a passkey"
# (authorize with prompt=login). It is a plain same-origin relative path, so it
# survives `_safe_return_path` unchanged; the callback matches it EXACTLY.
# Keep in sync with PASSKEY_ADD_STATE_PATH in frontend/ui-v2/src/auth/authConfig.ts.
PASSKEY_ADD_STATE_PATH = "/__passkey_add__"
_MAX_AGE_RE = re.compile(r"[0-9]{1,10}")


def _safe_return_path(path: str) -> str:
    """Return `path` if it is a same-site absolute path, else '/'.

    Shared by the callback (decoded `state`) and the step-up login route
    (`returnTo`) so both apply one rule: starts with '/', not protocol-relative
    '//host', no scheme/host, no backslash (browsers treat '/\\host' as
    '//host'), no control characters, and never the callback or login routes
    (a redirect loop).
    """
    if not path or not path.startswith("/") or path.startswith("//"):
        return "/"
    if "\\" in path or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        return "/"
    parsed = urlparse(path)
    if parsed.scheme or parsed.netloc:
        return "/"
    if path.startswith(_AUTH_LOOP_PATHS):
        return "/"
    return path


def _b64url_decode_path(state: str) -> str:
    """Decode the base64url `state` param (the pre-login path) set by the SPA.

    Falls back to '/' on any decode error or a non-local/callback-looping value
    so a crafted state can never open-redirect off-site.
    """
    if not state:
        return "/"
    try:
        pad = "=" * ((4 - len(state) % 4) % 4)
        decoded = base64.urlsafe_b64decode(state + pad).decode("utf-8")
    except Exception:  # noqa: BLE001
        return "/"
    return _safe_return_path(decoded)


class _TokenExchangeFailed(ValueError):
    """Non-200 from /oauth2/token; `oauth_error` is Cognito's `error` field."""

    def __init__(self, message: str, oauth_error: str = "") -> None:
        super().__init__(message)
        self.oauth_error = oauth_error


def _post_token_exchange(domain: str, code: str) -> Dict[str, Any]:
    """POST the authorization code to `<domain>/oauth2/token` and return the JSON.

    Public client (no secret) — grant_type=authorization_code with
    client_id + code + the fixed registered redirect_uri. Raises
    _TokenExchangeFailed (a ValueError) on an HTTP error, ValueError on an
    unreachable endpoint.
    """
    body = urlencode({
        "grant_type": "authorization_code",
        "client_id": COGNITO_CLIENT_ID,
        "code": code,
        "redirect_uri": WEBUI_OAUTH_REDIRECT_URI,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{domain.rstrip('/')}/oauth2/token",
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        logger.warning("oauth token exchange failed: %s %s", exc.code, detail)
        oauth_error = ""
        try:
            parsed = json.loads(detail)
            if isinstance(parsed, dict):
                oauth_error = str(parsed.get("error") or "")
        except ValueError:
            pass
        raise _TokenExchangeFailed("token_exchange_failed", oauth_error) from exc
    except urllib.error.URLError as exc:
        logger.error("oauth token endpoint unreachable: %s", exc)
        raise ValueError("token_endpoint_unreachable") from exc


def _exchange_code_for_tokens(code: str) -> Dict[str, Optional[str]]:
    """Exchange the authorization code for tokens. Raises ValueError on failure.

    DVP-TSK-B24: exchanges on COGNITO_HOSTED_UI_DOMAIN (the managed-login v2
    custom domain). Authorization codes belong to the pool, so a code issued on
    either domain redeems on either. Safety net: if the first attempt returns
    `invalid_grant` and a different domain is available, retry ONCE against the
    classic prefix domain (the callback cannot tell which domain issued the
    code, so the retry is unconditional on origin).
    """
    try:
        data = _post_token_exchange(COGNITO_HOSTED_UI_DOMAIN, code)
    except _TokenExchangeFailed as exc:
        same = COGNITO_HOSTED_UI_DOMAIN.rstrip("/") == COGNITO_PREFIX_DOMAIN.rstrip("/")
        if exc.oauth_error != "invalid_grant" or same:
            raise
        logger.info("invalid_grant on %s; retrying once on the prefix domain", COGNITO_HOSTED_UI_DOMAIN)
        data = _post_token_exchange(COGNITO_PREFIX_DOMAIN, code)

    id_token = data.get("id_token")
    if not id_token:
        raise ValueError("no_id_token")
    return {"id_token": id_token, "refresh_token": data.get("refresh_token")}


def _passkey_add_url() -> str:
    """Managed-login v2 `/passkeys/add` URL on the custom domain (DVP-TSK-B28).

    Same client id and registered redirect_uri as the token exchange, so the
    return (`?result=...`, no code) lands on this callback again.
    """
    domain = COGNITO_HOSTED_UI_DOMAIN.rstrip("/")
    if domain == COGNITO_PREFIX_DOMAIN.rstrip("/"):
        # Passkeys only exist on the custom domain; never send the user to the
        # classic prefix domain (the token-exchange fallback / MCP domain).
        domain = COGNITO_CUSTOM_DOMAIN.rstrip("/")
    query = urlencode({"client_id": COGNITO_CLIENT_ID, "redirect_uri": WEBUI_OAUTH_REDIRECT_URI})
    return f"{domain}/passkeys/add?{query}"


def _handle_oauth_callback(event: Dict) -> Dict:
    """GET /api/v1/auth/callback — Cognito Hosted-UI redirect lands here.

    Exchanges ?code for tokens, sets the session cookies (host-scoped, matching
    the prod auth_edge format), and 302-redirects to the ?state path.
    """
    params = event.get("queryStringParameters") or {}
    code = params.get("code")
    state = params.get("state") or ""

    # Cognito surfaces auth errors as ?error=...; send the user back to sign in.
    if params.get("error"):
        logger.info("oauth callback error param: %s", params.get("error"))
        return {"statusCode": 302, "headers": {"Location": "/", "Cache-Control": "no-store"}, "body": ""}
    if not code:
        # DVP-TSK-B24: managed login's /passkeys/add returns to this same
        # registered callback with `?result=<success|invalid_session|...>` and
        # no code. Hand the result to the SPA as /?passkey_result=<result>; the
        # session cookies are deliberately untouched. A return with neither
        # code nor result just goes to the app root.
        result = params.get("result")
        location = "/?passkey_result=" + quote(result, safe="") if result else "/"
        logger.info("oauth callback without code; result=%s", result)
        return {"statusCode": 302, "headers": {"Location": location, "Cache-Control": "no-store"}, "body": ""}

    try:
        tokens = _exchange_code_for_tokens(code)
    except ValueError as exc:
        logger.warning("oauth callback exchange failed: %s", exc)
        # Bounce to the app root rather than showing a raw error; the SPA will
        # re-prompt sign-in if still unauthenticated.
        return {"statusCode": 302, "headers": {"Location": "/", "Cache-Control": "no-store"}, "body": ""}

    target = _b64url_decode_path(state)
    now_ms = str(int(time.time() * 1000))

    cookies = [
        f"enceladus_id_token={tokens['id_token']}; "
        f"Path=/; Secure; HttpOnly; SameSite=None; Max-Age={ID_TOKEN_MAX_AGE}",
        f"enceladus_session_at={now_ms}; "
        f"Path=/enceladus; Secure; SameSite=None; Max-Age={SESSION_COOKIE_MAX_AGE}",
    ]
    if tokens.get("refresh_token"):
        cookies.append(
            f"enceladus_refresh_token={tokens['refresh_token']}; "
            f"Path=/; Secure; HttpOnly; SameSite=None; Max-Age={REFRESH_TOKEN_MAX_AGE}"
        )

    if target == PASSKEY_ADD_STATE_PATH:
        # DVP-TSK-B28: the user came from "Add a passkey" and has just completed
        # a fresh sign-in. Cookies are set exactly as for a normal login; the
        # redirect continues to managed login's /passkeys/add, which needs that
        # recent hosted-UI session. Always the custom domain, even if the code
        # exchange fell back to the prefix domain: passkeys only exist there.
        target = _passkey_add_url()

    logger.info("oauth callback succeeded; redirecting to %s", target)
    return {
        "statusCode": 302,
        "headers": {"Location": target, "Cache-Control": "no-store"},
        "cookies": cookies,
        "body": "",
    }


def _handle_login(event: Dict) -> Dict:
    """GET /api/v1/auth/login — step-up / re-login entry (DVP-TSK-B07).

    The @io-kit/auth cognitoAdapter navigates here with
    ?returnTo=<path>&prompt=login&max_age=0 for high/critical actions. We only
    force a real Cognito re-login and bring the user back: 302 to the Hosted-UI
    /oauth2/authorize with `state` = base64url(returnTo), exactly what the SPA's
    buildLoginUrl sends, so the existing callback decodes it unchanged and sets
    the fresh session cookies. Public route; no cookie needed.
    """
    params = event.get("queryStringParameters") or {}
    return_to = _safe_return_path(params.get("returnTo") or "")
    state = base64.urlsafe_b64encode(return_to.encode("utf-8")).decode("ascii").rstrip("=")

    query: Dict[str, str] = {
        "response_type": "code",
        "client_id": COGNITO_CLIENT_ID,
        "redirect_uri": WEBUI_OAUTH_REDIRECT_URI,
        "scope": "openid email profile",
        "state": state,
    }
    if params.get("prompt") == "login":
        query["prompt"] = "login"
    max_age = params.get("max_age")
    if max_age is not None and _MAX_AGE_RE.fullmatch(max_age):
        query["max_age"] = max_age

    location = f"{COGNITO_HOSTED_UI_DOMAIN.rstrip('/')}/oauth2/authorize?{urlencode(query)}"
    logger.info("login redirect; returnTo=%s prompt=%s max_age=%s",
                return_to, query.get("prompt"), query.get("max_age"))
    return {"statusCode": 302, "headers": {"Location": location, "Cache-Control": "no-store"}, "body": ""}


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# DVP-TSK-861: @io-kit/auth edge contract (refresh + manifest)
# ---------------------------------------------------------------------------
# auth_refresh is the auth edge for ui-v2 (cookie mode). The kit client's
# cognitoAdapter calls POST {authEdgeBase}/refresh with X-Requested-With:
# io-kit + a matching Origin and expects 200 {accessToken,idToken,expiresIn,
# exp}, 401 AUTH_REFRESH_FAILED (cookies cleared) or 503 AUTH_NETWORK (cookie
# kept). Requests without that header keep the legacy response unchanged.

KIT_HEADER_VALUE = "io-kit"
ALLOWED_ORIGINS = tuple(
    o.strip()
    for o in os.environ.get(
        "AUTH_ALLOWED_ORIGINS",
        "https://enceladus.jreese.net,https://enceladus-gamma.jreese.net",
    ).split(",")
    if o.strip()
)
MANIFEST_TTL_SECONDS = 300
_POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy_table.json")


def _header(event: Dict, name: str) -> str:
    for k, v in (event.get("headers") or {}).items():
        if k.lower() == name.lower():
            return v or ""
    return ""


def _is_kit_request(event: Dict) -> bool:
    return _header(event, "x-requested-with").lower() == KIT_HEADER_VALUE


def _kit_error(status: int, code: str, message: str, extra_headers: Optional[Dict] = None,
               cookies: Optional[list] = None) -> Dict:
    out = _response(status, {"code": code, "error": message}, {"Cache-Control": "no-store", **(extra_headers or {})})
    if cookies:
        out["cookies"] = cookies
    return out


def _clear_cookies() -> list:
    return [
        "enceladus_id_token=; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=0",
        "enceladus_refresh_token=; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=0",
        "enceladus_session_at=; Path=/enceladus; Secure; SameSite=None; Max-Age=0",
    ]


def _jwt_claims(token: str) -> Dict[str, Any]:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:  # noqa: BLE001 - any malformed token is "no claims"
        return {}


def _handle_kit_refresh(event: Dict) -> Dict:
    origin = _header(event, "origin")
    if origin not in ALLOWED_ORIGINS:
        return _kit_error(403, "AUTH_FORBIDDEN", "origin not allowed")
    refresh_token = _extract_refresh_token(event)
    if not refresh_token:
        return _kit_error(401, "AUTH_REFRESH_FAILED", "no refresh token", cookies=_clear_cookies())
    try:
        tokens = _refresh_tokens(refresh_token)
    except RefreshNetwork as exc:
        logger.warning("kit refresh network failure: %s", exc)
        return _kit_error(503, "AUTH_NETWORK", "identity provider unreachable")
    except ValueError as exc:
        logger.warning("kit refresh rejected: %s", exc)
        return _kit_error(401, "AUTH_REFRESH_FAILED", "refresh rejected", cookies=_clear_cookies())
    id_token = tokens["id_token"]
    exp = int(_jwt_claims(id_token).get("exp") or (time.time() + ID_TOKEN_MAX_AGE))
    now_ms = str(int(time.time() * 1000))
    out = _response(
        200,
        {"accessToken": tokens.get("access_token") or id_token, "idToken": id_token,
         "expiresIn": ID_TOKEN_MAX_AGE, "exp": exp},
        {"Cache-Control": "no-store", "Access-Control-Allow-Origin": origin},
    )
    out["cookies"] = [
        f"enceladus_id_token={id_token}; Path=/; Secure; HttpOnly; SameSite=None; Max-Age={ID_TOKEN_MAX_AGE}",
        f"enceladus_session_at={now_ms}; Path=/enceladus; Secure; SameSite=None; Max-Age={SESSION_COOKIE_MAX_AGE}",
    ]
    return out


# ---------------------------------------------------------------------------
# DVP-TSK-B41: logout (revoke the refresh token + clear every auth cookie)
# ---------------------------------------------------------------------------

def _revoke_refresh_token(refresh_token: str) -> bool:
    """Best-effort POST <hosted-ui>/oauth2/revoke (form: token, client_id).

    Public client, no secret. Returns True when Cognito accepted the revoke.
    Never raises, and never logs the token (only the failure class / HTTP code).
    """
    body = urlencode({"token": refresh_token, "client_id": COGNITO_CLIENT_ID}).encode("utf-8")
    req = urllib.request.Request(
        f"{COGNITO_HOSTED_UI_DOMAIN.rstrip('/')}/oauth2/revoke",
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        return True
    except urllib.error.HTTPError as exc:
        logger.warning("logout revoke rejected: http %s", exc.code)
    except Exception as exc:  # noqa: BLE001 - revoke is best-effort, never fails the logout
        logger.warning("logout revoke failed: %s", type(exc).__name__)
    return False


def _logout_url() -> Optional[str]:
    """Hosted-UI /logout URL that ends the Cognito session and returns to the app.

    logout_uri is the origin of WEBUI_OAUTH_REDIRECT_URI plus '/', a LogoutURL
    registered on the PWA client for prod and gamma. None when the kill-switch
    COGNITO_HOSTED_LOGOUT is 'false' or the redirect URI has no scheme/host.
    """
    if (COGNITO_HOSTED_LOGOUT or "").strip().lower() == "false":
        return None
    parsed = urlparse(WEBUI_OAUTH_REDIRECT_URI)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    query = urlencode({"client_id": COGNITO_CLIENT_ID, "logout_uri": f"{parsed.scheme}://{parsed.netloc}/"})
    return f"{COGNITO_HOSTED_UI_DOMAIN.rstrip('/')}/logout?{query}"


def _handle_logout(event: Dict) -> Dict:
    """POST /api/v1/auth/logout — end the cookie session server-side.

    Same CSRF/origin gate as the kit refresh route: `X-Requested-With: io-kit`
    plus an allow-listed Origin (403 AUTH_FORBIDDEN otherwise, nothing cleared
    or revoked). A valid call revokes the refresh token at Cognito (best-effort)
    and clears every cookie this Lambda sets via Set-Cookie ... Max-Age=0 with
    the exact Path/attributes they were set with, so an HttpOnly refresh cookie
    the page cannot touch no longer survives a log out.
    """
    origin = _header(event, "origin")
    if origin not in ALLOWED_ORIGINS or not _is_kit_request(event):
        return _kit_error(403, "AUTH_FORBIDDEN", "origin or request header not allowed")
    refresh_token = _extract_refresh_token(event)
    revoked = _revoke_refresh_token(refresh_token) if refresh_token else False
    logger.info("logout; refresh_cookie_present=%s revoked=%s", bool(refresh_token), revoked)
    out = _response(
        200,
        {"logged_out": True, "logout_url": _logout_url()},
        {"Cache-Control": "no-store", "Access-Control-Allow-Origin": origin},
    )
    out["cookies"] = _clear_cookies()
    return out


def _load_policy() -> Dict[str, Any]:
    with open(_POLICY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def issue_manifest(claims: Dict[str, Any], table: Dict[str, Any], now: Optional[float] = None) -> Dict[str, Any]:
    """PermissionManifest (kit shape) from the policy table for the caller's groups.

    Display-only: every API handler stays authoritative, and the escalation
    decide path keeps its own three server gates.
    """
    now_s = int(now if now is not None else time.time())
    raw_groups = claims.get("cognito:groups") or []
    groups = [raw_groups] if isinstance(raw_groups, str) else list(raw_groups)
    grants = []
    for action, row in sorted(table["actions"].items()):
        modes = []
        if set(groups) & set(row.get("dry_run", [])) or set(groups) & set(row.get("execute", [])):
            modes.append("dry_run")
        if set(groups) & set(row.get("execute", [])):
            modes.append("execute")
        grant = {"action": action, "modes": modes,
                 "visibilityWhenDenied": row.get("visibilityWhenDenied", "hide")}
        if row.get("requiresStepUp"):
            grant["requiresStepUp"] = True
        grants.append(grant)
    return {
        "principal": {
            "type": "human", "sub": claims.get("sub", ""), "issuer": claims.get("iss", ""),
            "groups": groups, "authTime": int(claims.get("auth_time") or claims.get("iat") or now_s),
            **({"displayName": claims["email"]} if claims.get("email") else {}),
        },
        "policyVersion": table["version"], "issuedAt": now_s, "expiresAt": now_s + MANIFEST_TTL_SECONDS,
        "grants": grants,
    }


def _handle_manifest(event: Dict) -> Dict:
    token = _extract_id_token(event)
    if not token:
        auth = _header(event, "authorization")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else None
    claims = _jwt_claims(token) if token else {}
    if not claims or int(claims.get("exp") or 0) <= time.time() or claims.get("token_use") not in (None, "id", "access"):
        return _kit_error(401, "AUTH_EXPIRED", "not authenticated")
    if claims.get("iss") and not str(claims["iss"]).endswith(COGNITO_USER_POOL_ID):
        return _kit_error(401, "AUTH_EXPIRED", "wrong issuer")
    return _response(200, issue_manifest(claims, _load_policy()), {"Cache-Control": "no-store"})



def lambda_handler(event: Dict, context: Any) -> Dict:
    method = (
        (event.get("requestContext") or {}).get("http", {}).get("method")
        or event.get("httpMethod", "")
    )

    # CORS preflight
    if method == "OPTIONS":
        return {
            "statusCode": 204,
            "headers": _cors_headers(),
            "body": "",
        }

    path = (
        (event.get("requestContext") or {}).get("http", {}).get("path")
        or event.get("path", "")
    )

    if method == "GET" and path.rstrip("/").endswith("/github-token"):
        return _handle_github_token(event)

    # ENC-TSK-K95: Cognito Hosted-UI authorization-code callback for the v4
    # cockpit (same-origin login, no Lambda@Edge).
    if method == "GET" and path.rstrip("/").endswith("/auth/callback"):
        return _handle_oauth_callback(event)

    # DVP-TSK-B07: step-up re-login entry (prompt=login&max_age=0 round trip).
    if method == "GET" and path.rstrip("/").endswith("/auth/login"):
        return _handle_login(event)

    if method == "GET" and path.rstrip("/").endswith("/auth/manifest"):
        return _handle_manifest(event)

    if method != "POST":
        return _error(405, "Method not allowed.")

    # DVP-TSK-B41: real logout (revoke + clear cookies). Before the refresh
    # dispatch: a logout must never fall through to the refresh path.
    if path.rstrip("/").endswith("/auth/logout"):
        return _handle_logout(event)

    if _is_kit_request(event):
        return _handle_kit_refresh(event)

    logger.info("auth refresh request")

    # --- Extract refresh token cookie ---
    refresh_token = _extract_refresh_token(event)
    if not refresh_token:
        logger.info("no refresh token cookie found")
        return _error(401, "No refresh token. Please sign in again.")

    # --- Exchange refresh token for new id_token ---
    try:
        tokens = _refresh_tokens(refresh_token)
    except ValueError as exc:
        logger.warning("refresh failed: %s", exc)
        return _error(401, "refresh_failed")

    # --- Build response with new cookies ---
    id_token = tokens["id_token"]
    now_ms = str(int(time.time() * 1000))

    # Set two cookies: new id_token (HttpOnly) and session timestamp (JS-readable)
    set_cookie_id = (
        f"enceladus_id_token={id_token}; "
        f"Path=/; Secure; HttpOnly; SameSite=None; Max-Age={ID_TOKEN_MAX_AGE}"
    )
    set_cookie_session = (
        f"enceladus_session_at={now_ms}; "
        f"Path=/enceladus; Secure; SameSite=None; Max-Age={SESSION_COOKIE_MAX_AGE}"
    )

    logger.info("refresh succeeded, new id_token issued")

    # API Gateway HTTP API v2 (payload format 2.0) uses the `cookies` field
    # to return multiple Set-Cookie headers in a single response.
    return {
        "statusCode": 200,
        "headers": {
            **_cors_headers(),
            "Content-Type": "application/json",
        },
        "cookies": [set_cookie_id, set_cookie_session],
        "body": json.dumps({
            "success": True,
            "expires_in": ID_TOKEN_MAX_AGE,
        }),
    }
