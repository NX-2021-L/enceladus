"""ELR identity resolution (ENC-TSK-P75, T-B2 / FR-B4-4..7).

ELR is an ALTERNATE CLIENT for the governed Enceladus HTTP APIs, not a
bypass (see elr_lib.transport's module docstring). Prior to this module,
every ELR write (elr_publish.py) authenticated with nothing more than
whatever internal API key happened to be in the environment -- there was
no way for ELR to present a real governed ENC-SES identity, so it could
never carry a Session Claim ID (sci) and would 403 the moment the
ENC-TSK-J93 SCI gate's grandfather window closes for a run that presents
an ENC-SES-shaped provider.

This module resolves ELR's own identity POSTURE in strict order (AC-1):

  1. "credential-bound" -- an ENC-FTR-074 agent credential is configured
     (``ENCELADUS_AGENT_CREDENTIAL`` env var, or ``~/.enceladus/credential.json``
     when that file is present AND mode 0600). The credential's
     ``credential_id`` + ``agent_type_id`` drive a real
     coordination(agent.register) -> coordination(agent.claim) handshake,
     minting a live ENC-SES session_id + sci for the run.
  2. "internal-key" -- no usable credential, but an internal API key is
     configured (either name; see ``elr_lib.config.COMMON_INTERNAL_KEY_ENV_CHAIN``,
     which as of this task accepts both ``ENCELADUS_COORDINATION_INTERNAL_API_KEY``
     -- checked first, existing convention -- and the newer
     ``ENCELADUS_INTERNAL_API_KEY``).
  3. "unknown" -- neither. Reads still work wherever the endpoint allows
     them (e.g. the health check, which never gates on identity); every
     WRITE is refused *locally*, before any network call, with the
     remediation string in ``WRITE_REMEDIATION``.

This is a CHAIN, not a single mandatory step: any failure while resolving
step 1 (unusable credential source, or a register/claim HTTP failure)
falls through to step 2, and any failure/absence there falls through to
step 3. A misconfigured credential must never wedge ELR into being
unable to do the plain reads it could otherwise still do.

SCI lifecycle (AC-3): a session this run mints is retired
(coordination(agent.retire)) on normal exit -- ``finalize_identity()`` --
unless the caller passed ``--keep-session``, in which case the session
(session_id/sci/sci_issued_at/sci_ttl_seconds) is cached in
``~/.enceladus/session.json`` (written 0600) and reused by a later
invocation until the sci is close to its TTL. A governed WRITE that comes
back 403 SCI_REQUIRED with sci_failure_mode ``expired_sci`` or
``revoked_sci`` triggers exactly one re-claim (``reclaim()``, calling
coordination(agent.claim) again for the SAME session_id -- the same
client-side pattern already established by
backend/lambda/rhythm_cycle/identity.py's ``_reclaim_identity`` for this
exact scenario) and exactly one retry of the original call.

IMPORTANT -- agent.retire is SESSION lifecycle, not TASK lifecycle. This
module (and ``finalize_identity()`` in particular) must NEVER grow a
``checkout.release`` / ``checkout.advance`` / any task-status call. ELR's
charter (ENC-FTR-134 AC-9) is that it never issues checkout.* or other
task-lifecycle actions -- retiring the ENC-SES session ELR itself
registered is orthogonal to, and carries no opinion about, the state of
any tracker task a caller might separately be working against.

Python 3.11 standard library only. Nothing here imports server.py; ELR
must run standalone on any workstation.
"""

from __future__ import annotations

import json
import os
import stat
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import config as elr_config
from . import transport as elr_transport

# --- Credential / session cache sources ---------------------------------
# Module-level constants, looked up dynamically (never bound as a default
# parameter value) so tests can monkeypatch them to a tmp path with
# unittest.mock.patch.object(identity, "CREDENTIAL_FILE_PATH", tmp_path)
# without needing to thread a path through every call site.
AGENT_CREDENTIAL_ENV = "ENCELADUS_AGENT_CREDENTIAL"
CREDENTIAL_FILE_PATH = Path("~/.enceladus/credential.json")
SESSION_CACHE_FILE_PATH = Path("~/.enceladus/session.json")

REQUIRED_FILE_MODE = 0o600

POSTURE_CREDENTIAL_BOUND = "credential-bound"
POSTURE_INTERNAL_KEY = "internal-key"
POSTURE_UNKNOWN = "unknown"
VALID_POSTURES = (POSTURE_CREDENTIAL_BOUND, POSTURE_INTERNAL_KEY, POSTURE_UNKNOWN)

# AC-1's exact remediation string -- returned verbatim on every locally
# refused write while posture is "unknown". Do not reword.
WRITE_REMEDIATION = "provision an agent credential (ENC-FTR-074) or set ENCELADUS_INTERNAL_API_KEY"

ELR_RUNTIME_ENV = "ELR_RUNTIME"
DEFAULT_ELR_RUNTIME = "elr"

# Re-claim/refresh a cached session this many seconds before its sci's TTL
# actually elapses, mirroring backend/lambda/rhythm_cycle/identity.py's
# own _SCI_RENEW_SKEW_SECONDS -- SCI_TTL_SECONDS defaults to 86400
# server-side, so this skew is a small, safe fraction of that.
SCI_RENEW_SKEW_SECONDS = 300

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# The two sci_failure_mode values that mean "this SCI is no longer good
# but the SESSION itself may still be" -- worth one re-claim. Every other
# failure mode (missing_sci, unknown_sci, wrong_token_type,
# session_mismatch, unknown_session) means retrying with a re-claimed sci
# cannot help (e.g. the session id itself is unknown), so those are
# surfaced as-is rather than spending a network round trip on a retry
# that cannot succeed.
RECLAIMABLE_SCI_FAILURE_MODES = frozenset({"expired_sci", "revoked_sci"})


def _parse_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


@dataclass
class IdentityContext:
    """The resolved identity for one ELR run.

    ``posture`` is always one of VALID_POSTURES. The session/sci/
    agent_type_id/credential_id fields are populated only when
    posture == POSTURE_CREDENTIAL_BOUND; they are empty/zero otherwise.
    """

    posture: str
    session_id: str = ""
    sci: str = ""
    sci_issued_at: str = ""
    sci_ttl_seconds: int = 0
    agent_type_id: str = ""
    credential_id: str = ""
    registered_this_run: bool = False
    reclaim_count: int = 0
    anomalies: List[str] = field(default_factory=list)

    def sci_ttl_remaining_s(self, *, now: Optional[datetime] = None) -> Optional[int]:
        """Seconds remaining before the current sci's TTL elapses, or None
        when not credential-bound / no sci is held. Never negative.
        """
        if self.posture != POSTURE_CREDENTIAL_BOUND or not self.sci_issued_at or not self.sci_ttl_seconds:
            return None
        issued = _parse_iso(self.sci_issued_at)
        if issued is None:
            return None
        current = now or datetime.now(timezone.utc)
        remaining = self.sci_ttl_seconds - (current - issued).total_seconds()
        return max(int(remaining), 0)

    def write_source(self) -> Dict[str, str]:
        """The write_source fragment (AC-2) a governed write should carry:
        {"provider": <session_id>} when credential-bound, otherwise empty
        -- a non-credential-bound run never forges an ENC-SES provider it
        does not hold.
        """
        if self.posture == POSTURE_CREDENTIAL_BOUND and self.session_id:
            return {"provider": self.session_id}
        return {}


# ---------------------------------------------------------------------------
# Credential source resolution (AC-1, strict order: env var, then file)
# ---------------------------------------------------------------------------


def _validate_credential_shape(parsed: Dict[str, Any], *, source: str) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    credential_id = str(parsed.get("credential_id") or "").strip()
    agent_type_id = str(parsed.get("agent_type_id") or "").strip()
    if not credential_id or not agent_type_id:
        return None, f"{source} is missing credential_id and/or agent_type_id -- ignoring"
    return {"credential_id": credential_id, "agent_type_id": agent_type_id}, None


def _load_credential_from_env() -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    raw = os.environ.get(AGENT_CREDENTIAL_ENV, "").strip()
    if not raw:
        return None, None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"{AGENT_CREDENTIAL_ENV} is not valid JSON ({exc}) -- ignoring"
    if not isinstance(parsed, dict):
        return None, f"{AGENT_CREDENTIAL_ENV} must decode to a JSON object -- ignoring"
    return _validate_credential_shape(parsed, source=f"env:{AGENT_CREDENTIAL_ENV}")


def _load_credential_from_file(path: Optional[Path] = None) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    """AC-1: the credential file must be mode 0600 or it is refused --
    never read, not even to check its JSON shape. Absent is not an error
    (there's simply nothing here to use); present-but-insecure IS an
    error the caller must be told about (a remediation-carrying warning),
    since silently ignoring an insecure credential file would hide a
    real misconfiguration from the operator.
    """
    target = (path or CREDENTIAL_FILE_PATH).expanduser()
    try:
        st = target.stat()
    except OSError:
        return None, None
    mode = stat.S_IMODE(st.st_mode)
    if mode != REQUIRED_FILE_MODE:
        return None, (
            f"refusing to read {target} -- mode is {oct(mode)}, must be 0600 (run: chmod 600 {target})"
        )
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"{target} could not be read: {exc} -- ignoring"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"{target} is not valid JSON ({exc}) -- ignoring"
    if not isinstance(parsed, dict):
        return None, f"{target} must decode to a JSON object -- ignoring"
    return _validate_credential_shape(parsed, source=str(target))


def load_agent_credential() -> Tuple[Optional[Dict[str, str]], List[str]]:
    """AC-1 source order: ENCELADUS_AGENT_CREDENTIAL env var (a JSON object
    string carrying credential_id + agent_type_id), then
    ~/.enceladus/credential.json (same shape, 0600-enforced).

    Returns (credential_or_None, warnings). A warning is produced only
    when a source was PRESENT but unusable, so a misconfigured credential
    is never silently swallowed even though resolution still falls
    through to the next posture.
    """
    warnings: List[str] = []
    credential, warning = _load_credential_from_env()
    if credential is not None:
        return credential, warnings
    if warning:
        warnings.append(warning)

    credential, warning = _load_credential_from_file()
    if credential is not None:
        return credential, warnings
    if warning:
        warnings.append(warning)
    return None, warnings


# ---------------------------------------------------------------------------
# internal-key posture detection
# ---------------------------------------------------------------------------


def _internal_key_configured() -> bool:
    """True iff any name in elr_lib.config.COMMON_INTERNAL_KEY_ENV_CHAIN is
    set. That chain is the single source of truth for "which env var
    names count as an internal key" -- it now includes both the existing
    ENCELADUS_COORDINATION_INTERNAL_API_KEY (checked first) and this AC's
    ENCELADUS_INTERNAL_API_KEY (see elr_lib/config.py), so this function
    and the actual per-request key InternalProfileConfig attaches can
    never disagree about what counts as "configured".
    """
    return any(os.environ.get(name, "").strip() for name in elr_config.COMMON_INTERNAL_KEY_ENV_CHAIN)


# ---------------------------------------------------------------------------
# Session cache (~/.enceladus/session.json, --keep-session)
# ---------------------------------------------------------------------------


def _read_session_cache(path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    target = (path or SESSION_CACHE_FILE_PATH).expanduser()
    try:
        st = target.stat()
    except OSError:
        return None
    # Never trust an insecurely-permissioned cache either -- same
    # discipline as the credential file, just without a warning (a stale
    # cache with bad perms simply means "mint fresh", not "misconfigured
    # by the operator" the way a bad credential file is).
    if stat.S_IMODE(st.st_mode) != REQUIRED_FILE_MODE:
        return None
    try:
        parsed = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _write_session_cache(identity: IdentityContext, path: Optional[Path] = None) -> None:
    target = (path or SESSION_CACHE_FILE_PATH).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = {
        "session_id": identity.session_id,
        "sci": identity.sci,
        "sci_issued_at": identity.sci_issued_at,
        "sci_ttl_seconds": identity.sci_ttl_seconds,
        "agent_type_id": identity.agent_type_id,
        "credential_id": identity.credential_id,
    }
    # Open with the target mode from creation (O_CREAT mode=0600) rather
    # than write-then-chmod, so the file is never briefly world/group
    # readable in between.
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, REQUIRED_FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(payload))
    os.chmod(str(target), REQUIRED_FILE_MODE)  # belt-and-suspenders vs. a restrictive umask


def _clear_session_cache(path: Optional[Path] = None) -> None:
    target = (path or SESSION_CACHE_FILE_PATH).expanduser()
    try:
        target.unlink()
    except OSError:
        pass


def _cache_is_fresh(cached: Dict[str, Any], credential_id: str) -> bool:
    if str(cached.get("credential_id") or "") != credential_id:
        return False
    if not cached.get("session_id") or not cached.get("sci"):
        return False
    issued = _parse_iso(str(cached.get("sci_issued_at") or ""))
    try:
        ttl = int(cached.get("sci_ttl_seconds") or 0)
    except (TypeError, ValueError):
        return False
    if issued is None or ttl <= 0:
        return False
    age = (datetime.now(timezone.utc) - issued).total_seconds()
    return age < max(ttl - SCI_RENEW_SKEW_SECONDS, 0)


# ---------------------------------------------------------------------------
# coordination(agent.*) calls -- POST /agents/sessions[...], the SAME
# routes tools/enceladus-mcp-server/server.py's _agent_register /
# _agent_claim / _agent_retire hit via _coordination_api_request.
# ---------------------------------------------------------------------------


def _elr_runtime() -> str:
    return os.environ.get(ELR_RUNTIME_ENV, "").strip() or DEFAULT_ELR_RUNTIME


def _register_session(
    client: "elr_transport.InternalClient", credential_id: str, agent_type_id: str
) -> Tuple[bool, Dict[str, Any], str]:
    payload = {"agent_type_id": agent_type_id, "runtime": _elr_runtime(), "credential_id": credential_id}
    status, body = client.request("POST", "coordination", "/agents/sessions", payload=payload)
    if status != 201 or not isinstance(body, dict):
        return False, {}, f"agent.register failed (status={status})"
    session = body.get("session")
    if not isinstance(session, dict) or not session.get("session_id"):
        return False, {}, "agent.register returned no session_id"
    return True, session, ""


def _claim_session(
    client: "elr_transport.InternalClient", session_id: str, agent_type_id: str
) -> Tuple[bool, Dict[str, Any], str]:
    payload: Dict[str, Any] = {"session_id": session_id}
    if agent_type_id:
        payload["expected_agent_type_id"] = agent_type_id
    status, body = client.request("POST", "coordination", "/agents/sessions/claim", payload=payload)
    if status != 200 or not isinstance(body, dict) or not body.get("sci"):
        return False, {}, f"agent.claim failed (status={status})"
    return True, body, ""


def _retire_session(client: "elr_transport.InternalClient", session_id: str) -> Tuple[bool, str]:
    encoded = urllib.parse.quote(session_id, safe="")
    status, _body = client.request("POST", "coordination", f"/agents/sessions/{encoded}/retire")
    if status != 200:
        return False, f"agent.retire failed (status={status})"
    return True, ""


def _coordination_client(profile_name: str, timeout: int) -> "elr_transport.InternalClient":
    return elr_transport.InternalClient(elr_config.get_profile(profile_name), timeout=timeout)


def _identity_from_claim(credential: Dict[str, str], session_id: str, claim_body: Dict[str, Any], *, registered_this_run: bool) -> IdentityContext:
    return IdentityContext(
        posture=POSTURE_CREDENTIAL_BOUND,
        session_id=session_id,
        sci=str(claim_body.get("sci") or ""),
        sci_issued_at=str(claim_body.get("sci_issued_at") or ""),
        sci_ttl_seconds=int(claim_body.get("sci_ttl_seconds") or 0),
        agent_type_id=credential["agent_type_id"],
        credential_id=credential["credential_id"],
        registered_this_run=registered_this_run,
    )


def _resolve_credential_bound(
    credential: Dict[str, str], client: "elr_transport.InternalClient", *, keep_session: bool
) -> Optional[IdentityContext]:
    cached = _read_session_cache()
    if cached and _cache_is_fresh(cached, credential["credential_id"]):
        return IdentityContext(
            posture=POSTURE_CREDENTIAL_BOUND,
            session_id=str(cached["session_id"]),
            sci=str(cached["sci"]),
            sci_issued_at=str(cached["sci_issued_at"]),
            sci_ttl_seconds=int(cached["sci_ttl_seconds"]),
            agent_type_id=credential["agent_type_id"],
            credential_id=credential["credential_id"],
            registered_this_run=False,
        )

    ok, session, _err = _register_session(client, credential["credential_id"], credential["agent_type_id"])
    if not ok:
        return None
    session_id = str(session["session_id"])

    # A register that succeeds but whose claim fails leaves an orphaned
    # 'allocated' session -- not cleaned up here. The backend's own
    # unclaim-TTL sweep (ENC-ISS-441 / ENC-TSK-J94,
    # AGENT_SESSIONS_UNCLAIM_SWEEP_ENABLED) reaps exactly this shape of
    # ghost registration after AGENT_SESSIONS_UNCLAIM_TTL_MINUTES; ELR
    # does not need (and, being credential-bound-claim-less at this
    # point, has no sci to) retire it itself.
    ok, claim_body, _err = _claim_session(client, session_id, credential["agent_type_id"])
    if not ok:
        return None

    identity = _identity_from_claim(credential, session_id, claim_body, registered_this_run=True)
    if keep_session:
        _write_session_cache(identity)
    return identity


def resolve_identity(
    *,
    profile_name: str = "internal",
    timeout: int = 20,
    keep_session: bool = False,
    client: Optional["elr_transport.InternalClient"] = None,
) -> IdentityContext:
    """AC-1: resolve ELR's identity posture in strict order. See the
    module docstring for the full chain semantics (this is a fallback
    CHAIN: a failure at a higher-priority step falls through to the
    next, it does not abort resolution).
    """
    anomalies: List[str] = []
    credential, warnings = load_agent_credential()
    anomalies.extend(warnings)

    if credential is not None:
        active_client = client or _coordination_client(profile_name, timeout)
        identity = _resolve_credential_bound(credential, active_client, keep_session=keep_session)
        if identity is not None:
            identity.anomalies = anomalies + identity.anomalies
            return identity
        anomalies.append("credential-bound resolution failed (register/claim) -- falling back")

    if _internal_key_configured():
        return IdentityContext(posture=POSTURE_INTERNAL_KEY, anomalies=anomalies)

    return IdentityContext(posture=POSTURE_UNKNOWN, anomalies=anomalies)


def reclaim(identity: IdentityContext, client: "elr_transport.InternalClient") -> bool:
    """Re-claim the CURRENT session (agent.claim called again for the same
    session_id) after a 403 SCI_REQUIRED/{expired_sci,revoked_sci}, to
    mint a fresh sci. Mutates ``identity`` in place and bumps
    ``reclaim_count``. Mirrors backend/lambda/rhythm_cycle/identity.py's
    ``_reclaim_identity`` client pattern -- same call, same session_id;
    ELR does not invent a new server contract here. Returns True on
    success.
    """
    if identity.posture != POSTURE_CREDENTIAL_BOUND or not identity.session_id:
        return False
    ok, claim_body, err = _claim_session(client, identity.session_id, identity.agent_type_id)
    if not ok:
        identity.anomalies.append(f"reclaim-failed: {err}")
        return False
    identity.sci = str(claim_body.get("sci") or "")
    identity.sci_issued_at = str(claim_body.get("sci_issued_at") or "")
    identity.sci_ttl_seconds = int(claim_body.get("sci_ttl_seconds") or 0)
    identity.reclaim_count += 1
    return True


def finalize_identity(
    identity: IdentityContext,
    client: Optional["elr_transport.InternalClient"] = None,
    *,
    keep_session: bool,
    profile_name: str = "internal",
    timeout: int = 20,
) -> None:
    """AC-3: called once, at normal exit. SESSION lifecycle only -- see
    the module docstring's warning about task lifecycle.

      * Not credential-bound: no-op (nothing was minted).
      * --keep-session: cache the session (0600) for a later invocation
        to reuse; do NOT retire it.
      * otherwise: coordination(agent.retire) the session this run is
        holding (whether freshly registered this run or reused from an
        earlier --keep-session cache), then drop the stale cache file so
        a later invocation cannot resurrect an already-retired session
        id. Best-effort: a retire failure is recorded as an anomaly, it
        never raises -- a coordination-API hiccup on the way out must
        not turn a successful run into a crash.
    """
    if identity.posture != POSTURE_CREDENTIAL_BOUND or not identity.session_id:
        return
    if keep_session:
        _write_session_cache(identity)
        return

    active_client = client or _coordination_client(profile_name, timeout)
    ok, err = _retire_session(active_client, identity.session_id)
    if not ok:
        identity.anomalies.append(f"retire-failed: {err}")
    _clear_session_cache()


# ---------------------------------------------------------------------------
# Governed-call carriage (AC-2) + local write refusal (AC-1) + one-retry
# re-claim (AC-3), for governed WRITE paths (today: elr_publish.py) to
# route their PUT/PATCH/POST/DELETE calls through instead of calling
# InternalClient.request() directly.
# ---------------------------------------------------------------------------


def _sci_failure_mode(body: Any) -> str:
    """The checkout_service / tracker_mutation SCI gate's 403 envelope
    spreads its ``details`` dict onto the TOP level of the response body
    (see backend/lambda/checkout_service/lambda_function.py's _error():
    ``body.update(details)``) in addition to nesting it under
    error_envelope.details -- check both shapes defensively.
    """
    if not isinstance(body, dict):
        return ""
    mode = body.get("sci_failure_mode")
    if mode:
        return str(mode)
    envelope = body.get("error_envelope")
    if isinstance(envelope, dict):
        details = envelope.get("details")
        if isinstance(details, dict) and details.get("sci_failure_mode"):
            return str(details["sci_failure_mode"])
    return ""


def _augment_write_payload(identity: IdentityContext, payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """AC-2: every governed call carries sci in the body and
    provider=<session_id> in write_source when credential-bound. A
    caller-supplied write_source (unlikely for ELR today, but future
    proof) is preserved except for the provider key, which this identity
    always owns when credential-bound.
    """
    merged: Dict[str, Any] = dict(payload or {})
    if identity.posture == POSTURE_CREDENTIAL_BOUND and identity.session_id:
        merged["sci"] = identity.sci
        write_source = dict(merged.get("write_source") or {})
        write_source.update(identity.write_source())
        merged["write_source"] = write_source
    return merged


def governed_call(
    identity: IdentityContext,
    client: "elr_transport.InternalClient",
    method: str,
    api: str,
    path: str = "",
    *,
    payload: Optional[Dict[str, Any]] = None,
    query: Optional[Dict[str, Any]] = None,
) -> Tuple[int, Any, Dict[str, Any]]:
    """Issue one call through ``client``, applying AC-1/AC-2/AC-3 identity
    discipline for WRITE verbs (POST/PUT/PATCH/DELETE); GET (and any
    other non-write verb) passes straight through to
    ``client.request()`` unchanged -- reads are never locally refused and
    never carry sci/write_source (the SCI gate only ever guards
    mutations).

    Returns (status, body, meta). ``meta`` is always
    {"refused": bool, "refusal_reason": str|None, "retried": bool} so a
    caller's digest can report exactly what happened without
    re-deriving it. When "refused" is True, status/body are a LOCAL
    stand-in (status=0) -- no network call was made.
    """
    method_upper = method.upper()
    if method_upper not in WRITE_METHODS:
        status, body = client.request(method_upper, api, path, payload=payload, query=query)
        return status, body, {"refused": False, "refusal_reason": None, "retried": False}

    if identity.posture == POSTURE_UNKNOWN:
        return (
            0,
            {"error": WRITE_REMEDIATION},
            {"refused": True, "refusal_reason": WRITE_REMEDIATION, "retried": False},
        )

    effective_payload = _augment_write_payload(identity, payload)
    status, body = client.request(method_upper, api, path, payload=effective_payload, query=query)

    if identity.posture == POSTURE_CREDENTIAL_BOUND and status == 403:
        failure_mode = _sci_failure_mode(body)
        if failure_mode in RECLAIMABLE_SCI_FAILURE_MODES and reclaim(identity, client):
            retry_payload = _augment_write_payload(identity, payload)
            status, body = client.request(method_upper, api, path, payload=retry_payload, query=query)
            return status, body, {"refused": False, "refusal_reason": None, "retried": True}

    return status, body, {"refused": False, "refusal_reason": None, "retried": False}
