"""Governed machine identity for the rhythm cycle beat (ENC-TSK-N21 / BRD DOC-44230223DD1C §4.3).

Prior to this module, the rhythm wrote escalations under a hardcoded
pseudo-identity (``requested_by_session="rhythm-decide-beat"``) that never
resolved to a real governed ENC-SES session and could never carry a Session
Claim ID (sci). That is a dead end under the FTR-122 SCI gate contract: any
beat-originated write that must present a real session + sci would 403/fail
closed the moment the gate's grandfather window closes.

This module resolves-or-mints a governed identity for the rhythm Lambda
itself, using the same coordination-API HTTP surface (COORDINATION_API_BASE +
config.internal_headers()) the beat already reaches for dispatch-plan
dry-runs (tiers/decide.py):

* ``POST {COORDINATION_API_BASE}/coordination/agents/sessions`` — agent.register
* ``POST {COORDINATION_API_BASE}/coordination/agents/sessions/claim`` — agent.claim,
  which mints the session's Session Claim ID (sci)

The resolved identity (session_id, agent_type_id, sci, sci_issued_at,
sci_ttl_seconds) is cached in the beat's own S3 artifact chain (tier=
"identity", via artifact_store) so that successor beat invocations reuse it
rather than re-minting a session on every cold start, and the sci is
re-claimed once its TTL is close to elapsing.

Identity minting is entirely best-effort: RHYTHM_AGENT_TYPE_ID unset,
COORDINATION_API_BASE unset, or any HTTP failure all degrade to
``{"session_id": "", "sci": "", "degraded": True, ...}`` with a logged
WARNING rather than a raised exception — a coordination-API outage or an
un-minted agent type must never block a beat from running.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from artifact_store import read_latest, write_artifact
from config import COORDINATION_API_BASE, RHYTHM_AGENT_TYPE_ID, RHYTHM_RUNTIME
from http_client import post_json

logger = logging.getLogger(__name__)

_IDENTITY_TIER = "identity"

# Re-claim this many seconds before the cached sci's TTL actually elapses, so
# a long-running beat never straddles expiry mid-invocation (agent_id_alloc's
# SCI_TTL_SECONDS default is 86400 — a 300s skew is a small fraction of that).
_SCI_RENEW_SKEW_SECONDS = 300


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _sci_expired(cached: Dict[str, Any]) -> bool:
    issued = _parse_iso(str(cached.get("sci_issued_at") or ""))
    ttl = int(cached.get("sci_ttl_seconds") or 0)
    if issued is None or ttl <= 0:
        return True
    age = (_now() - issued).total_seconds()
    return age >= max(ttl - _SCI_RENEW_SKEW_SECONDS, 0)


def _degraded(reason: str, session_id: str = "") -> Dict[str, Any]:
    logger.warning("rhythm identity resolution degraded: %s", reason)
    return {
        "session_id": session_id,
        "agent_type_id": RHYTHM_AGENT_TYPE_ID,
        "sci": "",
        "sci_issued_at": "",
        "sci_ttl_seconds": 0,
        "degraded": True,
        "reason": reason,
    }


def _register_session() -> Dict[str, Any]:
    """POST {COORDINATION_API_BASE}/coordination/agents/sessions — agent.register."""
    url = f"{COORDINATION_API_BASE}/coordination/agents/sessions"
    resp = post_json(
        url,
        {
            "agent_type_id": RHYTHM_AGENT_TYPE_ID,
            "runtime": RHYTHM_RUNTIME,
            "parent_session_id": "root",
        },
    )
    return resp.get("session") or {}


def _claim_session(session_id: str) -> Dict[str, Any]:
    """POST {COORDINATION_API_BASE}/coordination/agents/sessions/claim — agent.claim."""
    url = f"{COORDINATION_API_BASE}/coordination/agents/sessions/claim"
    return post_json(
        url,
        {"session_id": session_id, "expected_agent_type_id": RHYTHM_AGENT_TYPE_ID},
    )


def _mint_identity() -> Dict[str, Any]:
    session = _register_session()
    session_id = str(session.get("session_id") or "")
    if not session_id:
        raise RuntimeError("agent.register returned no session_id")
    claim = _claim_session(session_id)
    sci = str(claim.get("sci") or "")
    if not sci:
        raise RuntimeError(f"agent.claim for {session_id} returned no sci")
    return {
        "session_id": session_id,
        "agent_type_id": RHYTHM_AGENT_TYPE_ID,
        "sci": sci,
        "sci_issued_at": str(claim.get("sci_issued_at") or ""),
        "sci_ttl_seconds": int(claim.get("sci_ttl_seconds") or 0),
        "degraded": False,
        "reason": "",
    }


def _reclaim_identity(session_id: str) -> Dict[str, Any]:
    claim = _claim_session(session_id)
    sci = str(claim.get("sci") or "")
    if not sci:
        raise RuntimeError(f"re-claim of {session_id} returned no sci")
    return {
        "session_id": session_id,
        "agent_type_id": RHYTHM_AGENT_TYPE_ID,
        "sci": sci,
        "sci_issued_at": str(claim.get("sci_issued_at") or ""),
        "sci_ttl_seconds": int(claim.get("sci_ttl_seconds") or 0),
        "degraded": False,
        "reason": "",
    }


def resolve_identity() -> Dict[str, Any]:
    """Resolve-or-mint the rhythm's governed identity, cached in the beat artifact chain.

    Returns a dict with session_id/agent_type_id/sci/sci_issued_at/sci_ttl_seconds
    and degraded=False on success. On any failure (unconfigured, gated agent
    type, HTTP error) returns degraded=True with an empty sci (and, when a
    prior session_id is cached, that session_id is carried through so callers
    can log which identity they *would* have used) — callers must treat
    ``degraded`` (or an empty ``sci``) as "identity unavailable" and fall back
    to their pre-N21 behavior rather than raise.
    """
    if not COORDINATION_API_BASE:
        return _degraded("COORDINATION_API_BASE unconfigured")
    if not RHYTHM_AGENT_TYPE_ID:
        return _degraded(
            "RHYTHM_AGENT_TYPE_ID unset — rhythm_cycle agent type not minted/wired "
            "(see ENC-TSK-N21 report; escalations fall back to pre-N21 behavior)"
        )

    cached = read_latest(_IDENTITY_TIER) or {}
    session_id = str(cached.get("session_id") or "")

    if session_id and not _sci_expired(cached):
        return cached

    try:
        identity = _reclaim_identity(session_id) if session_id else _mint_identity()
    except Exception as exc:  # noqa: BLE001 - identity minting must never block a beat
        return _degraded(str(exc), session_id=session_id)

    write_artifact(_IDENTITY_TIER, identity, _now())
    return identity
