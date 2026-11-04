"""ELR client-side timing headers and local ledger (ENC-TSK-S26-0B).

Implements the ``client_side`` fields of BRD DOC-E32D0ED08473 section 7.2.
Every transport call (InternalClient and McpHttpClient) sends the same
request-header set so the server can correlate its own timing against what
the client measured, and appends one JSON line per call to a local ledger.

Request headers (``headers_for``):

    X-Correlation-Id            uuid4 (or ELR_CORRELATION_ID / caller kwarg)
    X-Enc-T-Client-Start        epoch milliseconds, integer string
    X-Enc-Client-Session-Reused "0" / "1"
    X-Enc-Client-Session-Init-Ms integer milliseconds
    X-Enc-Client-Tls-New        "0" / "1"
    X-Enc-Client-Serialize-Ms   integer milliseconds
    X-Enc-Surface               "elr"

Ledger: ``~/.enceladus/elr/ledger/client_timing.jsonl`` (override with
``ELR_LEDGER_PATH``, disable with ``ELR_LEDGER=0``). Ledger rows carry
timings and routing facts only -- never a header value, so neither the
Authorization bearer nor the internal key can reach disk through here.

Long-lived mode (ENC-TSK-S28-0B): the transport keeps connections alive and
runs the MCP handshake once per process, so ``client_session_reused`` is true
on every MCP call after the first, ``client_tls_new`` is true only when the
call actually opened a connection (the pool reports it per send attempt), and
``client_session_init_ms`` is the one-time initialize + initialized cost.
With ELR_LONG_LIVED=0 the legacy per-call urllib behaviour (tls_new always
true) is unchanged.

Stdlib only.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

SURFACE = "elr"
ENV_CORRELATION_ID = "ELR_CORRELATION_ID"
ENV_LEDGER_PATH = "ELR_LEDGER_PATH"
ENV_LEDGER_TOGGLE = "ELR_LEDGER"
DEFAULT_LEDGER_PATH = os.path.join("~", ".enceladus", "elr", "ledger", "client_timing.jsonl")

H_CORRELATION_ID = "X-Correlation-Id"
H_T_CLIENT_START = "X-Enc-T-Client-Start"
H_SESSION_REUSED = "X-Enc-Client-Session-Reused"
H_SESSION_INIT_MS = "X-Enc-Client-Session-Init-Ms"
H_TLS_NEW = "X-Enc-Client-Tls-New"
H_SERIALIZE_MS = "X-Enc-Client-Serialize-Ms"
H_SURFACE = "X-Enc-Surface"
TIMING_HEADER_NAMES = (
    H_CORRELATION_ID,
    H_T_CLIENT_START,
    H_SESSION_REUSED,
    H_SESSION_INIT_MS,
    H_TLS_NEW,
    H_SERIALIZE_MS,
    H_SURFACE,
)

LEDGER_KEYS = (
    "correlation_id",
    "t_client_start",
    "t_client_end",
    "client_total_ms",
    "client_session_reused",
    "client_session_init_ms",
    "client_tls_new",
    "client_serialize_ms",
    "response_bytes",
    "method",
    "verb",
    "host",
    "status",
    "surface",
)

# ---------------------------------------------------------------------------
# Per-process context
# ---------------------------------------------------------------------------

_LOCK = threading.Lock()
# kind ("internal" / "mcp") -> True once a payload-bearing call has been made.
_USED: Dict[str, bool] = {}
# Milliseconds spent in initialize + notifications/initialized that have not
# yet been attributed to a tools/call.
_PENDING_INIT_MS = 0


def reset_process_context() -> None:
    """Forget session state (tests, or a deliberate fresh start)."""
    global _PENDING_INIT_MS
    with _LOCK:
        _USED.clear()
        _PENDING_INIT_MS = 0


def add_session_init_ms(ms: float) -> None:
    """Credit time spent in MCP initialize / notifications/initialized."""
    global _PENDING_INIT_MS
    with _LOCK:
        _PENDING_INIT_MS += max(0, int(round(ms)))


def _take_session_state(kind: str, consume: bool) -> "tuple[bool, int]":
    """Return (session_reused, session_init_ms) for the next call of kind.

    ``consume=False`` (MCP handshake calls) reports the current state
    without marking the session as used or draining the init time.
    """
    global _PENDING_INIT_MS
    with _LOCK:
        used = _USED.get(kind, False)
        init_ms = _PENDING_INIT_MS if kind == "mcp" else 0
        reused = used and init_ms == 0
        if consume:
            _USED[kind] = True
            if kind == "mcp":
                _PENDING_INIT_MS = 0
        elif kind == "mcp":
            init_ms = 0  # handshake calls ARE the init; do not echo it
        return reused, init_ms


def new_correlation_id() -> str:
    return str(uuid.uuid4())


def resolve_correlation_id(explicit: Optional[str] = None) -> str:
    """Caller kwarg wins, then env ELR_CORRELATION_ID, else a fresh uuid4."""
    for candidate in (explicit, os.environ.get(ENV_CORRELATION_ID)):
        if candidate and str(candidate).strip():
            return str(candidate).strip()
    return new_correlation_id()


# ---------------------------------------------------------------------------
# Per-call timing record
# ---------------------------------------------------------------------------


@dataclass
class CallTiming:
    correlation_id: str
    t_client_start_ms: int
    _perf_start: float
    kind: str = "internal"
    serialize_ms: int = 0
    session_reused: bool = False
    session_init_ms: int = 0
    # Default True (legacy urllib path opens a NEW connection per call). The
    # keep-alive pool overwrites it per send attempt with what truly happened.
    tls_new: bool = True
    response_bytes: int = 0

    def set_serialize_since(self, perf_t0: float) -> None:
        self.serialize_ms = int(round((time.perf_counter() - perf_t0) * 1000))


def begin_call(kind: str = "internal", correlation_id: Optional[str] = None, *, handshake: bool = False) -> CallTiming:
    """Start timing one transport call. Call BEFORE serialising the body."""
    reused, init_ms = _take_session_state(kind, consume=not handshake)
    return CallTiming(
        correlation_id=resolve_correlation_id(correlation_id),
        t_client_start_ms=int(time.time() * 1000),
        _perf_start=time.perf_counter(),
        kind=kind,
        session_reused=reused,
        session_init_ms=init_ms,
    )


def serialize_body(timing: CallTiming, payload: Any) -> bytes:
    """json.dumps(payload) -> bytes, recording client_serialize_ms."""
    t0 = time.perf_counter()
    body = json.dumps(payload).encode("utf-8")
    timing.set_serialize_since(t0)
    return body


def headers_for(timing: CallTiming) -> Dict[str, str]:
    """Exactly the seven timing request headers; no other header."""
    return {
        H_CORRELATION_ID: timing.correlation_id,
        H_T_CLIENT_START: str(int(timing.t_client_start_ms)),
        H_SESSION_REUSED: "1" if timing.session_reused else "0",
        H_SESSION_INIT_MS: str(int(timing.session_init_ms)),
        H_TLS_NEW: "1" if timing.tls_new else "0",
        H_SERIALIZE_MS: str(int(timing.serialize_ms)),
        H_SURFACE: SURFACE,
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


def ledger_enabled() -> bool:
    return os.environ.get(ENV_LEDGER_TOGGLE, "1").strip().lower() not in ("0", "false", "off", "no")


def ledger_path() -> str:
    return os.path.expanduser(os.environ.get(ENV_LEDGER_PATH) or DEFAULT_LEDGER_PATH)


def finish_call(
    timing: CallTiming,
    *,
    method: str,
    url: str,
    status: int,
    verb: Optional[str] = None,
    response_bytes: Optional[int] = None,
) -> Dict[str, Any]:
    """Close the timing record and append its ledger line. Best effort:
    a ledger failure must never break (or even slow) a governed call.
    Returns the row (useful to tests). ``url`` is reduced to its host.
    """
    t_end_ms = int(time.time() * 1000)
    row: Dict[str, Any] = {
        "correlation_id": timing.correlation_id,
        "t_client_start": timing.t_client_start_ms,
        "t_client_end": t_end_ms,
        "client_total_ms": int(round((time.perf_counter() - timing._perf_start) * 1000)),
        "client_session_reused": timing.session_reused,
        "client_session_init_ms": timing.session_init_ms,
        "client_tls_new": timing.tls_new,
        "client_serialize_ms": timing.serialize_ms,
        "response_bytes": timing.response_bytes if response_bytes is None else response_bytes,
        "method": method,
        "verb": verb or method,
        "host": urllib.parse.urlparse(url).netloc,
        "status": status,
        "surface": SURFACE,
    }
    if ledger_enabled():
        try:
            path = ledger_path()
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, separators=(",", ":")) + "\n")
        except Exception:  # noqa: BLE001 -- ledger is advisory
            pass
    return row
