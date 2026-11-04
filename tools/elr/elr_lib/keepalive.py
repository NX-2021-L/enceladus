"""ELR keep-alive connection pool (ENC-TSK-S28-0B, BRD DOC-E32D0ED08473 W1.2).

One ELR process normally makes several governed calls (batch_get over N ids,
compact_context composing a dozen sections, an MCP initialize followed by
tools/call). With urllib each call paid a fresh TCP + TLS handshake. This
module keeps ``http.client`` connections alive per (scheme, host, port) for
the life of the process so every call after the first rides an established
connection.

Design notes
------------
* Idle-connection pool, not a single shared socket: compact_context runs its
  section fetches on a thread pool, so concurrent callers each check out their
  own connection (opening one if none is idle) and return it afterwards. In the
  sequential case there is exactly one connection per host.
* A reused connection can have been closed by the server (idle timeout, LB
  recycling). On BadStatusLine / RemoteDisconnected / ConnectionReset /
  BrokenPipe from a *reused* connection the pool reconnects ONCE and replays
  the request, but only when the caller marks the call idempotent (GET, or a
  tools/call carrying an Idempotency-Key). A non-idempotent request is never
  replayed; the connection is dropped and the error is raised so the caller can
  surface an ambiguous failure instead of double-applying a write. Stale
  connections are also detected *before* sending (socket readable == EOF) so
  the common idle-close case needs no retry at all.
* ``ELR_LONG_LIVED=0`` is honoured by the transport (it never constructs a pool
  and falls back to one urllib connection per call).

Stdlib only.
"""

from __future__ import annotations

import http.client
import os
import select
import ssl
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

ENV_LONG_LIVED = "ELR_LONG_LIVED"
MAX_IDLE_PER_HOST = 8
# Value assumed when ELR_LONG_LIVED is unset (the offline test suite flips this
# to "0" because it mocks urllib; production default is on).
DEFAULT_LONG_LIVED = "1"

# Errors that mean "the (reused) connection was dropped under us".
DROPPED_CONNECTION_ERRORS = (
    http.client.BadStatusLine,  # RemoteDisconnected is a subclass
    http.client.RemoteDisconnected,
    http.client.CannotSendRequest,
    http.client.ResponseNotReady,
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
)


def long_lived_enabled() -> bool:
    """``ELR_LONG_LIVED=0|false|off|no`` restores per-call behaviour."""
    return os.environ.get(ENV_LONG_LIVED, DEFAULT_LONG_LIVED).strip().lower() not in ("0", "false", "off", "no")


@dataclass
class PoolResponse:
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    opened_new: bool = False  # a new TCP/TLS connection served this response
    reconnected: bool = False  # the request was replayed once after a drop


def _default_connection_factory(
    scheme: str, host: str, port: Optional[int], timeout: float, ssl_context: Optional[ssl.SSLContext]
) -> http.client.HTTPConnection:
    if scheme == "http":
        return http.client.HTTPConnection(host, port, timeout=timeout)
    return http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl_context)


def _is_new(conn: Any) -> bool:
    """True when the next request will have to open a socket."""
    return getattr(conn, "sock", None) is None


def _looks_stale(conn: Any) -> bool:
    """A readable idle socket means the server sent EOF (or garbage) while the
    connection sat in the pool -- it is unusable. Best effort; False when the
    socket cannot be inspected."""
    sock = getattr(conn, "sock", None)
    if sock is None:
        return False
    try:
        readable, _, _ = select.select([sock], [], [], 0)
    except (OSError, ValueError):
        return True
    return bool(readable)


class KeepAlivePool:
    """Per-process pool of idle http.client connections."""

    def __init__(
        self,
        ssl_context: Optional[ssl.SSLContext] = None,
        *,
        connection_factory: Optional[Callable[..., Any]] = None,
        max_idle_per_host: int = MAX_IDLE_PER_HOST,
    ):
        self._ssl_context = ssl_context
        self._factory = connection_factory or _default_connection_factory
        self._max_idle = max_idle_per_host
        self._lock = threading.Lock()
        self._idle: Dict[Tuple[str, str, Optional[int]], List[Any]] = {}
        self.connections_opened = 0  # observability for tests / diagnostics

    # -- pool plumbing ------------------------------------------------------

    def _checkout(self, key: Tuple[str, str, Optional[int]], timeout: float) -> Any:
        with self._lock:
            bucket = self._idle.get(key)
            while bucket:
                conn = bucket.pop()
                if _looks_stale(conn):
                    self._safe_close(conn)
                    continue
                return conn
        return self._factory(key[0], key[1], key[2], timeout, self._ssl_context)

    def _checkin(self, key: Tuple[str, str, Optional[int]], conn: Any) -> None:
        with self._lock:
            bucket = self._idle.setdefault(key, [])
            if len(bucket) < self._max_idle:
                bucket.append(conn)
                return
        self._safe_close(conn)

    @staticmethod
    def _safe_close(conn: Any) -> None:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        with self._lock:
            conns = [c for bucket in self._idle.values() for c in bucket]
            self._idle.clear()
        for conn in conns:
            self._safe_close(conn)

    def idle_count(self) -> int:
        with self._lock:
            return sum(len(b) for b in self._idle.values())

    # -- request ------------------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes],
        *,
        timeout: float,
        idempotent: bool,
        on_connection: Optional[Callable[[bool], None]] = None,
    ) -> PoolResponse:
        """Issue one request, reusing an idle connection when possible.

        ``on_connection(opened_new)`` fires before each send attempt so the
        caller can record client_tls_new truthfully (and refresh the
        X-Enc-Client-Tls-New header on a replay).
        Raises the underlying OSError / http.client.HTTPException /
        TimeoutError for the caller to classify.
        """
        parts = urllib.parse.urlsplit(url)
        scheme = parts.scheme or "https"
        key = (scheme, parts.hostname or "", parts.port)
        target = parts.path or "/"
        if parts.query:
            target = f"{target}?{parts.query}"

        reconnected = False
        attempt = 0
        while True:
            attempt += 1
            if reconnected:
                conn = self._factory(key[0], key[1], key[2], timeout, self._ssl_context)
            else:
                conn = self._checkout(key, timeout)
            fresh = _is_new(conn)
            if fresh:
                self.connections_opened += 1
            if on_connection is not None:
                on_connection(fresh)
            try:
                conn.timeout = timeout
                conn.request(method, target, body=body, headers=headers)
                resp = conn.getresponse()
                raw = resp.read()
                resp_headers = {k: v for k, v in resp.getheaders()}
                status = resp.status
                will_close = bool(getattr(resp, "will_close", False))
            except DROPPED_CONNECTION_ERRORS:
                self._safe_close(conn)
                # Only a *reused* connection can have been dropped by the
                # server between calls; a fresh one failing is a real error.
                if not fresh and idempotent and attempt == 1:
                    reconnected = True
                    continue
                raise
            except BaseException:
                self._safe_close(conn)
                raise
            if will_close:
                self._safe_close(conn)
            else:
                self._checkin(key, conn)
            return PoolResponse(
                status=status,
                headers=resp_headers,
                body=raw,
                opened_new=fresh or reconnected,
                reconnected=reconnected,
            )
