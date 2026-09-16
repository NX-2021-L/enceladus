"""ELR TLS resolution chain (ENC-TSK-P76, T-B3, FR-B4-8..9).

Builds a VERIFYING ``ssl.SSLContext`` by resolving a CA bundle source, in
priority order:

  1. ``SSL_CERT_FILE`` env var, if set AND the path is readable and loads.
  2. ``certifi.where()``, if the ``certifi`` package is importable. This is
     an OPTIONAL guarded import -- ELR remains stdlib-only when certifi is
     absent; ELR never requires it and never installs it.
  3. The interpreter's own default verify paths, IF
     ``ssl.create_default_context()`` loads them without raising AND the
     resulting context actually holds at least one CA cert
     (``ctx.cert_store_stats()['x509_ca'] > 0``). An empty default store
     (e.g. a stripped-down interpreter with no OS trust store wired up)
     is treated the same as "no CA bundle available" -- NOT a silent pass.
  4. source ``"missing"`` -- no CA bundle could be resolved anywhere.

There is NO flag, environment variable, or code path anywhere in this
module (or in its only consumer, ``elr_lib.transport``) that disables
certificate verification or hostname checking. Every context this module
builds -- including the ``"missing"`` case -- keeps ``check_hostname =
True`` and ``verify_mode = ssl.CERT_REQUIRED``; a ``"missing"`` context
simply has no CA certs loaded, so any real handshake through it will fail
closed rather than skip verification. Callers MUST check
``resolve_ca_bundle().source == SOURCE_MISSING`` BEFORE attempting a
network call and fail fast with ``REMEDIATION_MESSAGE`` (AC-2) instead of
letting urlopen raise a raw ``ssl.SSLCertVerificationError`` traceback.
"""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from typing import Optional

try:  # OPTIONAL guarded import -- ELR must keep working with stdlib only.
    import certifi  # type: ignore
except ImportError:  # pragma: no cover - environment-dependent
    certifi = None  # type: ignore[assignment]

REMEDIATION_MESSAGE = "set SSL_CERT_FILE to a PEM bundle or pip install certifi"

SOURCE_SSL_CERT_FILE = "SSL_CERT_FILE"
SOURCE_CERTIFI = "certifi"
SOURCE_DEFAULT = "default"
SOURCE_MISSING = "missing"

# Exit code contract (AC-2): TLS-unresolvable is always exit code 4.
EXIT_CODE_TLS_UNRESOLVED = 4

# Sentinel "status" value transport.py returns (in place of an HTTP status
# int) when a request is refused before ever reaching urlopen because the
# CA bundle resolved to SOURCE_MISSING. Kept here (not in transport.py) so
# every consumer checks against the same single source of truth.
TLS_UNRESOLVED_STATUS = "tls_unresolved"


@dataclass(frozen=True)
class CaBundleResolution:
    source: str
    path: Optional[str]

    @property
    def unresolved(self) -> bool:
        return self.source == SOURCE_MISSING

    def as_digest_field(self) -> dict:
        """The {"source", "path"} shape every digest's ca_bundle field uses."""
        return {"source": self.source, "path": self.path}


def _context_loads(cafile: str) -> bool:
    try:
        ssl.create_default_context(cafile=cafile)
        return True
    except Exception:
        return False


def _try_ssl_cert_file() -> Optional[CaBundleResolution]:
    path = os.environ.get("SSL_CERT_FILE", "").strip()
    if not path:
        return None
    if not os.path.isfile(path) or not os.access(path, os.R_OK):
        return None
    if not _context_loads(path):
        return None
    return CaBundleResolution(source=SOURCE_SSL_CERT_FILE, path=path)


def _try_certifi() -> Optional[CaBundleResolution]:
    if certifi is None:
        return None
    try:
        path = certifi.where()
    except Exception:
        return None
    if not path or not os.path.isfile(path) or not _context_loads(path):
        return None
    return CaBundleResolution(source=SOURCE_CERTIFI, path=path)


def _try_interpreter_default() -> Optional[CaBundleResolution]:
    try:
        ctx = ssl.create_default_context()
        stats = ctx.cert_store_stats()
    except Exception:
        return None
    if stats.get("x509_ca", 0) <= 0:
        return None
    paths = ssl.get_default_verify_paths()
    path = paths.cafile or paths.capath
    return CaBundleResolution(source=SOURCE_DEFAULT, path=path)


def resolve_ca_bundle() -> CaBundleResolution:
    """Walk the resolution chain and return the first hit, else "missing"."""
    for resolver in (_try_ssl_cert_file, _try_certifi, _try_interpreter_default):
        result = resolver()
        if result is not None:
            return result
    return CaBundleResolution(source=SOURCE_MISSING, path=None)


def build_ssl_context(resolution: Optional[CaBundleResolution] = None) -> ssl.SSLContext:
    """Build a verifying SSLContext for `resolution` (or a freshly resolved
    one). ALWAYS returns check_hostname=True / verify_mode=CERT_REQUIRED --
    see module docstring / AC-3.
    """
    resolution = resolution or resolve_ca_bundle()
    if resolution.unresolved:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.create_default_context(cafile=resolution.path)
    # Belt-and-suspenders: create_default_context() already defaults to
    # these, but AC-3 requires this true unconditionally, with no path in
    # this module (or transport.py) able to flip either one.
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
