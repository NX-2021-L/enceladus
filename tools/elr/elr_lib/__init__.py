"""elr_lib -- Enceladus Local Runner (ELR) transport substrate.

ELR is an alternate CLIENT for the governed Enceladus HTTP APIs, not a
bypass: governance is enforced at the API boundary (the Lambda
handlers), and ELR only moves bytes and returns compact digests.
Stdlib-only (Python 3.11): urllib.request, json, hashlib, argparse, ssl.

Public surface:
  config.get_profile("internal" | "mcp-http") -> profile config object
  transport.InternalClient  -- direct governed-API HTTPS calls
  transport.McpHttpClient   -- JSON-RPC 2.0 over the MCP-over-HTTP gateway
  digest.build_digest(...)  -- the stable digest-first result shape
"""

from . import config, digest, transport
from .config import McpHttpProfileConfig, InternalProfileConfig, get_profile
from .digest import build_digest
from .transport import InternalClient, McpHttpClient

__version__ = "1.0.0"

__all__ = [
    "config",
    "digest",
    "transport",
    "get_profile",
    "InternalProfileConfig",
    "McpHttpProfileConfig",
    "InternalClient",
    "McpHttpClient",
    "build_digest",
    "__version__",
]
