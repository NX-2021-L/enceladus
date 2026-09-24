"""ENC-TSK-L10 (B64 Ph3): true Lambda response-streaming ASGI entry point.

Distinct from the existing enceladus-mcp-streamable Lambda (ENC-FTR-025),
which is invoked event-per-request via a Lambda Function URL in BUFFERED
mode and hand-translates one HTTP request per invocation into an ASGI
scope/receive/send triple. This process instead runs as a long-lived
Starlette/uvicorn server, fronted by AWS Lambda Web Adapter, so it can be
invoked by API Gateway REST API's responseTransferMode=STREAM integration
(which requires Lambda's InvokeWithResponseStream API and a real persistent
HTTP server process behind the adapter -- not the per-invocation event
model the existing Lambda uses).

Reuses `app` (the mcp.server.Server instance with all governed tool
handlers) from tools/enceladus-mcp-server/server.py, packaged alongside this
file by the Gen2 build (see .github/workflows/_build.yml special-case list,
same convention as mcp_streamable/mcp_code/coordination_api).

json_response=False here (vs. the existing Lambda's json_response=True) so
the underlying StreamableHTTPSessionManager actually emits an SSE stream
instead of buffering a single JSON body -- otherwise there is nothing for
API Gateway to stream.
"""

from __future__ import annotations

import contextlib
import logging
from typing import AsyncIterator

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from server import app  # tools/enceladus-mcp-server/server.py, packaged at zip root

logger = logging.getLogger("mcp_streaming_gateway")
logging.basicConfig(level=logging.INFO)

from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

session_manager = StreamableHTTPSessionManager(app=app, json_response=False, stateless=True)


async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "transport": "streamable_http", "streaming": True})


async def mcp_endpoint(scope, receive, send) -> None:
    await session_manager.handle_request(scope, receive, send)


@contextlib.asynccontextmanager
async def lifespan(_: Starlette) -> AsyncIterator[None]:
    async with session_manager.run():
        logger.info("mcp_streaming_gateway: session manager started")
        yield


application = Starlette(
    debug=False,
    routes=[
        Route("/health", health, methods=["GET"]),
        Mount("/mcp", app=mcp_endpoint),
        Mount("/", app=mcp_endpoint),
    ],
    lifespan=lifespan,
)
