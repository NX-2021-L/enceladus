#!/bin/bash
# ENC-TSK-L10: Lambda Web Adapter entrypoint. AWS_LAMBDA_EXEC_WRAPPER=/opt/bootstrap
# launches this script once per execution environment (cold start), then proxies
# subsequent invocations to it as HTTP requests on AWS_LWA_PORT.
set -euo pipefail
# AWS_LAMBDA_EXEC_WRAPPER fully replaces the native runtime bootstrap, which is
# what normally sets PYTHONPATH=/opt/python so Lambda Layers (enceladus-shared,
# providing enceladus_shared.appconfig_flags) are importable. That never
# happens under the adapter, so set it explicitly (confirmed live: without
# this, server.py's `from enceladus_shared.appconfig_flags import flag` AND
# its `from appconfig_flags import flag` local-fallback both raise
# ModuleNotFoundError at import time, crashing uvicorn's cold start -> 502).
export PYTHONPATH="/opt/python:${PYTHONPATH:-}"
exec python3 -m uvicorn asgi_app:application --host 0.0.0.0 --port "${AWS_LWA_PORT:-8080}"
