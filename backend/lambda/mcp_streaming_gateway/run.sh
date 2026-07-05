#!/bin/bash
# ENC-TSK-L10: Lambda Web Adapter entrypoint. AWS_LAMBDA_EXEC_WRAPPER=/opt/bootstrap
# launches this script once per execution environment (cold start), then proxies
# subsequent invocations to it as HTTP requests on AWS_LWA_PORT.
set -euo pipefail
exec python3 -m uvicorn asgi_app:application --host 0.0.0.0 --port "${AWS_LWA_PORT:-8080}"
