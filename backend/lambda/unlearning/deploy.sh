#!/usr/bin/env bash
# FTR-106 / ENC-TSK-K03 — package unlearning Lambda for S3 deploy artifact.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT="${1:-/tmp/unlearning.zip}"
cd "$(dirname "${BASH_SOURCE[0]}")"
zip -q -j "$OUT" lambda_function.py unlearning_core.py
echo "Wrote $OUT"
