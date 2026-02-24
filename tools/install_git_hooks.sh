#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

git -C "${REPO_ROOT}" config core.hooksPath .githooks
echo "[DONE] Git hooks path set to .githooks for ${REPO_ROOT}"

