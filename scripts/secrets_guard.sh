#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN_REMOTE="${SCAN_REMOTE:-0}"
REMOTE_REPO_URL="${REMOTE_REPO_URL:-}"

if ! command -v trufflehog >/dev/null 2>&1; then
  echo "[ERROR] trufflehog is required but not installed." >&2
  exit 1
fi

PATTERN="(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|-----BEGIN (RSA|OPENSSH|EC|DSA|PRIVATE KEY)-----|xox[baprs]-[A-Za-z0-9-]{10,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35}|sk_(live|test)_[0-9A-Za-z]{16,}|api[_-]?key\\s*[:=]\\s*['\\\"][A-Za-z0-9_\\-]{16,}['\\\"]|secret[_-]?key\\s*[:=]\\s*['\\\"][A-Za-z0-9_\\-]{16,}['\\\"]|authorization:\\s*bearer\\s+[A-Za-z0-9._\\-]+)"

echo "[START] Regex secrets sweep"
if command -v rg >/dev/null 2>&1; then
  if rg -n --hidden \
    --glob "!.git/**" \
    --glob "!ui/node_modules/**" \
    --glob "!ui/dist/**" \
    "${PATTERN}" \
    "${REPO_ROOT}"; then
    echo "[ERROR] Regex sweep found potential secret material." >&2
    exit 1
  fi
else
  if grep -RInE \
    --exclude-dir=.git \
    --exclude-dir=node_modules \
    --exclude-dir=dist \
    "${PATTERN}" \
    "${REPO_ROOT}"; then
    echo "[ERROR] Regex sweep found potential secret material." >&2
    exit 1
  fi
fi
echo "[SUCCESS] Regex secrets sweep clean"

echo "[START] TruffleHog git history scan"
trufflehog git --no-update --fail --results=verified,unknown,unverified "file://${REPO_ROOT}"
echo "[SUCCESS] TruffleHog git history scan clean"

echo "[START] TruffleHog filesystem scan"
trufflehog filesystem \
  --no-update \
  --fail \
  --results=verified,unknown,unverified \
  --exclude-paths "${REPO_ROOT}/.trufflehog-exclude-paths.txt" \
  "${REPO_ROOT}"
echo "[SUCCESS] TruffleHog filesystem scan clean"

if [[ "${SCAN_REMOTE}" == "1" ]]; then
  if [[ -z "${REMOTE_REPO_URL}" ]]; then
    if command -v git >/dev/null 2>&1; then
      origin_url="$(git -C "${REPO_ROOT}" remote get-url origin 2>/dev/null || true)"
    else
      origin_url=""
    fi
    if [[ "${origin_url}" == git@github.com:* ]]; then
      REMOTE_REPO_URL="https://github.com/${origin_url#git@github.com:}"
    elif [[ "${origin_url}" == https://github.com/* ]]; then
      REMOTE_REPO_URL="${origin_url}"
    fi
  fi

  if [[ -z "${REMOTE_REPO_URL}" ]]; then
    echo "[ERROR] SCAN_REMOTE=1 but REMOTE_REPO_URL is not set and origin URL could not be resolved." >&2
    exit 1
  fi

  echo "[START] TruffleHog remote repo scan: ${REMOTE_REPO_URL}"
  trufflehog git --no-update --fail --results=verified,unknown,unverified "${REMOTE_REPO_URL}"
  echo "[SUCCESS] TruffleHog remote repo scan clean"
fi

echo "[DONE] Secrets guard checks passed"
