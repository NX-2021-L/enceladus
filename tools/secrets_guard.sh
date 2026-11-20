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

# ENC-TSK-T18: npm registry credentials, in TRACKED CONTENT ONLY.
#
# The correct shape is a reference the tool substitutes at run time --
# frontend/ui-v2/.npmrc carries `_authToken=${CODEARTIFACT_AUTH_TOKEN}`, and ci.yml and _ui_deploy.yml each mint a
# 900-second token into that variable for `npm ci` to expand. Nothing stopped someone pasting a real token over that
# reference and committing it, and the PATTERN sweep below would not have noticed: it knows AWS keys, private keys,
# Slack, GitHub, Google and Stripe shapes and bearer headers, but no npm _authToken. This makes the reference form
# the only form that survives CI.
#
# `git grep` is the right instrument rather than a convenience, because it reads tracked and staged content only.
# CI legitimately WRITES an .npmrc holding a real minted token into the working tree -- parity-report.yml does
# exactly that -- so a filesystem sweep would flag the build's own scaffolding and fail every run. Those files are
# untracked, so this cannot see them. It also keeps the rule clear of frontend/ui-v2/node_modules, which the
# ripgrep branch below does not exclude (only frontend/ui is excluded there) and where a package fixture could
# otherwise trip it.
#
# The matcher takes a VALUE and not a reference: `${CODEARTIFACT_AUTH_TOKEN}` and `${{ secrets.X }}` both open with
# a dollar and a brace, which are outside the character class; a printf `%s` and an empty value are too short.
echo "[START] Tracked-content npm credential sweep"
LITERAL_AUTHTOKEN='_authToken[[:space:]]*=[[:space:]]*[A-Za-z0-9+/=._-]{20,}'
if authtoken_hits="$(git -C "${REPO_ROOT}" grep -nIE "${LITERAL_AUTHTOKEN}" -- . 2>/dev/null)"; then
  if [[ -n "${authtoken_hits}" ]]; then
    echo "[ERROR] A tracked file carries a LITERAL npm _authToken value. Replace it with a \${VAR} reference and" >&2
    echo "        supply the value from the environment; see frontend/ui-v2/.npmrc for the shape." >&2
    # File and line only. Never the match: the guard that catches a leak must not be what publishes it to a log.
    printf '%s\n' "${authtoken_hits}" | cut -d: -f1,2 | sed 's/^/          /' >&2
    exit 1
  fi
fi
echo "[SUCCESS] Tracked-content npm credential sweep clean"

echo "[START] Regex secrets sweep"
if command -v rg >/dev/null 2>&1; then
  if rg -n --hidden \
    --glob "!.git/**" \
    --glob "!frontend/ui/node_modules/**" \
    --glob "!frontend/ui/dist/**" \
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
