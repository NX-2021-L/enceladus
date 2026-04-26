#!/usr/bin/env bash
# lambda_artifact_helper.sh — Sourced helper for deploy.sh scripts.
#
# Provides resolve_artifact() which attempts to fetch a pre-built Lambda zip
# from S3 (produced by build-lambda-artifacts.yml). Falls back to local build
# when S3 is not configured. Errors when neither path is available.
#
# Usage (in deploy.sh):
#   REPO_ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null)}"
#   source "${REPO_ROOT}/tools/lambda_artifact_helper.sh"
#
#   # In package_lambda():
#   if resolved_zip="$(resolve_artifact "${FUNCTION_NAME}" "${zip_path}")"; then
#     echo "${resolved_zip}"
#     return 0
#   fi
#   # ... existing local build logic ...
#
# Environment variables (set by CI or caller):
#   LAMBDA_ARTIFACT_S3_BUCKET  — S3 bucket containing pre-built zips
#   LAMBDA_ARTIFACT_S3_KEY     — S3 key for the specific function zip
#   LAMBDA_ARTIFACT_LOCAL_BUILD — Set to "1" to force local build (escape hatch)
#
# Part of ENC-TSK-E20 (Split Lambda Build Pipeline), Phase 2 (ENC-TSK-E27).
# See DOC-8A7C16A42534 for the full plan.

resolve_artifact() {
  local function_name="${1:?resolve_artifact requires function_name}"
  local zip_path="${2:?resolve_artifact requires zip_path}"

  # Escape hatch: explicit local build overrides everything
  if [[ "${LAMBDA_ARTIFACT_LOCAL_BUILD:-}" == "1" ]]; then
    echo "[artifact] LAMBDA_ARTIFACT_LOCAL_BUILD=1 — using local build for ${function_name}" >&2
    return 1
  fi

  # S3 artifact path available: download
  if [[ -n "${LAMBDA_ARTIFACT_S3_BUCKET:-}" && -n "${LAMBDA_ARTIFACT_S3_KEY:-}" ]]; then
    local s3_uri="s3://${LAMBDA_ARTIFACT_S3_BUCKET}/${LAMBDA_ARTIFACT_S3_KEY}"
    echo "[artifact] Fetching ${function_name} from ${s3_uri}" >&2
    if aws s3 cp "${s3_uri}" "${zip_path}" --region "${AWS_DEFAULT_REGION:-us-west-2}" >/dev/null 2>&1; then
      echo "[artifact] Downloaded ${function_name} artifact ($(wc -c < "${zip_path}" | xargs) bytes)" >&2
      echo "${zip_path}"
      return 0
    else
      echo "[artifact] ERROR: Failed to download artifact from ${s3_uri}" >&2
      echo "[artifact] Set LAMBDA_ARTIFACT_LOCAL_BUILD=1 to fall back to local build" >&2
      exit 1
    fi
  fi

  # No S3 vars set — fall back to local build (backward compatible default)
  return 1
}
