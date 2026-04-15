#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# deploy.sh — Deploy feed_publisher Lambda (devops-feed-publisher)
#
# Updates the Lambda code only. Infrastructure (IAM role, EventBridge trigger,
# SNS topic, S3 feed bucket) already exists.
#
# The feed_publisher Lambda generates S3 JSON feeds from DynamoDB tracker
# and projects tables, invalidates CloudFront, and publishes SNS notifications.
#
# Usage:
#   ./deploy.sh                    # deploy code only
#   ./deploy.sh --upload-source    # also upload source archive to S3 for
#                                  # orchestrator-based deploys
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-feed-publisher}"
S3_BUCKET="${S3_BUCKET:-jreese-net}"
PROJECT_ID="${PROJECT_ID:-devops}"
UPLOAD_SOURCE=false

for arg in "$@"; do
  case "$arg" in
    --upload-source) UPLOAD_SOURCE=true ;;
  esac
done

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

package_lambda() {
  local zip_path
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  (
    cd "${SCRIPT_DIR}"
    zip -qj "${zip_path}" lambda_function.py feed_utils.py
  )

  echo "${zip_path}"
}

deploy_lambda() {
  local zip_path="$1"

  log "[START] updating Lambda code: ${FUNCTION_NAME}"
  # ENC-TSK-E19: verify package arch matches Lambda runtime before upload
  E19_REPO_ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null)}"
  E19_EXPECTED_ARCH="x86_64"
  [ -n "${ENVIRONMENT_SUFFIX:-}" ] && E19_EXPECTED_ARCH="arm64"
  python3 "${E19_REPO_ROOT}/tools/verify_lambda_package_arch.py" \
    --package "${zip_path}" \
    --expected-arch "${E19_EXPECTED_ARCH}"
  aws lambda update-function-code \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --zip-file "fileb://${zip_path}" >/dev/null

  aws lambda wait function-updated-v2 \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}"

  log "[END] Lambda updated: ${FUNCTION_NAME}"
}

upload_source_archive() {
  local ts key source_zip repo_root
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  key="deploy-sources/${PROJECT_ID}/${ts}-local-manual.zip"
  source_zip="/tmp/${FUNCTION_NAME}-source.zip"
  repo_root="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

  log "[START] uploading source archive to s3://${S3_BUCKET}/${key}"
  (
    cd "${repo_root}"
    zip -qr "${source_zip}" \
      backend/lambda/feed_publisher/lambda_function.py \
      backend/lambda/feed_publisher/feed_utils.py
  )

  aws s3 cp "${source_zip}" "s3://${S3_BUCKET}/${key}" --region "${REGION}" >/dev/null
  rm -f "${source_zip}"
  log "[END] Source archive uploaded: s3://${S3_BUCKET}/${key}"
}

main() {
  log "=========================================="
  log "Deploying feed_publisher Lambda (ENC-ISS-080)"
  log "=========================================="

  log ""
  log "--- Packaging ---"
  local zip_path
  zip_path="$(package_lambda)"
  log "[OK] Package: ${zip_path}"

  log ""
  log "--- Deploying ---"
  deploy_lambda "${zip_path}"
  rm -f "${zip_path}"

  if [[ "${UPLOAD_SOURCE}" == "true" ]]; then
    log ""
    log "--- Uploading source archive ---"
    upload_source_archive
  fi

  log ""
  log "=========================================="
  log "[SUCCESS] feed_publisher Lambda deployed"
  log "=========================================="
}

main "$@"
