#!/usr/bin/env bash
# Deploy the enceladus-governance-audit Lambda function.
#
# Related: ENC-ISS-009, ENC-TSK-454

set -euo pipefail

FUNCTION_NAME="${FUNCTION_NAME:-enceladus-governance-audit}"
REGION="${AWS_REGION:-us-west-2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZIP_FILE="/tmp/${FUNCTION_NAME}.zip"

echo "[START] Deploying ${FUNCTION_NAME}"

echo "[INFO] Packaging Lambda from ${SCRIPT_DIR}/lambda_function.py"
cd "${SCRIPT_DIR}"
zip -q -j "${ZIP_FILE}" lambda_function.py
echo "[INFO] Package ready: ${ZIP_FILE} ($(du -h "${ZIP_FILE}" | cut -f1))"

echo "[INFO] Updating Lambda function code"
aws lambda update-function-code \
  --function-name "${FUNCTION_NAME}" \
  --zip-file "fileb://${ZIP_FILE}" \
  --region "${REGION}" \
  --no-cli-pager >/dev/null

echo "[INFO] Waiting for Lambda update to finish"
aws lambda wait function-updated \
  --function-name "${FUNCTION_NAME}" \
  --region "${REGION}" \
  --no-cli-pager

echo "[SUCCESS] Deployment complete; current function summary:"
aws lambda get-function-configuration \
  --function-name "${FUNCTION_NAME}" \
  --region "${REGION}" \
  --query '{FunctionName:FunctionName,Runtime:Runtime,LastModified:LastModified,CodeSha256:CodeSha256,LastUpdateStatus:LastUpdateStatus}' \
  --no-cli-pager

echo "[END] Deployment finished"
