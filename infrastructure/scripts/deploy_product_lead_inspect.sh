#!/usr/bin/env bash
set -euo pipefail

PROFILE="product-lead"
USER_NAME="product-lead-inspect"
POLICY_NAME="product-lead-inspect-policy"
CREATE_ACCESS_KEY="false"
ACCESS_KEY_OUTPUT=""

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
POLICY_FILE="${ROOT_DIR}/infra/iam/product-lead-inspect-policy.json"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

usage() {
  cat <<'EOF'
Usage: deploy_product_lead_inspect.sh [options]

Creates or updates the product-lead-inspect IAM user and managed policy.

Options:
  --profile <name>            AWS CLI profile to use (default: product-lead)
  --user-name <name>          IAM user name (default: product-lead-inspect)
  --policy-name <name>        Managed policy name (default: product-lead-inspect-policy)
  --policy-file <path>        Policy JSON path (default: infra/iam/product-lead-inspect-policy.json)
  --create-access-key         Create a fresh access key for the IAM user
  --access-key-output <path>  Write create-access-key JSON to this path
  --help                      Show this help text
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'Missing required command: %s\n' "$1" >&2
    exit 1
  }
}

aws_cli() {
  aws --profile "${PROFILE}" "$@"
}

ensure_user() {
  if aws_cli iam get-user --user-name "${USER_NAME}" >/dev/null 2>&1; then
    log "[OK] user exists: ${USER_NAME}"
    return
  fi

  log "[START] creating IAM user ${USER_NAME}"
  aws_cli iam create-user \
    --user-name "${USER_NAME}" \
    --tags \
      Key=Purpose,Value="Enceladus inspect access with scoped S3 write" \
      Key=CreatedBy,Value="ENC-TSK-C58" \
      Key=ManagedBy,Value="deploy_product_lead_inspect.sh" >/dev/null
  log "[END] created IAM user ${USER_NAME}"
}

get_policy_arn() {
  local account_id
  account_id="$(aws_cli sts get-caller-identity --query 'Account' --output text)"
  printf 'arn:aws:iam::%s:policy/%s\n' "${account_id}" "${POLICY_NAME}"
}

delete_oldest_nondefault_policy_version() {
  local policy_arn="$1"
  local removable
  removable="$(
    aws_cli iam list-policy-versions --policy-arn "${policy_arn}" --output json \
      | jq -r '.Versions | map(select(.IsDefaultVersion | not)) | sort_by(.CreateDate) | .[0].VersionId // empty'
  )"
  if [[ -n "${removable}" ]]; then
    log "[INFO] deleting oldest non-default policy version ${removable}"
    aws_cli iam delete-policy-version --policy-arn "${policy_arn}" --version-id "${removable}"
  fi
}

ensure_policy() {
  local policy_arn current_version current_doc current_sorted desired_sorted version_count
  policy_arn="$(get_policy_arn)"

  if ! aws_cli iam get-policy --policy-arn "${policy_arn}" >/dev/null 2>&1; then
    log "[START] creating managed policy ${POLICY_NAME}"
    aws_cli iam create-policy \
      --policy-name "${POLICY_NAME}" \
      --description "Wide Enceladus inspect access with scoped S3 write (ENC-TSK-C58)" \
      --policy-document "file://${POLICY_FILE}" >/dev/null
    log "[END] created managed policy ${POLICY_NAME}"
    printf '%s\n' "${policy_arn}"
    return
  fi

  current_version="$(
    aws_cli iam get-policy --policy-arn "${policy_arn}" \
      --query 'Policy.DefaultVersionId' --output text
  )"
  current_doc="$(
    aws_cli iam get-policy-version --policy-arn "${policy_arn}" --version-id "${current_version}" \
      --query 'PolicyVersion.Document' --output json
  )"
  current_sorted="$(printf '%s\n' "${current_doc}" | jq -S .)"
  desired_sorted="$(jq -S . "${POLICY_FILE}")"

  if [[ "${current_sorted}" == "${desired_sorted}" ]]; then
    log "[OK] managed policy already matches repo file"
    printf '%s\n' "${policy_arn}"
    return
  fi

  version_count="$(
    aws_cli iam list-policy-versions --policy-arn "${policy_arn}" --query 'length(Versions)' --output text
  )"
  if [[ "${version_count}" -ge 5 ]]; then
    delete_oldest_nondefault_policy_version "${policy_arn}"
  fi

  log "[START] publishing new default version for ${POLICY_NAME}"
  aws_cli iam create-policy-version \
    --policy-arn "${policy_arn}" \
    --policy-document "file://${POLICY_FILE}" \
    --set-as-default >/dev/null
  log "[END] updated managed policy ${POLICY_NAME}"
  printf '%s\n' "${policy_arn}"
}

ensure_policy_attachment() {
  local policy_arn="$1"
  local attached

  attached="$(
    aws_cli iam list-attached-user-policies --user-name "${USER_NAME}" --output json \
      | jq -r --arg arn "${policy_arn}" '.AttachedPolicies[]?.PolicyArn | select(. == $arn)'
  )"

  if [[ -n "${attached}" ]]; then
    log "[OK] policy already attached to ${USER_NAME}"
    return
  fi

  log "[START] attaching policy to ${USER_NAME}"
  aws_cli iam attach-user-policy --user-name "${USER_NAME}" --policy-arn "${policy_arn}"
  log "[END] attached policy to ${USER_NAME}"
}

create_access_key() {
  local active_keys output_path="$1"
  active_keys="$(
    aws_cli iam list-access-keys --user-name "${USER_NAME}" --query 'length(AccessKeyMetadata)' --output text
  )"

  if [[ "${active_keys}" -ge 2 ]]; then
    printf 'User %s already has %s access keys; refusing to create a third.\n' "${USER_NAME}" "${active_keys}" >&2
    exit 1
  fi

  log "[START] creating access key for ${USER_NAME}"
  if [[ -n "${output_path}" ]]; then
    aws_cli iam create-access-key --user-name "${USER_NAME}" --output json > "${output_path}"
    log "[END] wrote access key JSON to ${output_path}"
    return
  fi

  aws_cli iam create-access-key --user-name "${USER_NAME}" --output json
  log "[END] created access key for ${USER_NAME}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --user-name)
      USER_NAME="$2"
      shift 2
      ;;
    --policy-name)
      POLICY_NAME="$2"
      shift 2
      ;;
    --policy-file)
      POLICY_FILE="$2"
      shift 2
      ;;
    --create-access-key)
      CREATE_ACCESS_KEY="true"
      shift
      ;;
    --access-key-output)
      ACCESS_KEY_OUTPUT="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_cmd aws
require_cmd jq

if [[ ! -f "${POLICY_FILE}" ]]; then
  printf 'Policy file not found: %s\n' "${POLICY_FILE}" >&2
  exit 1
fi

log "[INFO] using profile ${PROFILE}"
log "[INFO] policy file ${POLICY_FILE}"

ensure_user
policy_arn="$(ensure_policy)"
ensure_policy_attachment "${policy_arn}"

aws_cli iam get-user --user-name "${USER_NAME}" --query 'User.{UserName:UserName,Arn:Arn,CreateDate:CreateDate}' --output table
aws_cli iam list-attached-user-policies --user-name "${USER_NAME}" --output table

if [[ "${CREATE_ACCESS_KEY}" == "true" ]]; then
  create_access_key "${ACCESS_KEY_OUTPUT}"
fi

log "[SUCCESS] product-lead-inspect deployment complete"
