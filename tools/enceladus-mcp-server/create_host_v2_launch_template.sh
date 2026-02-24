#!/usr/bin/env bash
# create_host_v2_launch_template.sh
#
# Create or version an EC2 launch template for Enceladus host-v2 fleet nodes.
# The template is used by coordination API to launch ad-hoc remote Codex hosts.
#
# Examples:
#   IMAGE_ID=ami-0123456789abcdef0 SECURITY_GROUP_IDS=sg-abc123,sg-def456 \
#   IAM_INSTANCE_PROFILE_NAME=enceladus-host-v2 tools/enceladus-mcp-server/create_host_v2_launch_template.sh
#
#   TEMPLATE_ID=lt-0abc123def456 SOURCE_VERSION='$Default' \
#   tools/enceladus-mcp-server/create_host_v2_launch_template.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
TEMPLATE_NAME="${TEMPLATE_NAME:-enceladus-host-v2-fleet}"
TEMPLATE_ID="${TEMPLATE_ID:-}"
SOURCE_VERSION="${SOURCE_VERSION:-\$Default}"
SET_DEFAULT_VERSION="${SET_DEFAULT_VERSION:-true}"
IMAGE_ID="${IMAGE_ID:-}"
INSTANCE_TYPE="${INSTANCE_TYPE:-t3.large}"
KEY_NAME="${KEY_NAME:-}"
SECURITY_GROUP_IDS="${SECURITY_GROUP_IDS:-}"
IAM_INSTANCE_PROFILE_NAME="${IAM_INSTANCE_PROFILE_NAME:-}"
ROOT_VOLUME_SIZE_GB="${ROOT_VOLUME_SIZE_GB:-40}"
ROOT_VOLUME_TYPE="${ROOT_VOLUME_TYPE:-gp3}"
USER_DATA_TEMPLATE="${USER_DATA_TEMPLATE:-${SCRIPT_DIR}/host_v2_user_data_template.sh}"
HOST_V2_USER="${HOST_V2_USER:-ec2-user}"
HOST_V2_HOME="${HOST_V2_HOME:-/home/${HOST_V2_USER}}"
HOST_V2_WORK_ROOT="${HOST_V2_WORK_ROOT:-${HOST_V2_HOME}/claude-code-dev}"
HOST_V2_MCP_BOOTSTRAP_SCRIPT="${HOST_V2_MCP_BOOTSTRAP_SCRIPT:-${HOST_V2_WORK_ROOT}/tools/enceladus-mcp-server/host_v2_first_bootstrap.sh}"
FLEET_TAG_MANAGED_BY_VALUE="${FLEET_TAG_MANAGED_BY_VALUE:-enceladus-coordination}"
NAME_PREFIX="${NAME_PREFIX:-enceladus-host-v2-fleet}"
VERSION_DESCRIPTION="${VERSION_DESCRIPTION:-enceladus-host-v2-fleet-$(date -u +%Y%m%dT%H%M%SZ)}"

if [[ ! -f "${USER_DATA_TEMPLATE}" ]]; then
  echo "[ERROR] user-data template not found: ${USER_DATA_TEMPLATE}" >&2
  exit 1
fi

if [[ -z "${TEMPLATE_ID}" ]]; then
  discovered_id="$(
    aws ec2 describe-launch-templates \
      --region "${REGION}" \
      --filters "Name=launch-template-name,Values=${TEMPLATE_NAME}" \
      --query 'LaunchTemplates[0].LaunchTemplateId' \
      --output text 2>/dev/null || true
  )"
  if [[ "${discovered_id}" != "None" && -n "${discovered_id}" ]]; then
    TEMPLATE_ID="${discovered_id}"
  fi
fi

if [[ -z "${TEMPLATE_ID}" && -z "${IMAGE_ID}" ]]; then
  echo "[ERROR] IMAGE_ID is required when creating a new launch template." >&2
  exit 1
fi

USER_DATA_B64="$(
  python3 - "${USER_DATA_TEMPLATE}" <<'PY'
import base64
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
print(base64.b64encode(path.read_bytes()).decode("utf-8"))
PY
)"

LAUNCH_TEMPLATE_DATA="$(
  REGION="${REGION}" \
  IMAGE_ID="${IMAGE_ID}" \
  INSTANCE_TYPE="${INSTANCE_TYPE}" \
  KEY_NAME="${KEY_NAME}" \
  SECURITY_GROUP_IDS="${SECURITY_GROUP_IDS}" \
  IAM_INSTANCE_PROFILE_NAME="${IAM_INSTANCE_PROFILE_NAME}" \
  ROOT_VOLUME_SIZE_GB="${ROOT_VOLUME_SIZE_GB}" \
  ROOT_VOLUME_TYPE="${ROOT_VOLUME_TYPE}" \
  USER_DATA_B64="${USER_DATA_B64}" \
  HOST_V2_WORK_ROOT="${HOST_V2_WORK_ROOT}" \
  HOST_V2_MCP_BOOTSTRAP_SCRIPT="${HOST_V2_MCP_BOOTSTRAP_SCRIPT}" \
  FLEET_TAG_MANAGED_BY_VALUE="${FLEET_TAG_MANAGED_BY_VALUE}" \
  NAME_PREFIX="${NAME_PREFIX}" \
  python3 - <<'PY'
import json
import os

data = {
    "InstanceType": os.environ["INSTANCE_TYPE"],
    "UserData": os.environ["USER_DATA_B64"],
    "InstanceInitiatedShutdownBehavior": "terminate",
    "MetadataOptions": {
        "HttpEndpoint": "enabled",
        "HttpTokens": "required",
    },
    "BlockDeviceMappings": [
        {
            "DeviceName": "/dev/xvda",
            "Ebs": {
                "DeleteOnTermination": True,
                "Encrypted": True,
                "VolumeSize": int(os.environ["ROOT_VOLUME_SIZE_GB"]),
                "VolumeType": os.environ["ROOT_VOLUME_TYPE"],
            },
        }
    ],
    "TagSpecifications": [
        {
            "ResourceType": "instance",
            "Tags": [
                {"Key": "Name", "Value": os.environ["NAME_PREFIX"]},
                {"Key": "enceladus:managed-by", "Value": os.environ["FLEET_TAG_MANAGED_BY_VALUE"]},
                {"Key": "enceladus:fleet-node", "Value": "true"},
                {"Key": "enceladus:project", "Value": "enceladus"},
            ],
        },
        {
            "ResourceType": "volume",
            "Tags": [
                {"Key": "enceladus:managed-by", "Value": os.environ["FLEET_TAG_MANAGED_BY_VALUE"]},
                {"Key": "enceladus:project", "Value": "enceladus"},
            ],
        },
    ],
}

image_id = os.environ.get("IMAGE_ID", "").strip()
if image_id:
    data["ImageId"] = image_id

key_name = os.environ.get("KEY_NAME", "").strip()
if key_name:
    data["KeyName"] = key_name

sg_ids = [part.strip() for part in os.environ.get("SECURITY_GROUP_IDS", "").split(",") if part.strip()]
if sg_ids:
    data["SecurityGroupIds"] = sg_ids

instance_profile = os.environ.get("IAM_INSTANCE_PROFILE_NAME", "").strip()
if instance_profile:
    data["IamInstanceProfile"] = {"Name": instance_profile}

print(json.dumps(data, separators=(",", ":")))
PY
)"

if [[ -n "${TEMPLATE_ID}" ]]; then
  echo "[INFO] Creating launch template version for ${TEMPLATE_ID} in ${REGION}"
  version_output="$(
    aws ec2 create-launch-template-version \
      --region "${REGION}" \
      --launch-template-id "${TEMPLATE_ID}" \
      --source-version "${SOURCE_VERSION}" \
      --version-description "${VERSION_DESCRIPTION}" \
      --launch-template-data "${LAUNCH_TEMPLATE_DATA}"
  )"
  VERSION_NUMBER="$(
    python3 - <<'PY' "${version_output}"
import json
import sys
payload = json.loads(sys.argv[1])
print(payload["LaunchTemplateVersion"]["VersionNumber"])
PY
)"
else
  echo "[INFO] Creating launch template ${TEMPLATE_NAME} in ${REGION}"
  create_output="$(
    aws ec2 create-launch-template \
      --region "${REGION}" \
      --launch-template-name "${TEMPLATE_NAME}" \
      --version-description "${VERSION_DESCRIPTION}" \
      --launch-template-data "${LAUNCH_TEMPLATE_DATA}"
  )"
  TEMPLATE_ID="$(
    python3 - <<'PY' "${create_output}"
import json
import sys
payload = json.loads(sys.argv[1])
print(payload["LaunchTemplate"]["LaunchTemplateId"])
PY
)"
  VERSION_NUMBER="$(
    python3 - <<'PY' "${create_output}"
import json
import sys
payload = json.loads(sys.argv[1])
print(payload["LaunchTemplate"]["LatestVersionNumber"])
PY
)"
fi

if [[ "${SET_DEFAULT_VERSION}" == "true" ]]; then
  aws ec2 modify-launch-template \
    --region "${REGION}" \
    --launch-template-id "${TEMPLATE_ID}" \
    --default-version "${VERSION_NUMBER}" >/dev/null
fi

echo "[SUCCESS] launch template ready"
echo "HOST_V2_FLEET_LAUNCH_TEMPLATE_ID=${TEMPLATE_ID}"
echo "HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION=${VERSION_NUMBER}"
echo "HOST_V2_FLEET_USER_DATA_TEMPLATE=${USER_DATA_TEMPLATE}"
