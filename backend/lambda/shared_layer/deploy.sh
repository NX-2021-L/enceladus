#!/usr/bin/env bash
# deploy.sh — Build, publish, and attach the enceladus-shared Lambda layer.
#
# Usage:
#   ./deploy.sh                 — publish layer only
#   ./deploy.sh --attach-all    — publish and attach to all Enceladus Lambdas
#   ./deploy.sh --attach <fn>   — publish and attach to a specific function
#
# Part of ENC-TSK-525: Extract shared Lambda layer.
set -euo pipefail

ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
LAYER_NAME="${LAYER_NAME:-enceladus-shared${ENVIRONMENT_SUFFIX}}"

# ENC-ISS-198 / ENC-TSK-D22: build target is now keyed off ENVIRONMENT_SUFFIX so
# prod (empty suffix) builds against python3.11/x86_64 (the V3 production lock)
# and gamma (-gamma suffix) builds against python3.12/arm64. The consumer ABI is
# overridden via pip --python-version / --abi / --platform — see build_layer().
if [[ -z "${ENVIRONMENT_SUFFIX}" ]]; then
    RUNTIME="python3.11"
    PYTHON_VERSION="3.11"
    PIP_ABI="cp311"
    PIP_PLATFORM="manylinux2014_x86_64"
    LAMBDA_ARCH="x86_64"
else
    RUNTIME="python3.12"
    PYTHON_VERSION="3.12"
    PIP_ABI="cp312"
    PIP_PLATFORM="manylinux2014_aarch64"
    LAMBDA_ARCH="arm64"
fi

# All Enceladus Lambda functions that should use this layer.
ALL_FUNCTIONS=(
    "devops-coordination-api${ENVIRONMENT_SUFFIX}"
    "devops-tracker-mutation-api${ENVIRONMENT_SUFFIX}"
    "devops-document-api${ENVIRONMENT_SUFFIX}"
    "devops-project-service${ENVIRONMENT_SUFFIX}"
    "devops-feed-query-api${ENVIRONMENT_SUFFIX}"
    "devops-coordination-monitor-api${ENVIRONMENT_SUFFIX}"
    "devops-deploy-intake${ENVIRONMENT_SUFFIX}"
    "devops-reference-search${ENVIRONMENT_SUFFIX}"
    "devops-deploy-orchestrator${ENVIRONMENT_SUFFIX}"
    "devops-deploy-finalize${ENVIRONMENT_SUFFIX}"
    "devops-feed-publisher${ENVIRONMENT_SUFFIX}"
    "enceladus-governance-audit${ENVIRONMENT_SUFFIX}"
    "enceladus-bedrock-agent-actions${ENVIRONMENT_SUFFIX}"
    "devops-doc-prep${ENVIRONMENT_SUFFIX}"
    "enceladus-checkout-service${ENVIRONMENT_SUFFIX}"
    "enceladus-checkout-service-auto${ENVIRONMENT_SUFFIX}"
)

log() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >&2
}

build_layer() {
    local build_dir zip_path
    build_dir="$(mktemp -d)"
    zip_path="${ROOT_DIR}/layer.zip"

    log "[START] Building layer package"

    # Copy shared module.
    cp -r "${ROOT_DIR}/python" "${build_dir}/"

    # CRITICAL: Pin EVERY dimension of the consumer ABI explicitly. Lambda layers
    # are silently broken if any dimension drifts from the consuming function.
    #
    # 🚨 THREE FLAGS, NOT ONE.
    #
    #   --platform           pins the OS/arch (manylinux2014_x86_64 vs aarch64)
    #   --python-version     pins the Python ABI version (3.11 vs 3.12)
    #   --abi                pins the Python ABI tag (cp311 vs cp312)
    #
    # If any one of these is omitted, pip will fall back to the BUILDER's host
    # Python and produce wheels that may not load on the consumer runtime. The
    # failure is always silent: `import jwt` raises ImportError, the surrounding
    # `except` swallows it, _JWT_AVAILABLE is set to False, and every Cognito
    # request returns HTTP 401 "JWT library not available in Lambda package".
    #
    # Historical incidents (same failure class, three different drift axes):
    #   - ENC-ISS-041 (2026-02): macOS Mach-O binaries vs Linux ELF
    #     → fix: added --platform manylinux2014_x86_64
    #     → JWT_AUTHENTICATION_FORENSICS.md, commit de33817
    #   - ENC-ISS-044 (2026-02): rebuild from clean Linux base
    #     → fix: republished as enceladus-shared:6 against python3.11/x86_64
    #   - ENC-ISS-198 (2026-04): cpython-312 .so loaded on a python3.11 Lambda
    #     → fix: added --python-version and --abi (THIS BLOCK)
    #     → DOC-E9B160563B1C v6 §Addendum, ENC-TSK-D22
    #
    # The consumer ABI is selected at the top of this script via ENVIRONMENT_SUFFIX
    # (PYTHON_VERSION / PIP_ABI / PIP_PLATFORM). DO NOT remove any of the three pip
    # flags below — single-dimension fixes are not sufficient.
    python3 -m pip install \
        --quiet \
        --upgrade \
        --platform "${PIP_PLATFORM}" \
        --implementation cp \
        --python-version "${PYTHON_VERSION}" \
        --abi "${PIP_ABI}" \
        --only-binary=:all: \
        -r "${ROOT_DIR}/requirements.txt" \
        -t "${build_dir}/python" >/dev/null

    # Create zip.
    (cd "${build_dir}" && zip -qr "${zip_path}" python/)

    rm -rf "${build_dir}"
    log "[END] Layer package built: ${zip_path}"
    echo "${zip_path}"
}

publish_layer() {
    local zip_path="$1"
    local description="${LAYER_DESCRIPTION:-Enceladus shared utilities: auth, DDB, HTTP helpers — built for ${RUNTIME} / ${LAMBDA_ARCH} (ENC-TSK-D22)}"

    log "[START] Publishing layer: ${LAYER_NAME} (${RUNTIME} / ${LAMBDA_ARCH})"
    local version_arn
    version_arn="$(aws lambda publish-layer-version \
        --region "${REGION}" \
        --layer-name "${LAYER_NAME}" \
        --description "${description}" \
        --compatible-runtimes "${RUNTIME}" \
        --compatible-architectures "${LAMBDA_ARCH}" \
        --zip-file "fileb://${zip_path}" \
        --query 'LayerVersionArn' \
        --output text)"

    log "[END] Layer published: ${version_arn}"
    echo "${version_arn}"
}

attach_layer() {
    local function_name="$1" layer_arn="$2"

    # Get current layers (excluding any previous version of our layer).
    local current_layers
    current_layers="$(aws lambda get-function-configuration \
        --region "${REGION}" \
        --function-name "${function_name}" \
        --query "Layers[?!contains(Arn, '${LAYER_NAME}')].Arn" \
        --output json 2>/dev/null || echo "[]")"

    # Build new layer list: existing layers + our new layer.
    local layer_list
    layer_list="$(echo "${current_layers}" | python3 -c "
import sys, json
layers = json.load(sys.stdin)
if not isinstance(layers, list):
    layers = []
layers.append('${layer_arn}')
print(' '.join(layers))
")"

    log "[START] Attaching layer to ${function_name}"
    aws lambda update-function-configuration \
        --region "${REGION}" \
        --function-name "${function_name}" \
        --layers ${layer_list} \
        --query 'FunctionName' \
        --output text >/dev/null

    # Wait for update to complete.
    aws lambda wait function-updated-v2 \
        --region "${REGION}" \
        --function-name "${function_name}" 2>/dev/null || true

    log "[END] Layer attached to ${function_name}"
}

main() {
    local mode="${1:-}"
    local specific_fn="${2:-}"

    # Build and publish.
    local zip_path layer_arn
    zip_path="$(build_layer)"
    layer_arn="$(publish_layer "${zip_path}")"

    # Clean up zip.
    rm -f "${zip_path}"

    log "[INFO] Layer ARN: ${layer_arn}"

    # Attach to functions if requested.
    if [[ "${mode}" == "--attach-all" ]]; then
        for fn in "${ALL_FUNCTIONS[@]}"; do
            attach_layer "${fn}" "${layer_arn}" || {
                log "[WARNING] Failed to attach to ${fn}, continuing..."
            }
        done
        log "[SUCCESS] Layer attached to all functions"
    elif [[ "${mode}" == "--attach" && -n "${specific_fn}" ]]; then
        attach_layer "${specific_fn}" "${layer_arn}"
        log "[SUCCESS] Layer attached to ${specific_fn}"
    else
        log "[INFO] Layer published. Use --attach-all or --attach <fn> to attach to functions."
    fi

    log "[SUCCESS] enceladus-shared layer deploy complete"
}

main "$@"
