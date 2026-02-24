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

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
LAYER_NAME="${LAYER_NAME:-enceladus-shared}"
RUNTIME="python3.11"

# All Enceladus Lambda functions that should use this layer.
ALL_FUNCTIONS=(
    devops-coordination-api
    devops-tracker-mutation-api
    devops-document-api
    devops-project-service
    devops-feed-query-api
    devops-coordination-monitor-api
    devops-deploy-intake
    devops-reference-search
    devops-deploy-orchestrator
    devops-deploy-finalize
    devops-feed-publisher
    enceladus-governance-audit
    enceladus-bedrock-agent-actions
    devops-doc-prep
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

    # Install dependencies into layer structure.
    python3 -m pip install \
        --quiet \
        --upgrade \
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

    log "[START] Publishing layer: ${LAYER_NAME}"
    local version_arn
    version_arn="$(aws lambda publish-layer-version \
        --region "${REGION}" \
        --layer-name "${LAYER_NAME}" \
        --description "Enceladus shared utilities: auth, DDB, HTTP helpers (ENC-TSK-525)" \
        --compatible-runtimes "${RUNTIME}" \
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
