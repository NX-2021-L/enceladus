#!/usr/bin/env bash
set -euo pipefail

# package_lambda_artifact.sh
# Packages a single Lambda function into a deployment zip.
#
# Usage: package_lambda_artifact.sh <function_name> <lambda_dir> <arch_tag> [extra_files_comma_separated]
#
# arch_tag: x86_64-py311 | arm64-py312
# Output:   prints the zip path to stdout

FUNCTION_NAME="${1:?Usage: package_lambda_artifact.sh <function_name> <lambda_dir> <arch_tag> [extra_files]}"
LAMBDA_DIR="${2:?Usage: package_lambda_artifact.sh <function_name> <lambda_dir> <arch_tag> [extra_files]}"
ARCH_TAG="${3:?Usage: package_lambda_artifact.sh <function_name> <lambda_dir> <arch_tag> [extra_files]}"
EXTRA_FILES="${4:-}"

REPO_ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null)}"

# Derive pip platform flags from arch_tag
case "${ARCH_TAG}" in
  x86_64-py311)
    PIP_PLATFORM="manylinux2014_x86_64"
    PIP_PYTHON_VERSION="3.11"
    PIP_ABI="cp311"
    ;;
  arm64-py312)
    PIP_PLATFORM="manylinux2014_aarch64"
    PIP_PYTHON_VERSION="3.12"
    PIP_ABI="cp312"
    ;;
  *)
    echo "ERROR: Unknown arch_tag '${ARCH_TAG}'. Expected x86_64-py311 or arm64-py312." >&2
    exit 1
    ;;
esac

LAMBDA_SRC="${REPO_ROOT}/${LAMBDA_DIR}"
BUILD_DIR=$(mktemp -d)
ZIP_PATH="/tmp/${FUNCTION_NAME}.zip"

cleanup() {
  rm -rf "${BUILD_DIR}"
}
trap cleanup EXIT

echo "Packaging ${FUNCTION_NAME} (${ARCH_TAG}) from ${LAMBDA_SRC}" >&2

# Copy lambda_function.py
if [[ ! -f "${LAMBDA_SRC}/lambda_function.py" ]]; then
  echo "ERROR: ${LAMBDA_SRC}/lambda_function.py not found" >&2
  exit 1
fi
cp "${LAMBDA_SRC}/lambda_function.py" "${BUILD_DIR}/"
echo "  Copied lambda_function.py" >&2

# Install requirements if present
if [[ -f "${LAMBDA_SRC}/requirements.txt" ]]; then
  echo "  Installing requirements (${PIP_PLATFORM}, Python ${PIP_PYTHON_VERSION})..." >&2
  pip install \
    --platform "${PIP_PLATFORM}" \
    --python-version "${PIP_PYTHON_VERSION}" \
    --abi "${PIP_ABI}" \
    --implementation cp \
    --only-binary=:all: \
    -t "${BUILD_DIR}" \
    -r "${LAMBDA_SRC}/requirements.txt" \
    --quiet
  echo "  Requirements installed" >&2
else
  echo "  No requirements.txt found, skipping pip install" >&2
fi

# Copy extra files if specified
if [[ -n "${EXTRA_FILES}" ]]; then
  IFS=',' read -ra FILES <<< "${EXTRA_FILES}"
  for file in "${FILES[@]}"; do
    file=$(echo "${file}" | xargs)  # trim whitespace
    if [[ -z "${file}" ]]; then
      continue
    fi
    src="${LAMBDA_SRC}/${file}"
    if [[ ! -e "${src}" ]]; then
      echo "ERROR: Extra file not found: ${src}" >&2
      exit 1
    fi
    dest_dir=$(dirname "${BUILD_DIR}/${file}")
    mkdir -p "${dest_dir}"
    cp -r "${src}" "${BUILD_DIR}/${file}"
    echo "  Copied extra file: ${file}" >&2
  done
fi

# Build the zip
echo "  Creating zip archive..." >&2
(cd "${BUILD_DIR}" && zip -r -q "${ZIP_PATH}" .)
echo "  Created ${ZIP_PATH}" >&2

# Print zip path to stdout (only output on stdout)
echo "${ZIP_PATH}"
