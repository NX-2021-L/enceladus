#!/usr/bin/env bash
# ENC-TSK-Q22 (DOC-5368FE6515ED FR-12): fail-closed change-set replacement/
# removal gate for .github/workflows/cloudformation-compute-stack-deploy.yml's
# plan job. Runs against a created-but-not-executed change-set (both the Data
# and Compute change-sets carry this gate) right after that change-set's
# describe-change-set summary, so a template edit that would REPLACE or
# REMOVE a live resource is visible and refused before the apply job ever
# gets a chance to execute it -- unless explicitly, visibly acknowledged.
#
# Usage: cfn_changeset_replacement_gate.sh <stack_label> <changeset_arn> <acknowledge_replacements>
#   stack_label               human label for the summary line (e.g. a stack name)
#   changeset_arn             the change-set to inspect (aws cloudformation describe-change-set)
#   acknowledge_replacements  "true" to allow a replacement/removal through anyway
#                             (io-only override -- the workflow_dispatch input of
#                             the same name); anything else is treated as false.
#
# Requires: aws, jq on PATH. Reads $AWS_REGION (required). Appends the summary
# line to $GITHUB_STEP_SUMMARY when that's set (a no-op outside CI / in tests).
#
# Exit 0: no replacements/removals, OR acknowledge_replacements=true.
# Exit 1: at least one replacement or removal and no acknowledgement.
set -euo pipefail

stack_label="${1:?usage: cfn_changeset_replacement_gate.sh <stack_label> <changeset_arn> <acknowledge_replacements>}"
changeset_arn="${2:?usage: cfn_changeset_replacement_gate.sh <stack_label> <changeset_arn> <acknowledge_replacements>}"
acknowledge="${3:-false}"
region="${AWS_REGION:?AWS_REGION must be set}"

changes_json='[]'
next_token=""
while :; do
  if [ -n "${next_token}" ]; then
    page=$(aws cloudformation describe-change-set \
      --region "${region}" \
      --change-set-name "${changeset_arn}" \
      --next-token "${next_token}" \
      --output json)
  else
    page=$(aws cloudformation describe-change-set \
      --region "${region}" \
      --change-set-name "${changeset_arn}" \
      --output json)
  fi
  page_changes=$(printf '%s' "${page}" | jq -c '.Changes // []')
  changes_json=$(jq -n --argjson a "${changes_json}" --argjson b "${page_changes}" '$a + $b')
  next_token=$(printf '%s' "${page}" | jq -r '.NextToken // empty')
  [ -z "${next_token}" ] && break
done

n=$(printf '%s' "${changes_json}" | jq 'length')
r=$(printf '%s' "${changes_json}" | jq '[.[] | select(.ResourceChange.Replacement == "True" or .ResourceChange.Replacement == "Conditional")] | length')
d=$(printf '%s' "${changes_json}" | jq '[.[] | select(.ResourceChange.Action == "Remove")] | length')

summary_line="change-set gate (${stack_label}): ${n} changes, ${r} replacements, ${d} removals"
echo "${summary_line}"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  echo "${summary_line}" >> "${GITHUB_STEP_SUMMARY}"
fi

if [ "${r}" -gt 0 ] || [ "${d}" -gt 0 ]; then
  offenders=$(printf '%s' "${changes_json}" | jq -r '
    .[]
    | select(.ResourceChange.Replacement == "True" or .ResourceChange.Replacement == "Conditional" or .ResourceChange.Action == "Remove")
    | "  \(.ResourceChange.Action) \(.ResourceChange.LogicalResourceId) (Replacement=\(.ResourceChange.Replacement // "N/A"))"
  ')
  if [ "${acknowledge}" = "true" ]; then
    echo "::warning::change-set gate (${stack_label}): ${r} replacement(s) / ${d} removal(s) ACKNOWLEDGED via acknowledge_replacements=true. Offending logical ids:"
    echo "${offenders}"
    exit 0
  fi
  echo "::error::change-set gate (${stack_label}): ${r} replacement(s) / ${d} removal(s) detected -- refusing to proceed. Set the workflow_dispatch input acknowledge_replacements=true (io-only) to allow this deliberately. Offending logical ids:"
  echo "${offenders}"
  exit 1
fi

exit 0
