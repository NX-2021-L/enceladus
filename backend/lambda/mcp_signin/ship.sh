#!/usr/bin/env bash
# Manual ship of the Enceladus MCP kit sign-in service (ENC-TSK-S57-a). Not wired into _build.yml / _deploy.yml:
# run it from a workstation, with credentials that may update the function (AWS_PROFILE=product-lead).
#   bash backend/lambda/mcp_signin/ship.sh                 # gamma: enceladus-mcp-signin-gamma
#   ENVIRONMENT_SUFFIX= CONFIRM_PRODUCTION=yes bash ...    # production (a human-approved promote only)
# Builds the zip, updates the code, publishes a version, moves the `live` alias to it, smokes the Function URL
# DIRECTLY (nothing routes to this service yet) and moves the alias back to the previous version if the smoke fails.
# Needs the stack (12-mcp-signin.yaml) deployed. The state key (SSM SecureString) must already exist, or the smoke
# fails and the alias rolls back. No secret is printed or written to disk by this script.
set -euo pipefail
REGION="${AWS_REGION:-us-west-2}"
SUFFIX="${ENVIRONMENT_SUFFIX--gamma}"
if [ -z "$SUFFIX" ] && [ "${CONFIRM_PRODUCTION:-}" != "yes" ]; then
  echo "refusing: empty ENVIRONMENT_SUFFIX is production; set CONFIRM_PRODUCTION=yes (human-approved promote only)" >&2
  exit 2
fi
FN="enceladus-mcp-signin${SUFFIX}"
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${CODEARTIFACT_AUTH_TOKEN:-}" ]; then
  CODEARTIFACT_AUTH_TOKEN="$(AWS_PROFILE="${CODEARTIFACT_PROFILE:-product-lead}" aws codeartifact get-authorization-token \
    --domain io --domain-owner 356364570033 --region us-west-2 --query authorizationToken --output text)"
  export CODEARTIFACT_AUTH_TOKEN
fi
bash "$HERE/build.sh"
aws lambda update-function-code --region "$REGION" --function-name "$FN" --zip-file "fileb://$HERE/mcp_signin.zip" >/dev/null
aws lambda wait function-updated --region "$REGION" --function-name "$FN"
PREV=$(aws lambda get-alias --region "$REGION" --function-name "$FN" --name live --query FunctionVersion --output text)
VER=$(aws lambda publish-version --region "$REGION" --function-name "$FN" --query Version --output text)
aws lambda update-alias --region "$REGION" --function-name "$FN" --name live --function-version "$VER" >/dev/null
echo "live: ${PREV} -> ${VER}"
URL=$(aws lambda get-function-url-config --region "$REGION" --function-name "$FN" --qualifier live --query FunctionUrl --output text)
URL="${URL%/}"
# Same-origin metadata must answer, and an unknown redirect_uri must be refused (never redirected to).
meta=000; refuse=000
for _ in 1 2 3 4 5 6; do
  meta=$(curl -s -o /dev/null -w '%{http_code}' "${URL}/.well-known/oauth-authorization-server" || true)
  [ "$meta" = "200" ] && break
  sleep 10
done
refuse=$(curl -s -o /dev/null -w '%{http_code}' "${URL}/authorize?response_type=code&client_id=x&redirect_uri=https%3A%2F%2Fevil.example%2Fcb&code_challenge=x&code_challenge_method=S256" || true)
echo "metadata -> ${meta}; authorize(unknown redirect_uri) -> ${refuse}"
if [ "$meta" != "200" ] || [ "$refuse" != "400" ]; then
  echo "smoke failed; moving live back to version ${PREV}" >&2
  aws lambda update-alias --region "$REGION" --function-name "$FN" --name live --function-version "$PREV" >/dev/null
  exit 1
fi
rm -rf "$HERE/build" "$HERE/mcp_signin.zip"
echo "shipped ${FN} version ${VER}; rollback: aws lambda update-alias --region ${REGION} --function-name ${FN} --name live --function-version ${PREV}"
