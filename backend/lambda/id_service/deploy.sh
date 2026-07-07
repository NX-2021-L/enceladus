#!/usr/bin/env bash
# ENC-TSK-L06 — tombstone. id_service is built by the Gen2 matrix build (_build.yml,
# auto-discovered via `find backend/lambda -name lambda_function.py`) and deployed by
# .github/workflows/_deploy.yml ("Deploy Lambda Artifacts (Gen2)"). This script is a no-op
# retained only to satisfy the lambda_workflow_manifest.json deploy_script coverage check
# (tools/verify_lambda_workflow_coverage.py). Do NOT deploy from here.
echo "id_service is managed by the Gen2 pipeline (_build.yml + _deploy.yml); this is a no-op tombstone."
exit 0
