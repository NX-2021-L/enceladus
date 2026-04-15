# AUDIT 2026-04-15 — devops-github-integration-lambda-role IAM cleanup

**Project**: enceladus
**Related**: ENC-TSK-E03, ENC-ISS-206, ENC-PLN-006
**Created**: 2026-04-15
**Author**: product-lead terminal session (io-dev-admin IAM)

## Canonical codification

The GMF DynamoDB perms on `devops-github-integration-lambda-role` are codified in `backend/lambda/github_integration/deploy.sh` lines 58-63 (commit `9163d27`, PR #289 "fix: persist GMF gate hotfixes — IAM policy and GSI key constraint", merged 2026-04-12T09:33Z UTC). The Sid is `GMFDeploymentManagerAccess` and the actions are `dynamodb:PutItem`, `dynamodb:UpdateItem`, `dynamodb:Scan` on `arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/devops-deployment-manager`. Every CI deploy of the github_integration Lambda re-applies this canonical block via `aws iam put-role-policy` (CloudTrail-confirmed).

## Emergency-patch lineage

| Time (UTC)           | Event                                                                                  |
|----------------------|----------------------------------------------------------------------------------------|
| 2026-04-12T09:10Z    | AccessDeniedException cluster on `/aws/lambda/devops-github-integration` (ENC-ISS-206) |
| 2026-04-12T09:18Z    | io-dev-admin out-of-band `PutRolePolicy`: `devops-github-integration-gmf-dynamodb` (emergency fix) |
| 2026-04-12T09:33Z    | Commit `9163d27` (PR #289) merged: codifies same block in `deploy.sh` — emergency patch is now redundant |
| 2026-04-15T06:29:59Z | This audit — `DeleteRolePolicy` on `devops-github-integration-gmf-dynamodb` under io-dev-admin |

## Cleanup operation

- IAM identity: `arn:aws:iam::356364570033:user/io-dev-admin`
- Command: `aws iam delete-role-policy --role-name devops-github-integration-lambda-role --policy-name devops-github-integration-gmf-dynamodb --region us-west-2`
- Executed: 2026-04-15T06:29:59Z UTC (completed 06:30:00Z UTC)
- CloudTrail event (us-east-1, global-service delivery): `EventName=DeleteRolePolicy`, `EventId=e76623f6-e0b7-4620-8a87-98fe54165af5`, `EventTime=2026-04-15T06:30:00Z`, `sourceIPAddress=99.108.136.150`, `userIdentity.arn=arn:aws:iam::356364570033:user/io-dev-admin`
- Pre-state: 2 inline policies (`devops-github-integration-inline` + `devops-github-integration-gmf-dynamodb`)
- Post-state: 1 inline policy (`devops-github-integration-inline` only)

## Current canonical state

Only `devops-github-integration-inline` remains on the role, applied by `backend/lambda/github_integration/deploy.sh` on every CI deploy. No out-of-band drift. Future operators: do NOT re-apply an emergency `PutRolePolicy` if AccessDenied recurs — instead verify the deploy.sh codification is still at lines 58-63 with the GMFDeploymentManagerAccess Sid, and check the most recent CI deploy CloudTrail entry for the GitHubActions `PutRolePolicy` that applied it.
