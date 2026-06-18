#!/usr/bin/env python3
"""Pre-deploy guard: every internal-key-consuming Lambda in 02-compute.yaml must
set COORDINATION_INTERNAL_API_KEY from the CoordinationInternalApiKey parameter.

Recurrence guard for the 2026-06-18 Sev-1 (ENC-TSK-H05 / ENC-LSN-053): a full-env
CloudFormation replace silently stripped COORDINATION_INTERNAL_API_KEY from backend
functions that carried it out-of-band, 401'ing all governed MCP tracker/doc traffic.
This check fails the deploy if any required consumer is missing the env ref, so the
strip can never recur via the template.

Exit 0 = all consumers covered. Exit 1 = at least one consumer missing the key.

Wire into the sanctioned deploy path (AC-8/AC-9), e.g. in the compute deploy job
before `aws cloudformation deploy`:

    python3 tools/verify_internal_key_coverage.py infrastructure/cloudformation/02-compute.yaml

To extend: when a new backend Lambda starts reading COORDINATION_INTERNAL_API_KEY
(grep backend/lambda for the env read), add its CFN logical id to REQUIRED_CONSUMERS.
"""
import sys
import re

# Lambda logical ids in 02-compute.yaml whose code authenticates or issues internal-key
# calls (grep backend/lambda for COORDINATION_INTERNAL_API_KEY / ENCELADUS_COORDINATION_*).
# Functions managed in OTHER templates (checkout-service, github-integration,
# deploy-capability-auditor) are out of scope for this file's check.
REQUIRED_CONSUMERS = {
    "CoordinationApiFunction",
    "TrackerMutationFunction",
    "DocumentApiFunction",
    "ProjectServiceFunction",
    "ChangelogApiFunction",
    "DeployIntakeFunction",
    "DeployParityValidatorFunction",
    "GraphQueryApiFunction",
    "DevopsEnvDriftAuditorFunction",
}
KEY_VAR = "COORDINATION_INTERNAL_API_KEY"


def consumers_with_key(path):
    """Return set of logical ids that set COORDINATION_INTERNAL_API_KEY in their env.

    Lightweight line scan (no YAML dep) so the guard runs anywhere in CI. A function
    'has the key' if `<KEY_VAR>:` appears between its `  <Id>:` header and the next
    top-level resource header.
    """
    lines = open(path).read().split("\n")
    have = set()
    cur = None
    for line in lines:
        m = re.match(r"^  ([A-Za-z0-9]+):\s*$", line)
        if m:
            cur = m.group(1)
        if cur and re.match(rf"^\s+{KEY_VAR}:\s", line):
            have.add(cur)
    return have


def main(argv):
    if len(argv) != 2:
        print(f"usage: {argv[0]} <path-to-02-compute.yaml>", file=sys.stderr)
        return 2
    have = consumers_with_key(argv[1])
    missing = sorted(REQUIRED_CONSUMERS - have)
    if missing:
        print("FAIL: internal-key coverage gap — these consumers would deploy "
              f"WITHOUT {KEY_VAR} (regresses the ENC-TSK-H05 Sev-1 fix):",
              file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        print("Add `COORDINATION_INTERNAL_API_KEY: !Ref CoordinationInternalApiKey` to "
              "each function's Environment.Variables.", file=sys.stderr)
        return 1
    print(f"OK: all {len(REQUIRED_CONSUMERS)} internal-key consumers set {KEY_VAR}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
