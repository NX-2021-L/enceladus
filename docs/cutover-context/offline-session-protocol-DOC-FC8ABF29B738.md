# Enceladus MCP-Down Offline Session Protocol

**Project**: enceladus
**Related**: ENC-TSK-O20, ENC-TSK-O10, ENC-PLN-081, DOC-2670B83D94F7
**Created**: 2026-08-21
**Author**: ENC-SES-0EG (PLN-081 cutover coordinator)

## When this applies

Enceladus MCP (mcp.jreese.net) is unreachable, or the MCP/tracker plane is itself the surface under cutover or active debugging.

## Boot procedure (file-boot)

1. Open docs/cutover-context/ on v4/main (io-local mirror: /Users/jreese/enceladus/workspace/cutover-context-2026-08-21).
2. Read README.md and MANIFEST.md first -- staleness is self-declaring via per-artifact export timestamps and the recorded governance_hash.
3. Load the catalog, blueprint, and deploy-path artifacts; state to the operator: active plan, current cutover phase, open blockers, and the MANIFEST export timestamp your statements are based on.
4. Prefix EVERY record-state claim with UNVERIFIED-OFFLINE. All claims are as-of the MANIFEST timestamp, not live truth.

## Hard rules while offline

- ZERO governed writes: no tracker, documents, checkout, deploy, or governance mutations, and no scripts that would mutate on your behalf.
- No direct DynamoDB or S3 writes ever (IAM denies them; do not attempt workarounds). This outage does not suspend ENC-TSK-564.
- Allowed: local code work in task worktrees, analysis, drafting docs as local files, git commits on agent branches.
- Every completed unit of work becomes a local F6 HANDOFF block appended to workspace/offline-handoff-queue.md with: record id, status claim (marked UNVERIFIED-OFFLINE), evidence, and the intended tracker mutations written out verbatim (action + arguments) for later replay.
- mcp-gamma MAY be used READ-ONLY as a secondary context surface ONLY when gamma is not the plane under debug or cutover. Never mutate via gamma. During the B69 route-flip window gamma is coupled to the plane under change -- do not use it at all.

## Post-restore reconciliation

1. connection_health for a fresh governance_hash; re-read every touched record live before replaying anything. Session caches and queued blocks are hypotheses, not truth (ENC-LSN-043).
2. For each queued F6 block: re-verify its preconditions against live state; apply the mutations through MCP with the fresh hash; mark the block RECONCILED with the resulting worklog refs. On any discrepancy, worklog the discrepancy on the record and stop -- never force.
3. Sweep for checkout wedges created during the outage (ENC-ISS-597 class) and release stale locks via the stale-checkout recovery recipe (release with the old session as provider, then re-checkout).

## Proof standard

A valid boot proof is a session that read ONLY the bundle files and correctly stated: the active plan, the current cutover phase, the open blockers, and the next gated step -- captured as transcript evidence on ENC-TSK-O20.
