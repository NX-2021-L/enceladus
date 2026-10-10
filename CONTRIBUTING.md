# Contributing

## UI parity: generic coverage by default (DVP-TSK-895, supersedes route-or-waiver)

`enceladus.jreese.net` runs the io-kit parity job (`.github/workflows/parity-report.yml`) as a
blocking ratchet against `frontend/ui-v2/parity/baseline.json` (flags-off basis: flag-gated actions
are excluded). Since DVP-TSK-895 the baseline is 82 covered / 0 partial / 0 missing of 82.

**A new registry action needs no route, no map entry and no waiver.** Every action in
`tools/enceladus-mcp-server/parity/caps.json` is covered generically: the command palette lists it,
`/actions/<name>` renders a form from its `inputSchema`, calls `execute` with `dry_run:true`, shows the
server-verified ResolvedCall v1 preview, then executes with an `Idempotency-Key` and shows the receipt
with the minted ids. When the action is added, also refresh the committed copy
`frontend/ui-v2/src/actions/capsFull.json` and `src/shell/capsSnapshot.json`
(`registry.test.ts` fails when `capsFull.json` drifts from `caps.json`).

The route-or-waiver convention now applies **only to bespoke overrides**: if you build a dedicated
screen for an action, add an `ACTION_RULES` entry in `frontend/ui-v2/parity/generate_parity.py`, add the
action to `BESPOKE_ACTIONS` in `src/actions/registry.ts`, and regenerate (`python3
frontend/ui-v2/parity/generate_parity.py`, commit `routes.yaml` and `map.yaml`). A waiver
(`parity/waivers.yaml`, `{action, surface: enceladus, owner, reason, expires}`, at most 30 days out) is
only for an action the generic path cannot serve. The ratchet still fails when `covered` drops or
`missing` rises; lowering the baseline is a deliberate edit.
