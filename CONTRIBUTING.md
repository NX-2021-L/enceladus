# Contributing

## UI parity: route or waiver (DVP-TSK-862)

`enceladus.jreese.net` runs the io-kit parity job (`.github/workflows/parity-report.yml`) in
blocking-with-ratchet mode on a flags-off basis (flag-gated actions are excluded, in the
baseline, the gate and the report). The job fails a PR when `missing` rises above, or `covered`
drops below, `frontend/ui-v2/parity/baseline.json`. It never requires coverage to rise.

A PR that adds an action to the MCP registry (`tools/enceladus-mcp-server/parity/caps.json`)
must, in the same PR, do one of:

1. **Route**: add the ui-v2 route/handler and an `ACTION_RULES` entry in
   `frontend/ui-v2/parity/generate_parity.py`, then run `python3 frontend/ui-v2/parity/generate_parity.py`
   and commit `routes.yaml` and `map.yaml`.
2. **Waiver**: add `{action, surface: enceladus, owner, reason, expires}` to
   `frontend/ui-v2/parity/waivers.yaml`. `expires` must be at most 30 days out; an expired waiver fails the job.
3. **Baseline bump**: rewrite the baseline deliberately (`io-kit parity baseline write --out
   frontend/ui-v2/parity/baseline.json` with the same arguments the job uses, no `--flags`) and
   say why in the PR body. Reviewers treat a baseline that gets worse as a decision, not a formality.

Run the proof locally: `python3 -I -m unittest discover -s frontend/ui-v2/parity/tests`
(the route-or-waiver tests need the `io-kit` CLI on PATH).
