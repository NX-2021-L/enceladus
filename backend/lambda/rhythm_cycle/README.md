# Rhythm Cycle Lambda (ENC-PLN-068)

Cost-weighted harmonic scheduling beats for gamma. See DOC-BDDE755DB874.

## S3 artifact key convention

All cycle artifacts live under:

```
{s3_env_prefix}rhythm-cycle/{tier}/{YYYY}/{MM}/{DD}/{HHmmss}.json   # timestamped
{s3_env_prefix}rhythm-cycle/{tier}/latest.json                        # pointer
```

Gamma uses `S3_ENV_PREFIX=gamma/` so keys become `gamma/rhythm-cycle/sense/latest.json`.

## Tiers

| Tier | Cadence | EventBridge Scheduler group |
|------|---------|----------------------------|
| sense | hourly :00 | rhythm-sense |
| light_integrate | 4x/day :15 | rhythm-light |
| decide | 8x/day :30 | rhythm-decide |
| heavy_integrate | 2x/day :45 | rhythm-heavy |
| coherence | 2x/day :00 | rhythm-coherence |

## Baseline capture (on-demand) — ENC-TSK-N26

Pre-cutover baseline capture (BRD DOC-44230223DD1C Wave 3 / ENC-TSK-N08 AC-3)
is a standalone, on-demand event mode on this same Lambda -- **not** part of
the scheduled harmonic beat chain above (no cadence, no EventBridge
Scheduler group, no `TIER_PREDECESSOR` entry). It writes one Sense-adjacent
artifact under `{s3_env_prefix}rhythm-cycle/baseline/latest.json` covering
four artifact classes: a percolation-telemetry export, a fixed-query
retrieval-quality run, a lesson citation-rate estimate, and corpus
invariants (N, M, mean degree, second moment, modularity Q, hot-tier
fraction — each either derived or explicitly marked not computable from this
Lambda's read surface). See `baseline.py` module docstring for the full
per-class design.

Invoke on demand:

```bash
aws lambda invoke \
    --function-name <rhythm-cycle-function-name> \
    --payload '{"tier": "baseline_capture"}' \
    --cli-binary-format raw-in-base64-out \
    /tmp/baseline_capture_out.json
```

This is **io/terminal-invoked only**. The `enceladus-agent-cli` IAM role
(agent CLI sessions) cannot call `lambda:InvokeFunction` — that is a
deliberate permission-boundary gap, not an oversight; baseline capture during
the actual baseline week is a human-triggered action.

No schedule resource exists for this tier today (code path only, per BRD
Wave 3). Making it recurring later is a matter of adding an EventBridge
Scheduler entry targeting `{"tier": "baseline_capture"}`, the same way the
tiers above are wired — no code change required.

## Tests

```bash
cd backend/lambda/rhythm_cycle
python -m unittest test_rhythm_cycle -v
python3 -m pytest backend/lambda/rhythm_cycle/ -q   # from repo root; also runs test_baseline.py
```
