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

## Tests

```bash
cd backend/lambda/rhythm_cycle
python -m unittest test_rhythm_cycle -v
```
