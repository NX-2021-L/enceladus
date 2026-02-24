# Infrastructure Metadata

This directory stores deployment metadata and parity-audit assets for Enceladus.

- `lambda-manifests/` — per-function runtime/deploy metadata + live hash evidence.
- `parity/lambda_function_map.json` — canonical map used by nightly parity audit.
- `lambda-live-inventory-2026-02-24.json` — initial imported live inventory snapshot.
- `parity/out/` — runtime-generated nightly audit outputs (CI artifacts).
- `scripts/deploy_compliance_guardrails.sh` — creates/updates governance policy + compliance tables and publishes CloudWatch dashboard for ENC-FTR-020.
