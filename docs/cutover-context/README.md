# docs/cutover-context/ — Cutover Context Freeze Bundle

Boot source for terminal agents when Enceladus MCP (mcp.jreese.net) is unreachable, or when
the MCP/tracker plane is itself the surface under cutover or active debugging. See
`offline-session-protocol-DOC-FC8ABF29B738.md` for the full offline session protocol
(boot procedure, hard rules, post-restore reconciliation).

**Start here:** read this README, then `MANIFEST.md` — staleness is self-declaring via the
per-artifact export timestamps and the recorded `governance_hash` in the manifest. Every
claim sourced from this bundle is as-of its export timestamp, not live truth.

| File | Source | Purpose |
| --- | --- | --- |
| `catalog-DOC-841F5D649EEF.md` | DOC-841F5D649EEF (docstore) | PLN-006/PLN-078 coding-task catalog — ADE dispatch source of truth; cutover-day blocker board and gate status |
| `blueprint-DOC-6EFD5DB32CD8.md` | DOC-6EFD5DB32CD8 (docstore) | Enceladus v4 greenfield architecture and migration blueprint |
| `deploy-path-DOC-B716E8FB10B6.md` | DOC-B716E8FB10B6 (docstore) | v3-prod surgical deploy brief — consent protocol, deploy channels A/B/C, COE + registry |
| `DOC-FFB4C9D87BCC.md` | DOC-FFB4C9D87BCC (docstore) | Enceladus governed dispatched-agent session prompt (copy-pastable boot prompt) |
| `coord-lead-init-DOC-586FB8D3DF02.md` | DOC-586FB8D3DF02 (docstore) | Enceladus coordination-lead session prompt (orchestration role, scope exclusions) |
| `governance-agents.md` | `governance://agents.md` | Full agent rules governance file |
| `governance-dictionary-snapshot.json` | repo `backend/lambda/coordination_api/governance_data_dictionary.json` | Bundled-Lambda governance data dictionary snapshot — this is the surface prod actually serves as fallback; NOT the S3 `governance/live/` authoritative copy |
| `connection-health-snapshot.json` | `search(action="system.connection_health")` | Live platform health + `governance_hash` captured at session init |
| `offline-session-protocol-DOC-FC8ABF29B738.md` | DOC-FC8ABF29B738 (docstore) | MCP-down offline session protocol — boot procedure, hard rules, post-restore reconciliation, proof standard |

See `MANIFEST.md` for per-artifact export timestamp, source, sha256, and the session
`governance_hash` this bundle was assembled under.
