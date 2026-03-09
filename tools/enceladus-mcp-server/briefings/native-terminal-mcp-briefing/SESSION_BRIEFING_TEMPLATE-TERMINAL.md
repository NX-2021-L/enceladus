# Session Briefing Template (Terminal / Host-v2)

Copy the block below and paste as the first message in local terminal sessions and host-v2 sessions that may not have MCP configured yet.

---

```text
enceladus

This is a terminal session that may start without Enceladus MCP configured.
Perform MCP bootstrap with setup-if-missing, then continue standard MCP-only initialization.

Bootstrap contract:
1) Detect whether MCP server "enceladus" is configured for this session.
2) If missing or invalid, install profile once using this briefing package installer:
   ENCELADUS_WORKSPACE_ROOT="$(pwd)" ./tools/enceladus-mcp-server/install_profile.sh
3) Validate MCP readiness by successfully running:
   - connection_health
   - coordination_capabilities
   - governance_hash
4) Read governance agents.md using governance_get("agents.md"), then complete standard init by loading:
   - governance_get("agents/bootstrap-template.md")
   - governance_get("agents/lifecycle-primer.md")
   Execute all required initialization steps from those governance resources.
   (Fallback if governance_get is unavailable: aws s3 cp s3://jreese-net/governance/live/agents.md - --profile enceladus-agent)

Operating mode:
- MCP-only for Enceladus system interactions.
- Lifecycle primer is mandatory before code work: know checkout arc, CAI/CCI flow, PR-body CCI placement, component strictness matching, and worktree CWD rules before first PR attempt.
- Do not use direct tracker/docstore CLI, boto3 scripts, or direct AWS API/CLI for normal task execution.
- If bootstrap fails, stop and report the exact failure stage and remediation needed.
```
