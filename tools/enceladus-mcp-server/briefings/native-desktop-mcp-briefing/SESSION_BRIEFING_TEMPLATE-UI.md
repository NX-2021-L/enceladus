# Session Briefing Template

Copy the block below and paste as the first message to start a native desktop session.

---

```text
enceladus

This is an MCP-only session. All interactions with Enceladus system resources
go through the active Enceladus MCP server alias (for example: enceladus or enceladus-local). Do not use direct CLI tools, AWS SDK,
or cloud API access.

Governance resource: governance://agents.md

Resolve the active Enceladus MCP server alias, then read governance agents.md
using governance_get("agents.md") and follow its session initialization instructions.
(Fallback if governance_get is unavailable: aws s3 cp s3://jreese-net/governance/live/agents.md - --profile enceladus-agent)
```
