# Enceladus repo — Claude Code bootstrap

Repo agent rules live in `AGENTS.md`; governance rules live in governance `agents.md` (read via MCP, never copied here).

> **Cost rules (binding):** governance `agents.md` §cost, rule-block v1 (sha256 `e44e51efbd6592b99f401fb58b4351644642075399f5831e11d850a164775587`, ENC-TSK-R21 / ENC-PLN-100). Paste the block verbatim into every subagent prompt; every dispatched task carries a cost class (C0 read-only, C1 per-activity, C2 per-event runtime path, C3 persistent monthly-billed resource). Read it with `governance.get("agents.md")`; do not copy it here.
