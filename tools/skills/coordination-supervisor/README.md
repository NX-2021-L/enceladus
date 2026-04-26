# Coordination Supervisor Skill

**Version**: 0.1.0
**Source Spec**: DOC-D4D7D8606824 (Coordination Supervisor Skill Feature Spec v3)
**Plan**: ENC-PLN-028 | **Task**: ENC-TSK-E40
**Related**: ENC-PLN-027 (Deploy Safety & Dual-Wheel Discipline)

## Overview

The Coordination Supervisor is a Claude Desktop skill that provides a consistent
human-AI surface layer for supervising multi-agent Enceladus activity. It sits one
step above the coordination lead and translates multi-session workspace activity into
a form io can supervise at speed.

### MVP Features (v0.1.0)

- **F2** -- Handoff Document Generator (3 template variants + Lambda-deploy rule)
- **F3** -- Dispatch Prompt Block Producer (3 dispatch contexts + retry budget)
- **F6** -- HANDOFF Block Interpreter (parse-verify-route + deploy-package validation)

### Stubbed Features (future iteration)

F1 (Concurrency Map), F4 (Executive Summary), F5 (Velocity Telemetry),
F7 (Decision Queue), F8 (Anchor-Word Resonance), F9 (Substrate Resilience).
See `references/stubbed-features.md` for pointers to DOC-D4D7D8606824 sections.

### Built-in Session Init

The skill includes a built-in Enceladus governed session init protocol
(DOC-ABEC1070C060 v2). When activated, the skill automatically runs health check,
loads open tasks, lessons, and plan status before responding. **The user does not
need to init the session manually before using this skill.**

## Installation

### Option A: Direct copy (recommended)

Copy the skill directory into your Claude Code skills path:

```bash
cp -r tools/skills/coordination-supervisor/ ~/.claude/skills/coordination-supervisor/
```

### Option B: Plugin directory flag (development)

Point Claude Code at the skill directory for development use:

```bash
claude --skill-dir /path/to/enceladus/repo/tools/skills/coordination-supervisor
```

### Option C: Symlink (keeps repo as source of truth)

```bash
ln -s /path/to/enceladus/repo/tools/skills/coordination-supervisor \
      ~/.claude/skills/coordination-supervisor
```

## Verification

After installation, open a new Claude Code session and try one of these trigger phrases:

- "coordination supervisor"
- "supervise my coordination"
- "generate a handoff document"
- "create a dispatch prompt"
- "interpret a HANDOFF block"
- "summarize agent activity"

The skill should activate and run the session init protocol automatically before
responding to your request.

## Scope Separation

The skill honors the supervisor scope-separation invariant. It will NEVER:

- Perform `checkout.task`, `checkout.advance`, or `checkout.append_worklog`
- Execute git operations or modify files directly
- Run `governance.update` or deploy mutations

See `references/scope-separation-invariant.md` for the complete prohibition list
and a worked negative-case example.

## Design Notes

**Architecture**: Bare skill directory with SKILL.md at root, matching the
`/mnt/skills/public/*/SKILL.md` convention. No plugin wrapper needed -- Claude
Desktop discovers skills by SKILL.md presence.

**Why bare directory over plugin**: AC1 specifies "SKILL.md at its root" and AC5
specifies "directory structure that can be copied directly." The bare directory
satisfies both without the overhead of `.claude-plugin/plugin.json`.

**ENC-FTR-077 concurrency**: The `handoff`, `coe`, and `wave` docstore subtypes
are being formalized concurrently. F2 templates already use the canonical `handoff`
subtype, and F6 includes the dual-append pattern (FTR-077 AC5). Schema changes
from FTR-077 may require template updates post-merge.

**Session init**: Built-in token-optimized v2 init protocol (DOC-ABEC1070C060)
reduces init overhead by ~85% compared to v1 by lazy-loading governance artifacts
and eliminating system-prompt/agents.md duplication.

## File Structure

```
coordination-supervisor/
  SKILL.md                          -- Core skill definition
  README.md                         -- This file
  references/
    f2-handoff-templates.md         -- F2: Handoff document generator templates
    f3-dispatch-templates.md        -- F3: Dispatch prompt block templates
    f6-handoff-interpreter.md       -- F6: HANDOFF block interpreter workflow
    scope-separation-invariant.md   -- Prohibition list + negative case
    stubbed-features.md             -- F1/F4/F5/F7/F8/F9 pointers
```
