---
name: enceladus-skill-sync
description: "Installs or upgrades a local Claude Code skill from an Enceladus governed docstore record. Takes a DOC-* document ID, fetches it via MCP documents.get, validates document_subtype is skill, reads agentskills_manifest.name, and writes ~/.claude/skills/<name>/SKILL.md with claude_description as frontmatter description and full_description as body. Strips webui-only scaffolding, docstore governance footer (Dreyfus stage, compliance, anchor words, adjacent skills), and any duplicate H1. Overwrites are upgrades in place — docstore is canonical, local copy always represents the latest managed version. Trigger on \"sync skill\", \"install skill\", \"upgrade skill\", \"enceladus-skill-sync\", or when io provides a DOC-* ID and asks to install or refresh it locally for terminal Claude Code. NOT for skill authoring (use skill-builder-alpha/beta), health scanning (use skill-builder-prod), or webui paste-format export (use enceladus-skill-manual-sync)."
---

Install or upgrade a local Claude Code skill from a governed Enceladus docstore record. Docstore is canonical -- every sync overwrites the local copy.

## Inputs

One DOC-* document ID. If io gives a different ID format, ask for the correct DOC-* ID first.

## Protocol

1. Fetch: `search(action="documents.get", arguments={"document_id": "<DOC-ID>"})`. `result.success` must be true; `document_subtype` should be `skill`; `agentskills_manifest` must parse as JSON.
2. Resolve name/path: `name = manifest["name"]`. Target: `~/.claude/skills/<n>/SKILL.md`. Detect existing file first (installed vs upgraded).
3. Build frontmatter description: `claude_description` (preferred) -> `description` field -> `manifest["description"]`. Plain text, no markdown/backticks/newlines, <=1024 chars, truncate at sentence boundary + "..." if over. Stop if all three sources empty.
4. Build body from `full_description`. Strip: leading YAML frontmatter; H1 if it duplicates the skill name; webui scaffolding (paste-into-skill-manager instructions, DESCRIPTION/INSTRUCTIONS copy-pasteable block steps, "copy-pasteable" framing); trailing governance footer (Dreyfus stage, compliance score, anchor words, adjacent skills, promote-to-beta criteria). If `manifest["runtime_hint"] == "claude-webui"`, also rewrite/drop webui-environment-assuming references (clipboard handoff, manual paste). Preserve all other markdown, the operational protocol, and MCP tool examples.
5. Compose: `---\nname: <n>\ndescription: <Step 3 result>\n---\n\n<Step 4 body>`.
6. Write: `mkdir -p ~/.claude/skills/<n>/`; write SKILL.md, overwrite any existing copy. No backup -- overwrite is the upgrade.
7. Report: DOC-ID + title; skill name + install path; installed/upgraded; manifest `version` + `content_hash` prefix (8 chars); description char count; what was stripped; reload note (next session start, or `/skills` in-session).

## Error handling

Document not found -> report and stop, no guessing. `agentskills_manifest` missing/unparseable -> stop. All description sources empty -> stop. Filesystem write failure -> report path + error, stop.

## Scope

Read: `documents.get` only. Write: local filesystem only, scoped to `~/.claude/skills/<n>/`. No tracker mutations, no `documents.patch`, no `execute()`, no `governance.update`.

## Non-goals

Skill authoring (skill-builder-alpha/beta). Health scans (skill-builder-prod). Webui paste-format export (enceladus-skill-manual-sync). Plugin installation, marketplace ops, settings.json mutations.

## Governance Awareness (detail DOC-28C7B321D060)

- SCI required on every governed mutation + server-minted ENC-SES-NNN, else 403 (ENC-FTR-122).
- FSM-forbidden mutations (arc change, state override, post-closure) route escalation.request -> ENC-ESC-NNN -> io approval in PWA; never re-create records or hand-edit DDB (ENC-FTR-121).
- Autonomous builds are stall-watched from the isolated enceladus-support repo; silent stalls notify io (ENC-FTR-119).
- Deploy/CFN: DOC-BAEB4AC14720 + DOC-B716E8FB10B6 + DOC-CAE64D63F326.
