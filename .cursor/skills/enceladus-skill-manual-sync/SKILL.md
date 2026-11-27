---
name: enceladus-skill-manual-sync
description: "Takes a docstore document ID as input, fetches the skill record from the Enceladus MCP docstore, and exports two copy-pasteable text blocks formatted for manual entry into the claude.ai or claude desktop skill manager: (1) Description — the plain-text trigger string <=1024 chars derived from claude_description, and (2) Instructions — the markdown skill body derived from full_description. Trigger on \"sync skill\", \"export skill\", \"manual sync\", \"skill manager format\", or when io provides a DOC-* ID and wants the Description and Instructions blocks ready to paste. NOT for skill authoring (use skill-builder-alpha/beta), health scanning (use skill-builder-prod), or dispatch (use coordination-supervisor)."
---

Fetches a skill record from the Enceladus docstore by ID and emits two clean copy-pasteable blocks for manual entry into the claude.ai or claude desktop skill manager.

## Resume Gate (DOC-79631EBFF71D)

This skill already re-fetches the source document live on every invocation, which is the correct posture. The one caveat: never reuse a body fetched earlier in the session. If asked to re-sync after an edit, re-run documents.get -- a cached body is presumed stale, and emitting it would paste an out-of-date skill into the manager.

---

## Protocol

### Step 1 — Fetch the document

```text
search(action="documents.get", arguments={"document_id": "<input DOC-ID>"})
```

### Step 2 — Extract fields

- Description block source: `claude_description` field
- Instructions block source: `full_description` field

If `claude_description` is absent or empty, derive from the document `description` field, truncating to 1024 characters at the nearest sentence boundary.

If `full_description` is absent, use `content` field as fallback.

### Step 3 — Validate Description

- Must be plain text (no markdown, no backticks, no newlines)
- Must be <= 1024 characters
- If over limit, truncate at nearest sentence boundary and append "..."
- Report character count alongside the block (e.g. 743/1024)

### Step 4 — Reformat Instructions

Emit the full_description body as-is EXCEPT:

- Strip any leading YAML frontmatter block (--- ... ---) if present
- Strip the H1 title if it duplicates the skill name
- Preserve all other markdown: headings, code blocks, bold, lists

### Step 5 — Emit output

Emit exactly two labeled blocks with no other commentary:

**DESCRIPTION** (paste into Description field):

[plain text content here]

**INSTRUCTIONS** (paste into Instructions field):

[markdown content here]

### Step 6 — Post-emit check

After emitting, report: document ID and title, description character count (N/1024), whether full_description or fallback was used, any truncation applied.

---

## Error Handling

- Document not found: report the ID and stop. Do not guess or substitute.
- document_subtype is not "skill": warn io but emit blocks anyway if content exists.
- claude_description and description both missing: emit Instructions only; flag Description as unavailable.

---

## Scope

Read-only. No mutations, no tracker writes, no checkout required.

Forbidden: documents.patch, tracker.set, execute(), any write surface.

---

## Governance Awareness (detail DOC-28C7B321D060)

- SCI required on every governed mutation + server-minted ENC-SES-NNN, else 403 (ENC-FTR-122).
- FSM-forbidden mutations (arc change, state override, post-closure) route escalation.request -> ENC-ESC-NNN -> io approval in PWA; never re-create records or hand-edit DDB (ENC-FTR-121).
- Autonomous builds are stall-watched from the isolated enceladus-support repo; silent stalls notify io (ENC-FTR-119).
- Deploy/CFN: DOC-BAEB4AC14720 + DOC-B716E8FB10B6 + DOC-CAE64D63F326.
