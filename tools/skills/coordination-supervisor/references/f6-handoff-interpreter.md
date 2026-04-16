# F6 HANDOFF Block Interpreter

Parse-verify-route workflow for interpreting HANDOFF blocks from dispatched agent worklogs.

Source: DOC-D4D7D8606824 section F6

---

## Parse Phase

Extract the HANDOFF block from the dispatched agent's task worklog. Two block types are recognized:

- **GOVERNANCE_SYNC_REQUIRED** — the agent produced a governance file update that requires product-lead IAM to land
- **EXECUTION_REQUIRED** — the agent produced a deploy or infrastructure mutation that requires elevated permissions

### Field Extraction

Parse the following fields from the block body:

| Field | Required | Description |
|-------|----------|-------------|
| `file_name` | Yes | Target governance or config file path |
| `content_source` | Yes | Where the proposed content lives (inline, docstore ref, or local path in agent worktree) |
| `s3_target` | Yes | Full S3 URI for the write destination |
| `archive_path` | Yes | S3 URI for the pre-mutation archive copy |
| `change_summary` | Yes | Human-readable description of what changed and why |

### Format Validation

- All five required fields must be present in the block
- No field may have an empty value
- The block must be delimited by the standard HANDOFF fence markers
- If any field is missing or empty, the supervisor logs a parse failure and surfaces it to io via F7 (decision queue) rather than attempting repair

---

## Verify Phase

After successful parsing, the supervisor validates the proposed change before routing it for execution.

### Content-Summary Cross-Check

- Read the proposed file content from `content_source`
- Compare against `change_summary` to confirm the summary accurately describes the delta
- Flag discrepancies for io review — do not silently accept a mismatch

### Governance File Validation

For governance files (governance data dictionary, agents.md, bootstrap templates):

- Confirm the proposed content is syntactically valid (well-formed JSON for dictionary files, valid Markdown structure for prose files)
- Verify the file targets a recognized governance path — reject writes to arbitrary S3 locations

### Deploy-Package Validation

When the HANDOFF block describes a Lambda deployment:

1. **Canonical deploy script**: Verify the command invokes `backend/lambda/<name>/deploy.sh` — the canonical deploy path for the named Lambda. Reject blocks that construct ad-hoc deploy commands.

2. **Build step present**: Confirm the block includes a `pip install` step with `--platform` targeting (e.g., `--platform manylinux2014_x86_64`). Deployments without platform-targeted builds produce architecture mismatches in production.

3. **Architecture and runtime assertions**: The block must include assertions derived from the live Lambda configuration (queried via AWS CLI or MCP), not hardcoded assumptions. Expected values: architecture (x86_64 or arm64) and runtime (python3.11, python3.12, etc.) sourced from the running function.

4. **Raw zip command rejection**: If the HANDOFF block embeds raw `zip` commands instead of delegating to `deploy.sh`, **REJECT** the block. Surface it for io's review via F7 (Decision Surfacing Queue). Raw zip commands bypass the deploy script's built-in validations and were the root cause of the ENC-TSK-1292 Sev1 incident.

---

## Route Phase

After verification passes, the supervisor generates a dispatch block for execution by a product-lead terminal session.

### Dispatch Block Generation

- Emit an **F3 dispatch block** targeting a product-lead terminal session running under `io-dev-admin` IAM
- The dispatch block includes:
  - The verified HANDOFF content (file name, content source, S3 targets)
  - The archive path for pre-mutation backup
  - The change summary for io's review
  - The originating task ID and agent session reference

### Execution Boundary

The supervisor **NEVER** attempts the S3 write itself. The `enceladus-agent-cli` IAM policy explicitly denies all S3 write operations. The dispatch block is the supervisor's terminal output for this workflow — execution is a product-lead concern.

### Post-Sync Verification

After the product-lead session completes the governance sync:

1. Call `connection_health()` to verify the governance hash has rotated
2. Compare the new hash against the pre-mutation hash to confirm the write landed
3. Draft an acceptance-evidence stamping step for io's approval — the supervisor prepares the evidence payload but does not execute `tracker.set_acceptance_evidence` directly

---

## ENC-FTR-077 Dual-Append Pattern

Per FTR-077 AC5, product-lead terminal sessions that execute governance syncs must append completion records to **two** documents:

1. **Originating handoff document** — the docstore artifact created by the dispatched agent's HANDOFF block
2. **Active wave document** — the current coordination wave tracking aggregate progress

### Wave Document Identification

The interpreter includes wave-doc lookup instructions in the dispatch block it generates:

```
Use documents.search with document_subtype=wave to find the active wave document.
Append the sync-completion record to both the handoff doc and the active wave doc.
```

The supervisor notes this dual-append requirement explicitly in every F3 dispatch block that routes a governance sync, so the product-lead session does not need to independently discover the requirement.
