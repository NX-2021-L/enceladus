# ENC-FTR-029 Session Archive Spec

## Scope

Archive EC2-hosted Codex session turns to S3 from coordination runtime without patching the Codex runtime.

## Lifecycle Hook

- Capture trigger: `coordination_api` SSM terminal refresh path.
- Input sources:
  - prompt: `dispatch.prompt_submitted`
  - response: provider summary/result or SSM stdout
- Output sink: S3 object per dispatch turn bundle.

## Record Schema

Each archived turn record includes:

- `schema_version` (string)
- `session_id` (string)
- `ec2_instance_id` (string)
- `dispatch_id` (string)
- `timestamp_utc` (ISO-8601 UTC)
- `turn_index` (integer)
- `role` (`user` or `assistant`)
- `content` (string, redacted)
- `token_count` (optional integer)
- `redaction_tags` (array of applied redaction rule names)

## S3 Layout

Prefix pattern:

`codex-sessions/{year}/{month}/{day}/{session_id}/{turn_index}-{dispatch_id}.json.gz`

This supports:

- session replay by scanning keys containing `/{session_id}/`
- date-range listing via partition prefixes `/{year}/{month}/{day}/`

## Compression and Versioning

- Compression: gzip (`ContentEncoding=gzip`)
- Content type: `application/json`
- Version strategy:
  - `schema_version` embedded in every record
  - additive-only schema changes
  - no destructive field renames/removals without migration note

## Redaction Policy

Inline regex redaction before S3 write:

- AWS access key IDs
- Bearer tokens
- secret/token/api-key environment assignments
- generic api_key/token/secret key-value patterns
- PEM private key blocks

Replacement format:

- `[REDACTED:<type>]`

## Reliability

- S3 write retries: exponential backoff, max 3 attempts
- On retry exhaustion: write failure payload to local buffer path
  - `/tmp/coordination-session-archive-buffer`
- Buffered payload includes target S3 key, records, and error details

## Retrieval Utility

Tool:

`tools/enceladus-mcp-server/session_archive_query.py`

Examples:

```bash
# Replay a session
python3 tools/enceladus-mcp-server/session_archive_query.py \
  --session-id <session_id> \
  --output replay

# Summary for a session
python3 tools/enceladus-mcp-server/session_archive_query.py \
  --session-id <session_id> \
  --output summary

# List/replay all archived records for a date
python3 tools/enceladus-mcp-server/session_archive_query.py \
  --date 2026-02-28 \
  --output raw

# Date-range replay
python3 tools/enceladus-mcp-server/session_archive_query.py \
  --start-date 2026-02-28 \
  --end-date 2026-03-02 \
  --output replay
```

