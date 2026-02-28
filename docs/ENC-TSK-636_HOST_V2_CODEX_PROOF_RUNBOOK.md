# ENC-TSK-636 Host-v2 Codex Proof Runbook

This runbook defines the reproducible validation flow for proving Codex works in an EC2 host-v2 SSH session.

## Goal

Produce auditable artifacts showing:

1. Host-v2 bootstrap ran.
2. `codex` is installed and executable.
3. A prompt was submitted with `codex exec`.
4. The response contains a deterministic verification token.

## Script

Use:

`tools/enceladus-mcp-server/validate_host_v2_codex.sh`

## Required Input

- SSH target for host-v2 (`ec2-user@<host>` or equivalent)
- SSH key path if required by your environment

## Command

```bash
tools/enceladus-mcp-server/validate_host_v2_codex.sh \
  --ssh-target ec2-user@<host-or-ip> \
  --ssh-key ~/.ssh/<key>.pem
```

Optional flags:

- `--workspace /home/ec2-user/claude-code-dev`
- `--prompt "<custom prompt>"`
- `--output-dir artifacts/enc-tsk-636`
- `--ssh-port 22`

## Success Criteria

The run succeeds only when:

- script exit code is `0`
- `proof_summary.md` shows `result: passed`
- `codex_last_message.txt` includes the verification token

## Evidence Artifacts

Artifacts are written under:

`artifacts/enc-tsk-636/<UTC_TIMESTAMP>/`

Files:

- `proof_summary.md`
- `summary.json`
- `bootstrap.log`
- `codex_version.txt`
- `codex_events.jsonl`
- `codex_last_message.txt`
- `ssh_stdout.log`

## Tracker Logging Guidance

When validation succeeds, log:

- exact artifact folder path
- codex version from `codex_version.txt`
- verification token and match confirmation
- any bootstrap warnings from `bootstrap.log`

