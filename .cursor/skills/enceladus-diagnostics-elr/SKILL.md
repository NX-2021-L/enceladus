---
name: enceladus-diagnostics-elr
description: "Read-only diagnostic that answers whether this machine can use the current Enceladus Local Runner (ELR) for EVERY governed project, and under which agent tool. Nine checks: source reachability, install currency (metafile _pulled_source_ref versus last commit touching tools/elr; elr_sync verify alone calls a stale install healthy), an absolute 3.11 interpreter with certifi, credential posture per surface, TLS resolution, live reachability on both environment profiles with a governance-hash match, local state hygiene, a live CROSS-PROJECT PROBE (ENC-* plus non-ENC id from elr census), and a live compact_context check, both required for READY: a single-project ELR is DEGRADED, never READY (ENC-ISS-791 / ENC-TSK-Q10). Trigger on 'can I use ELR here', 'check my ELR', 'enceladus-diagnostics-elr', 'why did elr fail', 'is my ELR current', an ELR command-not-found, exit 2 or 4, or as step 0 of enceladus-elr. Emits READY, DEGRADED or NOT-READY plus ranked remediation. Never writes, never mutates, never echoes a secret."
---

# Enceladus ELR Diagnostics

Read-only. Answers one question: can this machine use the current ELR, for EVERY governed
project, and under which agent tool? Never writes, never mutates, never echoes a secret.

`elr_sync.py verify` says `ok: true` on a month-stale install: it re-hashes disk against the
manifest written AT PULL TIME ("intact", never "current", ENC-LSN-077). Check 8 makes a
single-project ELR DEGRADED by construction (ENC-ISS-791); check 9 does the same for a host without the
compact_context verb (ENC-FTR-147).

Run every ELR step through `<ELR_CMD>` = `~/.enceladus/elr/elr <sub>` (the managed launcher,
ENC-TSK-Q35); `<PY> <ELR>/elr_<sub>.py` is equivalent. Neither reads `~/.claude.json`.

## The nine checks

1. SOURCE. `tools/elr` is on origin/main ONLY.
   `git -C <repo> fetch origin && git log -1 --format=%H origin/main -- tools/elr` -> LAST.

2. CURRENCY. Compare `~/.enceladus/elr/bin/.elr-sync-manifest.json` **`_pulled_source_ref`**
   (NOT `source_ref`) against LAST; judge completeness against the manifest entries. Absent =
   stale: elr_doc_digest.py, elr_doc_patch.py, elr_lib/vendor/*.py, and (post ENC-TSK-Q35) the
   `elr` launcher and elr_provision_key.py. PRESENT = stale: `elr_lib/prefix.py` or
   `~/.enceladus/prefix_map.json` (ENC-TSK-Q11).

3. INTERPRETER. Resolve an ABSOLUTE 3.11 binary (a pyenv shim can resolve and still fail),
   confirm `certifi` imports from it; the launcher reads the pin `.elr-python`.

4. CREDENTIAL. ELR resolves it in elr_lib: `ENCELADUS_AGENT_CREDENTIAL` /
   `~/.enceladus/credential.json` (FTR-074), then the internal-key env vars, then the ELR key file
   `~/.enceladus/internal_key` (mode 0600/0400). Report presence and mode only, never a value.
   None present = NOT-READY: io runs `tools/elr/elr_provision_key.py`; agents never write it.

5. TLS. SSL_CERT_FILE -> certifi -> interpreter default (non-empty store only) -> `missing` (exit 4).

6. LIVE. `<ELR_CMD> smoke --all-profiles`: one object per profile (prod, v4-gamma). Each needs
   `ok: true`, `auth_probe.ok: true`, `identity_posture` not `unknown`, and `governance_hash`
   equal to connection_health's. Exit 7 = no credential (check 4). Any failure = NOT-READY.

7. LOCAL STATE. `~/.enceladus/docs` (digest side files + doc_patch cache) versus
   `~/.enceladus/elr/cache` (doc_get default). Side files older than 24h cause exit 2.

8. CROSS-PROJECT PROBE (the READY gate). Pick ids AT RUN TIME: `<ELR_CMD> list --project
   enceladus --type task --status open --census` -> `pages[0].first.id`; repeat for an ACTIVE
   non-ENC project (MCP `projects.list`); count 0 -> drop `--status`; exit 6 -> pick via MCP
   `tracker.list page_size:1`. Run `<ELR_CMD> batch_get --ids <ENC-ID>,<OTHER-ID> --json`. READY
   needs `ok: true`, both rows `outcome: "found"` with the server `project_id`, `anomalies: []`.
   Else DEGRADED naming the id: `sentinel_route_unsupported_by_server` -> plane predates
   ENC-TSK-Q10, use MCP; `not_found` -> re-pick; `forbidden`/401/403 -> check 4.

9. COMPACT_CONTEXT VERB PRESENT AND LIVE. The installed manifest pins `elr_compact_context.py`
   (absent = stale install, see check 2). Then on EACH profile run `<ELR_CMD> compact_context
   --mode record --record-id <check-8 ENC id> --top-n 3 --profile <P>`: exit 0; prod needs
   `signals_present` of size 3, v4-gamma non-empty. Exit 6 = plane lacks hybrid, 8 = shape drift, 7 = check 4.
   Failure = DEGRADED naming the profile: reads go to MCP.

## Output and remediation

One digest line, ranked remediation, one verdict. NOT-READY: any of checks 1-6 fails. DEGRADED:
check 7, 8 or 9 fails; name the check and id; ALL reads go to MCP. READY: all nine pass. No "READY
for documents only". Stale install: `<PY> <ELR>/elr_sync.py pull --ref <FULL 40-hex sha>
--source github --dest ~/.enceladus/elr/bin` (arm gh first); it refreshes the launcher link.

## Never

Print, copy or write a key. Mutate anything. Report READY without checks 6, 8 AND 9. Split the read
surface: a failed check 8 or 9 means every read goes to MCP.
