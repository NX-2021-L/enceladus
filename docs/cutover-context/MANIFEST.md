# MANIFEST — docs/cutover-context/

Staleness is self-declaring: every artifact below carries its own source `updated_at`/`version`
(the state of the record when exported) and this manifest's `bundle_export_started_at` /
`bundle_export_completed_at` (when the export actually ran). Treat every claim in this bundle as
true only as of these timestamps — reconcile against live MCP before acting on anything stale.

```yaml
session_governance_hash: e04f7eda77c472a49717d6f0e6107da208712f8d79f296a3c479675fdde85152
session_id: ENC-SES-0EH
sci: SCI-5accb5055e4743d9a96d566270a936b7
bundle_export_started_at: "2026-08-21T18:44:10Z"   # connection_health checked_at, session init
bundle_export_completed_at: "2026-08-21T18:51:22Z"
task: ENC-TSK-O19
note: >
  Mid-export the original task worktree (.claude/worktrees/enc-tsk-o19-cutover-context-bundle)
  was torn down by a concurrent session's worktree stale-lock sweep (ENC-ISS-071 class) after
  8 of 9 artifacts had already been written but before any commit existed. Those 8 files were
  rescued from disk, the worktree was recreated from a fresh origin/v4/main fetch, and the
  rescued files were committed immediately (commit 8bd89da) before continuing. This manifest
  and the governance-dictionary-snapshot.json / README.md were produced after that recovery.
```

## Artifacts

### catalog-DOC-841F5D649EEF.md
- source: DOC-841F5D649EEF (docstore document)
- source_version: 137
- source_updated_at: 2026-08-21T18:08:59Z
- exported_at: 2026-08-21T18:45Z
- sha256: 8048886d1c36794c9b47efbd3202a30f687726538c8f729da0801d62865dd2e9
- note: matches docstore content_hash exactly (byte-identical export)

### blueprint-DOC-6EFD5DB32CD8.md
- source: DOC-6EFD5DB32CD8 (docstore document)
- source_version: 23
- source_updated_at: 2026-07-07T14:30:02Z
- exported_at: 2026-08-21T18:48Z
- sha256: 1dec878f2c462a7d0992607ef6d217a4ac20694812ce29681c364ac516527447
- note: matches docstore content_hash exactly (byte-identical export)

### deploy-path-DOC-B716E8FB10B6.md
- source: DOC-B716E8FB10B6 (docstore document)
- source_version: 6
- source_updated_at: 2026-08-14T04:59:23Z
- exported_at: 2026-08-21T18:46Z
- sha256: 42e88701ca5b75409882ab4050b9f348ff35a34aed07830df66ee32a2302655a
- note: matches docstore content_hash exactly (byte-identical export)

### DOC-FFB4C9D87BCC.md
- source: DOC-FFB4C9D87BCC (docstore document)
- title: "DOC-FFB4C9D87BCC Enceladus Governed Session Prompt — Gamma (v2)"
- source_version: 10
- source_updated_at: 2026-06-28T02:27:15Z
- exported_at: 2026-08-21T18:47Z
- sha256: 0c1f09d4914ccd669afe03bd41b6bfa42dcd45d1e620705a95977c01320fae07
- note: matches docstore content_hash exactly (byte-identical export)

### coord-lead-init-DOC-586FB8D3DF02.md
- source: DOC-586FB8D3DF02 (docstore document)
- title: "DOC-586FB8D3DF02 Enceladus Coordination Lead Session Prompt — Gamma (v2)"
- source_version: 7
- source_updated_at: 2026-06-28T02:31:03Z
- exported_at: 2026-08-21T18:48Z
- sha256: 75ef3d6befd430d6f1a5962762f0fec31892fe8367bd274869791019a262a9a2
- note: matches docstore content_hash exactly (byte-identical export)

### governance-agents.md
- source: governance://agents.md (`search(action="governance.get", arguments={file_name:"agents.md"})`)
- governance_revision (embedded token): 2026-06-30.09
- exported_at: 2026-08-21T18:48Z
- sha256: b944cec2f1deb509b3c25fdb2a7e0a78e0a572c4861fd5cfd2a9afc03823cf00

### governance-dictionary-snapshot.json
- source: repo path `backend/lambda/coordination_api/governance_data_dictionary.json`
- source_commit: 6218584 (origin/v4/main HEAD at fetch time, 2026-08-21T18:50Z)
- exported_at: 2026-08-21T18:51Z
- sha256: 44ee91e88e13f288d8536ca26d9131fda8bc687eb60b9a7dcba7982f24b63899
- note: this is the bundled-Lambda fallback surface (what prod actually serves when the DDB
  dictionary surface is unavailable), NOT the S3 `governance/live/governance_data_dictionary.json`
  authoritative copy. The dictionary has 3 decoupled live surfaces; this bundle captures only this one.

### connection-health-snapshot.json
- source: `search(action="system.connection_health")`, captured at session init
- checked_at: 2026-08-21T18:44:10Z
- governance_hash: e04f7eda77c472a49717d6f0e6107da208712f8d79f296a3c479675fdde85152
- exported_at: 2026-08-21T18:44:10Z
- sha256: d0d9f32989617c342c0bd839233669e090a85857b1713241969e0b370c6c4ac3

### offline-session-protocol-DOC-FC8ABF29B738.md
- source: DOC-FC8ABF29B738 (docstore document)
- title: "Enceladus MCP-Down Offline Session Protocol (B69 cutover, 2026-08-21)"
- source_version: 1
- source_updated_at: 2026-08-21T18:48:28Z
- source_content_hash (docstore-reported): 5f65bafba20a09789a59cb0b8b5f0dfd50cbd99a86d9a842ab9e0b52a5a8e756
- exported_at: 2026-08-21T18:49Z
- sha256 (this bundled file): 35da1990ac84a7b5b898ab0503ec1072c52d5c13ea1c77e3b809acc3fc425442
- note: differs from the docstore-reported content_hash by what appears to be a single
  trailing-newline/whitespace byte (size 2851 vs. reported 2850); content is otherwise a
  verbatim transcription of the fetched document body. Added mid-task per coordinator
  instruction (ENC-SES-0EG), replacing the originally-planned offline-protocol-PLACEHOLDER.md.
