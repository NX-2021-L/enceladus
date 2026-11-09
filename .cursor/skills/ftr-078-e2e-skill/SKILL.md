---
name: ftr-078-e2e-skill
description: "E2E skill for ENC-FTR-078 post-deploy verification. Invoke documents.put with document_subtype=skill + full_description + claude_description + agentskills_manifest (name/description/version) + agentskills_spec_version='0.1.0' + >=2 related_items. Confirms the Claude-install path round-trip."
---

Enceladus E2E smoke-test skill — how to invoke a governed documents.put against the deployed document_api Lambda with document_subtype=skill, confirming all required fields (full_description, claude_description, agentskills_manifest, agentskills_spec_version) pass the post-FTR-078 validators. Trigger: invoke when verifying post-deploy live surface. Context: requires a project_id, a 1024-char-max claude_description, a valid 0.1.0-spec agentskills_manifest, and >=2 related_items. Governance: every write rotates S3 state; backward-compat preserves legacy subtype reads.
