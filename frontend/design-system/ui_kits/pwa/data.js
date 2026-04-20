// Fixture data for the Enceladus PWA kit. IDs, scores, timings are plausible.
window.encData = {
  projects: [
    { prefix: 'ENC', project_id: 'enceladus', name: 'Enceladus', summary: 'Multi-agent governance platform. Core monorepo: MCP, Scoring, Checkout, PWA.', updated_at: '2026-04-20T11:12:00Z', open_tasks: 14, open_issues: 3, completed_features: 52 },
    { prefix: 'DVP', project_id: 'devops', name: 'DevOps', summary: 'CI/CD pipelines, secrets guardrail, nightly SHA-256 parity audits.', updated_at: '2026-04-19T22:04:00Z', open_tasks: 6, open_issues: 1, completed_features: 31 },
    { prefix: 'SHW', project_id: 'showcase', name: 'Showcase', summary: 'Public portfolio site at jreese.net/enceladus-showcase.', updated_at: '2026-04-18T14:30:00Z', open_tasks: 2, open_issues: 0, completed_features: 7 },
    { prefix: 'KND', project_id: 'kindred', name: 'Kindred', summary: 'Secondary constitutional-AI research spike. Dormant.', updated_at: '2026-04-10T09:00:00Z', open_tasks: 0, open_issues: 0, completed_features: 4 },
  ],
  tasks: [
    { task_id: 'ENC-TSK-A57', project_id: 'enceladus', title: 'Implement governed lesson primitive lifecycle gates', status: 'in-progress', priority: 'P1', active_agent_session: true, checkout_state: 'checked_out', checked_out_by: 'claude-code', checked_out_at: '2026-04-20T10:47:00Z', checklist_done: 3, checklist_total: 5, parent: 'ENC-FTR-052', updated_at: '2026-04-20T11:08:00Z' },
    { task_id: 'ENC-TSK-A58', project_id: 'enceladus', title: 'Wire up pillar_composite rollup in scoring service', status: 'open', priority: 'P2', checkout_state: null, checklist_done: 0, checklist_total: 4, parent: 'ENC-FTR-052', updated_at: '2026-04-20T09:22:00Z' },
    { task_id: 'DVP-TSK-214', project_id: 'devops', title: 'Rotate Neo4j AuraDB credentials quarterly', status: 'open', priority: 'P3', checkout_state: null, checklist_done: 0, checklist_total: 3, updated_at: '2026-04-19T20:00:00Z' },
    { task_id: 'ENC-TSK-A55', project_id: 'enceladus', title: 'Constitutional radar chart — four pillars view', status: 'closed', priority: 'P2', checkout_state: 'checked_in', checked_in_by: 'claude-code', checked_in_at: '2026-04-19T14:12:00Z', checklist_done: 4, checklist_total: 4, updated_at: '2026-04-19T14:12:00Z' },
  ],
  issues: [
    { issue_id: 'ENC-ISS-041', project_id: 'enceladus', title: 'Tracker API JWT library missing after Lambda deploy', status: 'blocked', priority: 'P0', parent: 'ENC-FTR-052', updated_at: '2026-04-20T09:08:00Z' },
    { issue_id: 'DVP-ISS-018', project_id: 'devops', title: 'Nightly parity audit false-positive on timestamp drift', status: 'open', priority: 'P2', updated_at: '2026-04-19T03:44:00Z' },
  ],
  features: [
    { feature_id: 'ENC-FTR-052', project_id: 'enceladus', title: 'Governed Lesson Primitive', status: 'in-progress', updated_at: '2026-04-20T10:47:00Z' },
    { feature_id: 'ENC-FTR-048', project_id: 'enceladus', title: 'Code-mode MCP meta-tools (5 operations)', status: 'closed', updated_at: '2026-04-12T16:20:00Z' },
  ],
  lessons: [
    { lesson_id: 'ENC-LSN-004', project_id: 'enceladus', title: 'Never build Lambda artifacts on macOS — platform mismatch breaks native deps', status: 'open', category: 'runtime', provenance: 'post-mortem', pillar_composite: 0.82, confidence: 0.94, updated_at: '2026-04-18T12:00:00Z' },
    { lesson_id: 'ENC-LSN-011', project_id: 'enceladus', title: 'DynamoDB GSI propagation is eventually consistent — read-after-write will lie', status: 'open', category: 'data', provenance: 'incident', pillar_composite: 0.78, confidence: 0.88, updated_at: '2026-04-15T09:00:00Z' },
    { lesson_id: 'DVP-LSN-003', project_id: 'devops', title: 'Secrets guardrail must run pre-push, not pre-commit — developers edit staged', status: 'open', category: 'security', provenance: 'near-miss', pillar_composite: 0.85, confidence: 0.96, updated_at: '2026-04-14T22:00:00Z' },
  ],
  changelog: [
    { version: 'v0.20.12', project: 'enceladus', date: '2026-04-20', note: 'Lesson primitive gate: pillar_composite ≥ 0.80 enforced in governance proposals.' },
    { version: 'v0.20.11', project: 'enceladus', date: '2026-04-18', note: 'Added constitutional radar chart — 4 pillars.' },
    { version: 'v2.4.0', project: 'devops', date: '2026-04-16', note: 'SHA-256 parity audit now runs nightly across all 8 DynamoDB tables.' },
    { version: 'v0.20.10', project: 'enceladus', date: '2026-04-12', note: 'Code-mode MCP: 5 meta-tools replace 47 raw mode operations (89% schema reduction).' },
  ],
  docs: [
    { doc_id: 'DOC-0CD901005ECA', project_id: 'enceladus', title: 'PWA 2.0 Architectural Framework', kind: 'architecture', updated_at: '2026-04-15' },
    { doc_id: 'DOC-6EFD5DB32CD8', project_id: 'enceladus', title: 'v4 Service Boundary Migration Plan', kind: 'plan', updated_at: '2026-04-14' },
    { doc_id: 'DOC-8A2C4B9F1E5D', project_id: 'enceladus', title: 'Constitutional Scoring — Pillar Semantics', kind: 'spec', updated_at: '2026-04-11' },
    { doc_id: 'DOC-3F8A9C2D7E4F', project_id: 'enceladus', title: 'Brand Identity & Visual System v1.0', kind: 'brand', updated_at: '2026-04-09' },
  ],
};
