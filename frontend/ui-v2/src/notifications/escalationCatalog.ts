/** DVP-TSK-A24 (E4-R28/R31): one catalog group, one type per gate kind. */
import type { NotifyCatalog, NotifyType } from '@io-kit/notify'

const KINDS: { id: string; label: string; desc: string }[] = [
  { id: 'acceptance', label: 'Acceptance', desc: 'A task awaits acceptance evidence sign-off' },
  { id: 'escalation', label: 'Escalation', desc: 'A governed mutation needs your approval' },
  { id: 'tool_call', label: 'Tool call', desc: 'A gated tool call needs approval' },
  { id: 'reconciliation', label: 'Reconciliation', desc: 'A record mismatch needs a ruling' },
  { id: 'limit', label: 'Limit', desc: 'A limit or budget needs raising' },
  { id: 'security', label: 'Security', desc: 'A security-sensitive action needs approval' },
  { id: 'stale_lock', label: 'Stale lock', desc: 'A stale lock needs release' },
  { id: 'drift', label: 'Drift', desc: 'A record drifted from what was approved' },
  { id: 'notice', label: 'Notice', desc: 'An informational notice to acknowledge' },
]

const types: Record<string, NotifyType> = {}
for (const k of KINDS) {
  types[k.id] = {
    group: 'escalations',
    label: k.label,
    desc: k.desc,
    title: 'Escalation · {risk}',
    generic: 'A decision is waiting in Enceladus',
    detailed: '{project_id}: {kind} — {summary}',
  }
}

export const escalationCatalog: NotifyCatalog = {
  groups: [{ id: 'escalations', label: 'Escalations' }],
  types,
  levels: { generic: 'Generic', detailed: 'Detailed', hint: 'Detailed shows the project, kind and summary on the lock screen.' },
  extraFields: [
    {
      id: 'min_risk', label: 'Minimum risk', kind: 'select',
      options: ['low', 'medium', 'high', 'critical'].map((v) => ({ value: v, label: v })),
    },
  ],
  sample: { risk: 'high', project_id: 'devops', kind: 'escalation', summary: 'Rotate signing key' },
}
