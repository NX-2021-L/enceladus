import { AlertTriangle } from 'lucide-react'
import type { Issue } from '../types/records'
import { MetaRow, PrimitiveCard, Prose } from '../components/PrimitiveCard'

export function IssuePrimitive({ record }: { record: Issue }) {
  return (
    <PrimitiveCard
      recordId={record.issue_id}
      kindLabel="Issue"
      title={record.title}
      status={record.status}
    >
      <Prose>{record.description}</Prose>
      <MetaRow label="Priority">{record.priority}</MetaRow>
      <MetaRow label="Severity">
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <AlertTriangle
            size={14}
            strokeWidth={1.5}
            color={record.severity === 'critical' ? 'var(--danger)' : 'var(--fg-muted)'}
          />
          {record.severity}
        </span>
      </MetaRow>
      {record.hypothesis ? (
        <MetaRow label="Hypothesis">{record.hypothesis}</MetaRow>
      ) : null}
    </PrimitiveCard>
  )
}
