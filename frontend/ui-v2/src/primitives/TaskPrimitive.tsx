import { ListChecks } from 'lucide-react'
import type { Task } from '../types/records'
import { MetaRow, Metric, PrimitiveCard, Prose } from '../components/PrimitiveCard'

export function TaskPrimitive({ record }: { record: Task }) {
  return (
    <PrimitiveCard
      recordId={record.task_id}
      kindLabel="Task"
      title={record.title}
      status={record.status}
    >
      <Prose>{record.description}</Prose>
      <MetaRow label="Priority">{record.priority}</MetaRow>
      <MetaRow label="Assigned">{record.assigned_to ?? 'Unassigned'}</MetaRow>
      <MetaRow label="Checklist">
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <ListChecks size={14} strokeWidth={1.5} color="var(--accent)" />
          <Metric>
            {record.checklist_done ?? 0}/{record.checklist_total ?? 0}
          </Metric>
        </span>
      </MetaRow>
      <MetaRow label="Related">
        <Metric>
          {(record.related_task_ids?.length ?? 0) +
            (record.related_issue_ids?.length ?? 0) +
            (record.related_feature_ids?.length ?? 0)}
        </Metric>{' '}
        edges
      </MetaRow>
    </PrimitiveCard>
  )
}
