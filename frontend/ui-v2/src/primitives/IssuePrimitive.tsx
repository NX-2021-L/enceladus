import { AlertTriangle } from 'lucide-react'
import type { Issue } from '../types/records'
import { ContextNodeBadges } from '../components/ContextNodeBadges'
import { MetaRow, Prose } from '../components/PrimitiveCard'
import { NeighborsTab, RecordDetailHub, WorklogTab } from '../components/RecordDetailHub'

export function IssuePrimitive({ record }: { record: Issue }) {
  const vitals = [
    { label: 'Priority', value: record.priority },
    { label: 'Severity', value: record.severity },
    { label: 'Project', value: record.project_id },
    ...(record.transition_type ? [{ label: 'Transition type', value: record.transition_type }] : []),
    ...(record.checked_out_by
      ? [{ label: 'Checkout', value: `${record.checked_out_by} (${record.checkout_state ?? 'checked_out'})` }]
      : []),
  ]

  return (
    <RecordDetailHub
      recordId={record.issue_id}
      kindLabel="Issue"
      title={record.title}
      status={record.status}
      priority={record.priority}
      vitals={vitals}
      overview={
        <>
          <Prose>{record.description}</Prose>
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
          {record.hypothesis ? <MetaRow label="Hypothesis">{record.hypothesis}</MetaRow> : null}
          <ContextNodeBadges contextNode={record.context_node} />
        </>
      }
      neighbors={
        <NeighborsTab
          projectId={record.project_id}
          groups={[{ label: 'Related tasks', ids: record.related_task_ids, type: 'task' }]}
          typedEdges={record.typed_relationships}
        />
      }
      worklog={<WorklogTab history={record.history} />}
    />
  )
}
