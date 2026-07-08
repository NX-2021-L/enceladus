import { ListChecks } from 'lucide-react'
import type { Task } from '../types/records'
import { ContextNodeBadges } from '../components/ContextNodeBadges'
import { MetaRow, Metric, Prose } from '../components/PrimitiveCard'
import { EvidenceTab, NeighborsTab, RecordDetailHub, WorklogTab } from '../components/RecordDetailHub'

export function TaskPrimitive({ record }: { record: Task }) {
  const vitals = [
    { label: 'Priority', value: record.priority },
    { label: 'Project', value: record.project_id },
    ...(record.transition_type ? [{ label: 'Transition type', value: record.transition_type }] : []),
    ...(record.checked_out_by
      ? [{ label: 'Checkout', value: `${record.checked_out_by} (${record.checkout_state ?? 'checked_out'})` }]
      : []),
  ]

  return (
    <RecordDetailHub
      recordId={record.task_id}
      kindLabel="Task"
      title={record.title}
      status={record.status}
      priority={record.priority}
      vitals={vitals}
      overview={
        <>
          <Prose projectId={record.project_id}>{record.description}</Prose>
          <MetaRow label="Assigned">{record.assigned_to ?? 'Unassigned'}</MetaRow>
          <MetaRow label="Checklist">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <ListChecks size={14} strokeWidth={1.5} color="var(--accent)" />
              <Metric>
                {record.checklist_done ?? 0}/{record.checklist_total ?? 0}
              </Metric>
            </span>
          </MetaRow>
          <ContextNodeBadges contextNode={record.context_node} />
        </>
      }
      neighbors={
        <NeighborsTab
          projectId={record.project_id}
          groups={[
            { label: 'Related tasks', ids: record.related_task_ids, type: 'task' },
            { label: 'Related issues', ids: record.related_issue_ids, type: 'issue' },
            { label: 'Related features', ids: record.related_feature_ids, type: 'feature' },
            { label: 'Subtasks', ids: record.subtask_ids, type: 'task' },
          ]}
          typedEdges={record.typed_relationships}
        />
      }
      worklog={<WorklogTab history={record.history} projectId={record.project_id} />}
      evidence={<EvidenceTab criteria={record.acceptance_criteria} projectId={record.project_id} />}
    />
  )
}
