import { Sparkles } from 'lucide-react'
import type { Feature } from '../types/records'
import { ContextNodeBadges } from '../components/ContextNodeBadges'
import { MetaRow, Metric, Prose } from '../components/PrimitiveCard'
import { NeighborsTab, RecordDetailHub, WorklogTab } from '../components/RecordDetailHub'

export function FeaturePrimitive({ record }: { record: Feature }) {
  const vitals = [
    { label: 'Project', value: record.project_id },
    ...(record.transition_type ? [{ label: 'Transition type', value: record.transition_type }] : []),
    ...(record.checked_out_by
      ? [{ label: 'Checkout', value: `${record.checked_out_by} (${record.checkout_state ?? 'checked_out'})` }]
      : []),
  ]

  return (
    <RecordDetailHub
      recordId={record.feature_id}
      kindLabel="Feature"
      title={record.title}
      status={record.status}
      vitals={vitals}
      overview={
        <>
          <Prose>{record.description}</Prose>
          <MetaRow label="Owners">
            {(record.owners ?? []).length > 0 ? (record.owners ?? []).join(', ') : 'Unowned'}
          </MetaRow>
          <MetaRow label="Success metrics">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <Sparkles size={14} strokeWidth={1.5} color="var(--accent)" />
              <Metric>{record.success_metrics?.length ?? 0}</Metric>
            </span>
          </MetaRow>
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
