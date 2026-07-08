import { Sparkles } from 'lucide-react'
import type { Feature } from '../types/records'
import { ContextNodeBadges } from '../components/ContextNodeBadges'
import { ActiveSessionChip, CategoryChip, CheckoutChip, ComponentChips } from '../components/ChipRow'
import { MetaRow, Metric, Prose, SectionHeading } from '../components/PrimitiveCard'
import { EvidenceTab, NeighborsTab, RecordDetailHub, WorklogTab } from '../components/RecordDetailHub'
import { isCheckedOut } from '../utils/transitionArcs'

export function FeaturePrimitive({ record }: { record: Feature }) {
  const checkedOut = isCheckedOut(record)
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
      chips={
        <>
          <CategoryChip category={record.category} />
          <ComponentChips components={record.components} />
          <ActiveSessionChip active={record.active_agent_session} sessionId={record.active_agent_session_id} />
          <CheckoutChip
            checkedOut={checkedOut}
            checkedOutBy={record.checked_out_by}
            checkedInBy={record.checked_in_by}
          />
        </>
      }
      mutation={{
        projectId: record.project_id,
        recordType: 'feature',
        recordId: record.feature_id,
        status: record.status,
        checkedOut,
        syncVersion: record.sync_version,
      }}
      actions={record.github_issue_url ? [{ label: 'GitHub ↗', href: record.github_issue_url }] : []}
      overview={
        <>
          {record.user_story ? (
            <>
              <SectionHeading>User Story</SectionHeading>
              <Prose projectId={record.project_id}>{record.user_story}</Prose>
            </>
          ) : null}
          <SectionHeading>Description</SectionHeading>
          <Prose projectId={record.project_id}>{record.description}</Prose>
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
      worklog={<WorklogTab history={record.history} projectId={record.project_id} />}
      evidence={<EvidenceTab criteria={record.acceptance_criteria} projectId={record.project_id} />}
    />
  )
}
