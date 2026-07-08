import { Map as MapIcon } from 'lucide-react'
import type { Plan } from '../types/records'
import { ContextNodeBadges } from '../components/ContextNodeBadges'
import { ActiveSessionChip, CategoryChip, CheckoutChip, ComponentChips, PriorityChip } from '../components/ChipRow'
import { PlanGraphExplorer } from '../components/PlanGraphExplorer'
import { MetaRow, Metric, Prose, SectionHeading } from '../components/PrimitiveCard'
import { NeighborsTab, RecordDetailHub, WorklogTab } from '../components/RecordDetailHub'
import { isCheckedOut } from '../utils/transitionArcs'

export function PlanPrimitive({ record }: { record: Plan }) {
  const checkedOut = isCheckedOut(record)
  const vitals = [
    { label: 'Priority', value: record.priority },
    { label: 'Project', value: record.project_id },
    { label: 'Category', value: record.category ?? 'Uncategorized' },
    ...(record.transition_type ? [{ label: 'Transition type', value: record.transition_type }] : []),
    ...(record.checked_out_by
      ? [{ label: 'Checkout', value: `${record.checked_out_by} (${record.checkout_state ?? 'checked_out'})` }]
      : []),
  ]

  return (
    <RecordDetailHub
      recordId={record.plan_id}
      kindLabel="Plan"
      title={record.title}
      status={record.status}
      priority={record.priority}
      vitals={vitals}
      chips={
        <>
          <PriorityChip priority={record.priority} />
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
        recordType: 'plan',
        recordId: record.plan_id,
        status: record.status,
        checkedOut,
        syncVersion: record.sync_version,
      }}
      actions={record.github_issue_url ? [{ label: 'GitHub ↗', href: record.github_issue_url }] : []}
      overview={
        <>
          <SectionHeading>Description</SectionHeading>
          <Prose projectId={record.project_id}>{record.description}</Prose>
          <MetaRow label="Objectives">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <MapIcon size={14} strokeWidth={1.5} color="var(--accent)" />
              <Metric>{record.objectives_set?.length ?? 0}</Metric>
            </span>
          </MetaRow>
          <MetaRow label="Attached docs">
            <Metric>{record.attached_documents?.length ?? 0}</Metric>
          </MetaRow>
          <PlanGraphExplorer
            projectId={record.project_id}
            planId={record.plan_id}
            objectiveIds={record.objectives_set ?? []}
          />
          <ContextNodeBadges contextNode={record.context_node} />
        </>
      }
      neighbors={
        <NeighborsTab
          projectId={record.project_id}
          groups={[
            { label: 'Objectives', ids: record.objectives_set, type: 'task' },
            { label: 'Attached documents', ids: record.attached_documents, type: 'document' },
            { label: 'Related tasks', ids: record.related_task_ids, type: 'task' },
          ]}
          typedEdges={record.typed_relationships}
        />
      }
      worklog={<WorklogTab history={record.history} projectId={record.project_id} />}
    />
  )
}
