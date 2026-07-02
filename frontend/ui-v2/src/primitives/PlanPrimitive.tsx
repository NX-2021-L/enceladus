import { Map as MapIcon } from 'lucide-react'
import type { Plan } from '../types/records'
import { MetaRow, Metric, PrimitiveCard, Prose } from '../components/PrimitiveCard'

export function PlanPrimitive({ record }: { record: Plan }) {
  return (
    <PrimitiveCard
      recordId={record.plan_id}
      kindLabel="Plan"
      title={record.title}
      status={record.status}
    >
      <Prose>{record.description}</Prose>
      <MetaRow label="Priority">{record.priority}</MetaRow>
      <MetaRow label="Category">{record.category ?? 'Uncategorized'}</MetaRow>
      <MetaRow label="Objectives">
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <MapIcon size={14} strokeWidth={1.5} color="var(--accent)" />
          <Metric>{record.objectives_set.length}</Metric>
        </span>
      </MetaRow>
      <MetaRow label="Attached docs">
        <Metric>{record.attached_documents.length}</Metric>
      </MetaRow>
    </PrimitiveCard>
  )
}
