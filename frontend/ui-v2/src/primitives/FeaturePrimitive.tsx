import { Sparkles } from 'lucide-react'
import type { Feature } from '../types/records'
import { MetaRow, Metric, PrimitiveCard, Prose } from '../components/PrimitiveCard'

export function FeaturePrimitive({ record }: { record: Feature }) {
  return (
    <PrimitiveCard
      recordId={record.feature_id}
      kindLabel="Feature"
      title={record.title}
      status={record.status}
    >
      <Prose>{record.description}</Prose>
      <MetaRow label="Owners">
        {record.owners.length > 0 ? record.owners.join(', ') : 'Unowned'}
      </MetaRow>
      <MetaRow label="Success metrics">
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <Sparkles size={14} strokeWidth={1.5} color="var(--accent)" />
          <Metric>{record.success_metrics.length}</Metric>
        </span>
      </MetaRow>
      <MetaRow label="Related tasks">
        <Metric>{record.related_task_ids.length}</Metric>
      </MetaRow>
    </PrimitiveCard>
  )
}
