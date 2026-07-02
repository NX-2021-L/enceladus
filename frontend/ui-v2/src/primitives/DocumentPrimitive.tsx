import { FileText } from 'lucide-react'
import type { Document } from '../types/records'
import { MetaRow, Metric, PrimitiveCard, Prose } from '../components/PrimitiveCard'

export function DocumentPrimitive({ record }: { record: Document }) {
  return (
    <PrimitiveCard
      recordId={record.document_id}
      kindLabel="Document"
      title={record.title}
      status={record.status}
    >
      <Prose>{record.description}</Prose>
      <MetaRow label="File">
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <FileText size={14} strokeWidth={1.5} color="var(--accent)" />
          <span style={{ fontFamily: 'var(--font-mono)' }}>{record.file_name}</span>
        </span>
      </MetaRow>
      {record.document_subtype ? (
        <MetaRow label="Subtype">{record.document_subtype}</MetaRow>
      ) : null}
      <MetaRow label="Version">
        <Metric>v{record.version ?? '?'}</Metric>
      </MetaRow>
      <MetaRow label="Keywords">
        {(record.keywords ?? []).length > 0 ? (record.keywords ?? []).join(', ') : 'None'}
      </MetaRow>
      <MetaRow label="Created by">{record.created_by}</MetaRow>
    </PrimitiveCard>
  )
}
