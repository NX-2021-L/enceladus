import { FileText } from 'lucide-react'
import type { Document } from '../types/records'
import { MetaRow, Metric, Prose } from '../components/PrimitiveCard'
import { NeighborsTab, RecordDetailHub } from '../components/RecordDetailHub'

export function DocumentPrimitive({ record }: { record: Document }) {
  const vitals = [
    { label: 'Project', value: record.project_id },
    { label: 'Version', value: `v${record.version ?? '?'}` },
    ...(record.document_subtype ? [{ label: 'Subtype', value: record.document_subtype }] : []),
  ]

  return (
    <RecordDetailHub
      recordId={record.document_id}
      kindLabel="Document"
      title={record.title}
      status={record.status}
      vitals={vitals}
      overview={
        <>
          <Prose projectId={record.project_id}>{record.description}</Prose>
          <MetaRow label="File">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <FileText size={14} strokeWidth={1.5} color="var(--accent)" />
              <span style={{ fontFamily: 'var(--font-mono)' }}>{record.file_name}</span>
            </span>
          </MetaRow>
          <MetaRow label="Version">
            <Metric>v{record.version ?? '?'}</Metric>
          </MetaRow>
          <MetaRow label="Keywords">
            {(record.keywords ?? []).length > 0 ? (record.keywords ?? []).join(', ') : 'None'}
          </MetaRow>
          <MetaRow label="Created by">{record.created_by}</MetaRow>
        </>
      }
      neighbors={
        <NeighborsTab projectId={record.project_id} groups={[{ label: 'Related items', ids: record.related_items }]} />
      }
    />
  )
}
