import { FileText } from 'lucide-react'
import type { Document } from '../types/records'
import { MarkdownContent } from '../components/MarkdownContent'
import { MetaRow, Metric, Prose } from '../components/PrimitiveCard'
import { NeighborsTab, RecordDetailHub } from '../components/RecordDetailHub'
import { downloadTextFile } from '../utils/downloadTextFile'

/** "8.6 KB" / "116.9 KB" style — matches Docs.dc.html row + metadata format. */
function formatSize(bytes: number | undefined): string | null {
  if (bytes == null || Number.isNaN(bytes)) return null
  if (bytes < 1024) return `${bytes} B`
  return `${(bytes / 1024).toFixed(1)} KB`
}

function formatTimestamp(iso: string | undefined): string | null {
  if (!iso) return null
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  })
}

export function DocumentPrimitive({ record }: { record: Document }) {
  const vitals = [
    { label: 'Project', value: record.project_id },
    { label: 'Version', value: `v${record.version ?? '?'}` },
    ...(record.document_subtype ? [{ label: 'Subtype', value: record.document_subtype }] : []),
  ]

  const sizeLabel = formatSize(record.size_bytes)
  const createdLabel = formatTimestamp(record.created_at)
  const updatedLabel = formatTimestamp(record.updated_at)
  const fileName = record.file_name || `${record.document_id}.md`

  return (
    <RecordDetailHub
      recordId={record.document_id}
      kindLabel="Document"
      title={record.title}
      status={record.status}
      vitals={vitals}
      actions={[
        {
          label: 'Download .md',
          onClick: () => downloadTextFile(fileName, record.content ?? '', 'text/markdown'),
        },
      ]}
      overview={
        <>
          <Prose projectId={record.project_id}>{record.description}</Prose>
          <MetaRow label="File">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <FileText size={14} strokeWidth={1.5} color="var(--accent)" />
              <span style={{ fontFamily: 'var(--font-mono)' }}>{fileName}</span>
            </span>
          </MetaRow>
          <MetaRow label="Type">
            <span style={{ fontFamily: 'var(--font-mono)' }}>{record.content_type || 'text/markdown'}</span>
          </MetaRow>
          {sizeLabel ? (
            <MetaRow label="Size">
              <span style={{ fontFamily: 'var(--font-mono)' }}>{sizeLabel}</span>
            </MetaRow>
          ) : null}
          {record.content_hash ? (
            <MetaRow label="Hash">
              <span style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all', color: 'var(--fg-muted)' }}>
                {record.content_hash}
              </span>
            </MetaRow>
          ) : null}
          <MetaRow label="Version">
            <Metric>v{record.version ?? '?'}</Metric>
          </MetaRow>
          <MetaRow label="Keywords">
            {(record.keywords ?? []).length > 0 ? (record.keywords ?? []).join(', ') : 'None'}
          </MetaRow>
          <MetaRow label="Created by">{record.created_by}</MetaRow>
          {createdLabel ? <MetaRow label="Created">{createdLabel}</MetaRow> : null}
          {updatedLabel ? <MetaRow label="Updated">{updatedLabel}</MetaRow> : null}
          {record.compliance_score != null ? (
            <MetaRow label="Compliance">
              <Metric>{record.compliance_score}</Metric>
              {record.compliance_warnings?.length ? (
                <span style={{ color: 'var(--fg-muted)' }}> · {record.compliance_warnings.length} warning(s)</span>
              ) : null}
            </MetaRow>
          ) : null}
        </>
      }
      content={<MarkdownContent content={record.content} projectId={record.project_id} />}
      neighbors={
        <NeighborsTab projectId={record.project_id} groups={[{ label: 'Related items', ids: record.related_items }]} />
      }
    />
  )
}
