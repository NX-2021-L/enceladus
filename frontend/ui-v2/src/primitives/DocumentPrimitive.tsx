import { lazy, Suspense } from 'react'
import { FileText } from 'lucide-react'
import type { Document } from '../types/records'
import { DocumentSectionsView } from '../components/DocumentSectionsView'
import { MetaRow, Metric, Prose } from '../components/PrimitiveCard'
import { NeighborsTab, RecordDetailHub } from '../components/RecordDetailHub'
import { downloadTextFile } from '../utils/downloadTextFile'

/** ENC-TSK-P81 — code-split: the History tab (list + rewind + diff) only
 *  ships to the client once the tab is opened, as its own chunk separate
 *  from this already-large `document` primitive chunk. */
const DocumentHistoryPanel = lazy(() =>
  import('../components/DocumentHistoryPanel').then((m) => ({ default: m.DocumentHistoryPanel })),
)

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
  // ENC-TSK-P92 (AC-1): a URL hash on load means the user followed a deep
  // link to a section -- open straight to the Content tab so that section
  // (rendered inside DocumentSectionsView) is in the DOM to scroll to,
  // instead of landing on Overview with the anchor unreachable.
  const hasSectionDeepLink = typeof window !== 'undefined' && window.location.hash.length > 1

  return (
    <RecordDetailHub
      recordId={record.document_id}
      kindLabel="Document"
      title={record.title}
      status={record.status}
      initialTabId={hasSectionDeepLink ? 'content' : undefined}
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
      content={<DocumentSectionsView record={record} />}
      history={
        <Suspense fallback={<p className="ev2-history__status">Loading history&hellip;</p>}>
          <DocumentHistoryPanel documentId={record.document_id} projectId={record.project_id} />
        </Suspense>
      }
      neighbors={
        <NeighborsTab projectId={record.project_id} groups={[{ label: 'Related items', ids: record.related_items }]} />
      }
    />
  )
}
