import { useEffect, useState } from 'react'
import { useParams, Link, Navigate } from 'react-router-dom'
import { useRecordFallback } from '../hooks/useRecordFallback'
import { useDocumentOutline } from '../hooks/useDocumentOutline'
import { StatusChip } from '../components/shared/StatusChip'
import { MarkdownRenderer } from '../components/shared/MarkdownRenderer'
import { CodeBlock, detectLanguageFromFilename } from '../components/shared/CodeBlock'
import { RecordFallbackLoading } from '../components/shared/RecordFallbackLoading'
import { RecordNotFound } from '../components/shared/RecordNotFound'
import { RecordFallbackError } from '../components/shared/RecordFallbackError'
import { ErrorState } from '../components/shared/ErrorState'
import { CopyButton } from '../components/shared/CopyButton'
import { DownloadMarkdownButton } from '../components/shared/DownloadMarkdownButton'
import { DocumentOutlineTree } from '../components/documents/DocumentOutlineTree'
import { DocumentSection } from '../components/documents/DocumentSection'
import { SectionEditor } from '../components/documents/SectionEditor'
import { formatDate, timeAgo } from '../lib/formatters'
import { HANDOFF_STATUS_COLORS, HANDOFF_STATUS_LABELS } from '../lib/constants'
import { ProjectPrimaryDocumentsPage } from './ProjectPrimaryDocumentsPage'
import {
  buildCanonicalDocumentPath,
  decodeSlug,
  documentSlugFromFileName,
  isDocId,
} from '../lib/documentUrls'

/** File extensions that should be rendered as markdown */
const MARKDOWN_EXTS = new Set(['md', 'markdown', 'mdx'])

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1048576).toFixed(1)} MB`
}

export function DocumentDetailPage() {
  const { documentId, documentSlug } = useParams<{
    documentId: string
    documentSlug?: string
  }>()
  const normalizedId = (documentId ?? '').trim()
  const isDocumentId = isDocId(normalizedId)

  // ENC-FTR-073: Documents have never been in the feed payload; the direct
  // GET /api/v1/documents/{id} path always runs. We use useRecordFallback
  // here for contract symmetry with the other five detail pages — the hook
  // dispatches to fetchDocument and renders the shared Loading/NotFound/
  // Error primitives on failure. The `cached` slot is intentionally
  // undefined because there is no feed cache layer for documents.
  const {
    data: doc,
    isLoading: fallbackLoading,
    isError: fallbackIsError,
    isNotFound,
    refetch,
  } = useRecordFallback({
    recordType: 'document',
    recordId: isDocumentId ? normalizedId : undefined,
    cached: undefined,
    feedPending: false,
    feedError: false,
  })

  // ENC-TSK-P80 (AC-1/AC-4): loads documents.manifest (outline + content_hash)
  // independently of the body above, and wires the K29 live-update channel.
  // Hooks must run unconditionally before the early returns below, same
  // constraint as useRecordFallback — `doc` may still be undefined here.
  const outline = useDocumentOutline(isDocumentId ? normalizedId : undefined, doc?.content, {
    onLiveMutation: refetch,
  })
  const [editingKey, setEditingKey] = useState<string | null>(null)

  // Deep-link scroll: sections render asynchronously (after manifest+body
  // both resolve), so the browser's native "scroll to #hash on load" can
  // fire before the target element exists. Retry once sections are present.
  useEffect(() => {
    if (outline.sections.length === 0) return
    const hash = window.location.hash?.slice(1)
    if (!hash) return
    const el = document.getElementById(hash)
    if (el) el.scrollIntoView({ block: 'start' })
  }, [outline.sections.length])

  if (normalizedId.length === 0) return <ErrorState message="Document not found" />
  if (!isDocumentId) {
    // Keep /documents/{project} behavior introduced for primary reference docs.
    if (documentSlug) return <Navigate to={`/documents/${encodeURIComponent(normalizedId)}`} replace />
    return <ProjectPrimaryDocumentsPage projectId={normalizedId} />
  }
  if (fallbackLoading) return <RecordFallbackLoading />
  if (isNotFound) return <RecordNotFound recordType="document" recordId={normalizedId} />
  if (fallbackIsError || !doc) return <RecordFallbackError onRetry={refetch} />

  const expectedSlug = documentSlugFromFileName(doc.file_name, doc.document_id)
  const currentSlug = decodeSlug(documentSlug)
  if (!currentSlug || currentSlug !== expectedSlug) {
    return <Navigate to={buildCanonicalDocumentPath(doc.document_id, doc.file_name)} replace />
  }

  const keywords = doc.keywords ?? []
  const relatedItems = doc.related_items ?? []

  return (
    <div className="p-4 space-y-4 pb-24 break-words">
      {/* Back link */}
      <Link to="/documents" className="text-xs text-blue-400 inline-block">
        &larr; Documents
      </Link>

      {/* Header */}
      <div>
        <Link
          to={`/projects/${doc.project_id}`}
          className="text-xs text-blue-400 hover:text-blue-300 block mb-1"
        >
          {doc.project_id}
        </Link>
        <span className="text-xs font-mono text-slate-500 mb-1 inline-flex items-center gap-1">
          {doc.document_id}
          <CopyButton text={doc.document_id} />
          <DownloadMarkdownButton document={doc} />
        </span>
        <h1 className="text-lg font-semibold text-slate-100 mb-2">{doc.title}</h1>
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <StatusChip status={doc.status} />
          <span className="text-xs text-slate-500">{formatBytes(doc.size_bytes)}</span>
          <span className="text-xs text-slate-500">v{doc.version}</span>
        </div>
        <div className="flex gap-4 text-xs text-slate-500">
          <span>Created {formatDate(doc.created_at)}</span>
          <span>Updated {formatDate(doc.updated_at)}</span>
        </div>
      </div>

      {/* Handoff Metadata (ENC-FTR-061) */}
      {doc.document_subtype === 'handoff' && (
        <div className="bg-slate-800 rounded-lg p-4 space-y-3">
          <div className="flex items-center gap-2">
            <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider">
              Handoff
            </h3>
            {doc.handoff_status && (
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${HANDOFF_STATUS_COLORS[doc.handoff_status] ?? 'bg-slate-500/20 text-slate-400'}`}>
                {HANDOFF_STATUS_LABELS[doc.handoff_status] ?? doc.handoff_status}
              </span>
            )}
          </div>

          {doc.source_record_id && (
            <div>
              <dt className="text-xs text-slate-500 mb-0.5">Source Record</dt>
              <dd>
                <Link
                  to={doc.source_record_id.includes('-TSK-') ? `/tasks/${doc.source_record_id}`
                    : doc.source_record_id.includes('-ISS-') ? `/issues/${doc.source_record_id}`
                    : doc.source_record_id.includes('-FTR-') ? `/features/${doc.source_record_id}`
                    : `/tasks/${doc.source_record_id}`}
                  className="text-sm text-blue-400 hover:text-blue-300 font-mono"
                >
                  {doc.source_record_id}
                </Link>
              </dd>
            </div>
          )}

          {doc.prerequisite_state && (
            <div>
              <dt className="text-xs text-slate-500 mb-0.5">Prerequisites</dt>
              <dd className="text-sm text-slate-300">{doc.prerequisite_state}</dd>
            </div>
          )}

          {doc.verification_criteria && (
            <div>
              <dt className="text-xs text-slate-500 mb-0.5">Verification Criteria</dt>
              <dd className="text-sm text-slate-300">{doc.verification_criteria}</dd>
            </div>
          )}

          {doc.action_checklist && doc.action_checklist.length > 0 && (
            <div>
              <dt className="text-xs text-slate-500 mb-1">Action Checklist</dt>
              <dd className="space-y-1">
                {doc.action_checklist.map((item, i) => (
                  <div key={i} className="flex items-start gap-2 text-sm text-slate-300">
                    <span className="text-slate-500 flex-shrink-0">{i + 1}.</span>
                    <span>{item}</span>
                  </div>
                ))}
              </dd>
            </div>
          )}

          <div className="flex gap-4 text-xs text-slate-500 pt-1 border-t border-slate-700">
            {doc.claimed_by && <span>Claimed by: {doc.claimed_by}</span>}
            {doc.claimed_at && <span>Claimed: {timeAgo(doc.claimed_at)}</span>}
            {doc.expires_at && <span>Expires: {formatDate(doc.expires_at)}</span>}
          </div>
        </div>
      )}

      {/* Description */}
      {doc.description && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Description
          </h3>
          <p className="text-sm text-slate-300 leading-relaxed">{doc.description}</p>
        </div>
      )}

      {/* Keywords */}
      {keywords.length > 0 && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Keywords
          </h3>
          <div className="flex flex-wrap gap-2">
            {keywords.map((kw) => (
              <span
                key={kw}
                className="text-xs px-2 py-1 rounded-md bg-indigo-500/20 text-indigo-400"
              >
                {kw}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Related Items */}
      {relatedItems.length > 0 && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Related Items
          </h3>
          <div className="flex flex-wrap gap-2">
            {relatedItems.map((id) => {
              const route = id.startsWith('DOC-')
                ? `/documents/${id}`
                : id.includes('-TSK-')
                  ? `/tasks/${id}`
                  : id.includes('-ISS-')
                    ? `/issues/${id}`
                    : id.includes('-FTR-')
                      ? `/features/${id}`
                      : null
              return route ? (
                <Link
                  key={id}
                  to={route}
                  className="inline-flex items-center px-2.5 py-1 rounded-md bg-slate-800 text-blue-400 hover:bg-slate-700 hover:text-blue-300 transition-colors font-mono text-xs border border-slate-700"
                >
                  {id}
                </Link>
              ) : (
                <span
                  key={id}
                  className="inline-flex items-center px-2.5 py-1 rounded-md bg-slate-800 text-slate-400 font-mono text-xs border border-slate-700"
                >
                  {id}
                </span>
              )
            })}
          </div>
        </div>
      )}

      {/* Metadata */}
      <div className="bg-slate-800 rounded-lg p-4">
        <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
          Metadata
        </h3>
        <dl className="grid grid-cols-2 gap-2 text-xs">
          <dt className="text-slate-500">File</dt>
          <dd className="text-slate-300 font-mono">{doc.file_name}</dd>
          <dt className="text-slate-500">Type</dt>
          <dd className="text-slate-300">{doc.content_type}</dd>
          <dt className="text-slate-500">Hash</dt>
          <dd className="text-slate-300 font-mono truncate">{doc.content_hash}</dd>
          <dt className="text-slate-500">Created by</dt>
          <dd className="text-slate-300">{doc.created_by}</dd>
        </dl>
      </div>

      {/* Content */}
      {doc.content && (() => {
        const ext = doc.file_name?.split('.').pop()?.toLowerCase() ?? 'md'
        const isMarkdown = MARKDOWN_EXTS.has(ext)
        const detectedLang = !isMarkdown ? detectLanguageFromFilename(doc.file_name ?? '') : undefined

        // ENC-TSK-P80 (AC-1): once the manifest has produced a non-empty
        // outline for a markdown document, render the navigable outline +
        // per-section editing UI instead of the single content blob. Non-
        // markdown documents, and markdown documents with no headings (or
        // whose manifest hasn't loaded / errored), keep the original
        // whole-body rendering unchanged.
        if (isMarkdown && outline.sections.length > 0) {
          const editingSection = outline.sections.find((s) => s.key === editingKey) ?? null
          return (
            <>
              <DocumentOutlineTree sections={outline.sections} changedKeys={outline.changedKeys} />
              <div className="space-y-4">
                {outline.sections.map((section) => (
                  <DocumentSection
                    key={section.key}
                    section={section}
                    changed={outline.changedKeys.has(section.key)}
                    onEdit={() => setEditingKey(section.key)}
                    onAcknowledgeChange={() => outline.clearChanged(section.key)}
                  />
                ))}
              </div>
              {editingSection && outline.manifest && (
                <SectionEditor
                  documentId={doc.document_id}
                  projectId={doc.project_id}
                  section={editingSection}
                  ifMatch={outline.manifest.content_hash}
                  liveChanged={outline.changedKeys.has(editingSection.key)}
                  onClose={() => setEditingKey(null)}
                  onSaved={() => {
                    setEditingKey(null)
                    outline.refetchManifest()
                    refetch()
                  }}
                />
              )}
            </>
          )
        }

        return (
          <div className="bg-slate-800 rounded-lg p-4">
            <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
              Content
            </h3>
            {isMarkdown ? (
              <MarkdownRenderer content={doc.content} />
            ) : (
              <CodeBlock code={doc.content} language={detectedLang} wrapLines />
            )}
          </div>
        )
      })()}
    </div>
  )
}
