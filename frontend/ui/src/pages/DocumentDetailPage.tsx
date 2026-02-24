import { useParams, Link, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { documentKeys, fetchDocument } from '../api/documents'
import { StatusChip } from '../components/shared/StatusChip'
import { MarkdownRenderer } from '../components/shared/MarkdownRenderer'
import { CodeBlock, detectLanguageFromFilename } from '../components/shared/CodeBlock'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { formatDate } from '../lib/formatters'
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

  const { data: doc, isPending, isError } = useQuery({
    queryKey: documentKeys.detail(normalizedId),
    queryFn: () => fetchDocument(normalizedId),
    enabled: normalizedId.length > 0 && isDocumentId,
  })

  if (normalizedId.length === 0) return <ErrorState message="Document not found" />
  if (!isDocumentId) {
    // Keep /documents/{project} behavior introduced for primary reference docs.
    if (documentSlug) return <Navigate to={`/documents/${encodeURIComponent(normalizedId)}`} replace />
    return <ProjectPrimaryDocumentsPage projectId={normalizedId} />
  }
  if (isPending) return <LoadingState />
  if (isError || !doc) return <ErrorState message="Document not found" />

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
        <span className="text-xs font-mono text-slate-500 block mb-1">{doc.document_id}</span>
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
