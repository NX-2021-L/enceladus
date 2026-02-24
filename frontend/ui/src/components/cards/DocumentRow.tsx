import { Link } from 'react-router-dom'
import type { Document } from '../../types/feeds'
import { StatusChip } from '../shared/StatusChip'
import { timeAgo } from '../../lib/formatters'
import { buildCanonicalDocumentPathFromDoc } from '../../lib/documentUrls'

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1048576).toFixed(1)} MB`
}

export function DocumentRow({ doc }: { doc: Document }) {
  return (
    <Link
      to={buildCanonicalDocumentPathFromDoc(doc)}
      className="block bg-slate-800 rounded-lg px-4 py-3 hover:bg-slate-750 active:bg-slate-700 transition-colors"
    >
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-xs font-mono text-slate-500 flex-shrink-0">{doc.document_id}</span>
            <span className="text-xs text-slate-600">{formatBytes(doc.size_bytes)}</span>
          </div>
          <h4 className="text-sm font-medium text-slate-200 truncate">{doc.title}</h4>
        </div>
        <span className="text-xs text-slate-500 flex-shrink-0">{timeAgo(doc.updated_at)}</span>
      </div>
      <div className="flex items-center gap-2 mt-1.5">
        <StatusChip status={doc.status} />
        {doc.keywords.length > 0 && (
          <div className="flex gap-1 overflow-hidden">
            {doc.keywords.slice(0, 3).map((kw) => (
              <span
                key={kw}
                className="text-xs px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-400 truncate max-w-[80px]"
              >
                {kw}
              </span>
            ))}
            {doc.keywords.length > 3 && (
              <span className="text-xs text-slate-500">+{doc.keywords.length - 3}</span>
            )}
          </div>
        )}
      </div>
    </Link>
  )
}
