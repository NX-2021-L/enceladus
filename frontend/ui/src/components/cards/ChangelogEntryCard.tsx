import { useState } from 'react'
import type { ChangelogEntry } from '../../types/feeds'
import { timeAgo } from '../../lib/formatters'

const CHANGE_TYPE_STYLES: Record<string, string> = {
  major: 'bg-emerald-500/20 text-emerald-400',
  minor: 'bg-blue-500/20 text-blue-400',
  patch: 'bg-slate-600/40 text-slate-400',
}

export function ChangelogEntryCard({ entry }: { entry: ChangelogEntry }) {
  const [expanded, setExpanded] = useState(false)

  const releaseNotesId = entry.related_record_ids.find((id) => id.startsWith('DOC-'))
  const badgeStyle = CHANGE_TYPE_STYLES[entry.change_type] ?? CHANGE_TYPE_STYLES.patch

  return (
    <div className="bg-slate-800 rounded-lg px-4 py-3">
      {/* Header row */}
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-base font-semibold text-slate-100">v{entry.version}</span>
          <span className={`text-xs px-1.5 py-0.5 rounded font-medium uppercase tracking-wide ${badgeStyle}`}>
            {entry.change_type}
          </span>
          {entry.project_id && (
            <span className="text-xs font-mono text-slate-500">{entry.project_id}</span>
          )}
        </div>
        <span className="text-xs text-slate-500 flex-shrink-0">{timeAgo(entry.deployed_at)}</span>
      </div>

      {/* Release summary */}
      {entry.release_summary && (
        <p className="text-sm text-slate-300 mt-1 leading-snug">{entry.release_summary}</p>
      )}

      {/* Changes list (collapsible) */}
      {entry.changes.length > 0 && (
        <div className="mt-2">
          <button
            onClick={() => setExpanded((v) => !v)}
            className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
          >
            {expanded ? '▾' : '▸'} {entry.changes.length} change{entry.changes.length !== 1 ? 's' : ''}
          </button>
          {expanded && (
            <ul className="mt-1.5 space-y-0.5 pl-3 border-l border-slate-700">
              {entry.changes.map((c, i) => (
                <li key={i} className="text-xs text-slate-400 leading-snug">
                  {c}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* Footer: release notes link + related IDs */}
      {(releaseNotesId || entry.related_record_ids.length > 0) && (
        <div className="mt-2 flex items-center gap-2 flex-wrap">
          {releaseNotesId && (
            <a
              href={`/documents/${releaseNotesId}`}
              className="text-xs px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-400 hover:text-indigo-300 transition-colors"
              onClick={(e) => e.stopPropagation()}
            >
              Release Notes →
            </a>
          )}
          {entry.related_record_ids
            .filter((id) => !id.startsWith('DOC-'))
            .slice(0, 3)
            .map((id) => (
              <span key={id} className="text-xs px-1.5 py-0.5 rounded bg-slate-700 text-slate-500 font-mono">
                {id}
              </span>
            ))}
        </div>
      )}
    </div>
  )
}
