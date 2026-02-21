import type { HistoryEntry } from '../../types/feeds'
import { formatDate } from '../../lib/formatters'
import { StatusChip } from './StatusChip'
import { LinkedText } from './LinkedText'

export function HistoryFeed({ entries }: { entries: HistoryEntry[] }) {
  if (!entries.length) {
    return <p className="text-sm text-slate-500">No history entries.</p>
  }

  const sorted = [...entries].sort((a, b) => {
    if (!a.timestamp) return 1
    if (!b.timestamp) return -1
    return b.timestamp.localeCompare(a.timestamp)
  })

  return (
    <div className="space-y-0">
      {sorted.map((entry, i) => (
        <div key={i} className="relative border-l-2 border-slate-700 pl-4 pb-4 last:pb-0">
          <div className="absolute -left-[5px] top-1.5 w-2 h-2 rounded-full bg-slate-600" />
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs text-slate-400">{formatDate(entry.timestamp)}</span>
            {entry.status && <StatusChip status={entry.status} />}
          </div>
          {entry.description && (
            <LinkedText
              text={entry.description}
              className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap"
            />
          )}
        </div>
      ))}
    </div>
  )
}
