import { Link } from 'react-router-dom'
import { StatusChip } from './StatusChip'

export interface RecordInfo {
  title: string
  status: string
}

interface RelatedGroup {
  label: string
  ids: string[]
  routePrefix: string
}

interface RelatedItemsProps {
  groups: RelatedGroup[]
  recordMap?: Record<string, RecordInfo>
}

export function RelatedItems({ groups, recordMap }: RelatedItemsProps) {
  const nonEmpty = groups.filter((g) => g.ids.length > 0)
  if (!nonEmpty.length) return null

  return (
    <div className="space-y-3">
      {nonEmpty.map((group) => (
        <div key={group.label}>
          <h4 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            {group.label} ({group.ids.length})
          </h4>
          <div className="space-y-1.5">
            {group.ids.map((id) => {
              const info = recordMap?.[id]
              return (
                <Link
                  key={id}
                  to={`${group.routePrefix}/${id}`}
                  className="flex items-start gap-2 rounded-md bg-slate-700/50 p-2 hover:bg-slate-700 transition-colors"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="font-mono text-xs text-blue-400 flex-shrink-0">{id}</span>
                      {info && <StatusChip status={info.status} />}
                    </div>
                    {info && (
                      <p className="text-sm text-slate-300 truncate">{info.title}</p>
                    )}
                  </div>
                </Link>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )
}
