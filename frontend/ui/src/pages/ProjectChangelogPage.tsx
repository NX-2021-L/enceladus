import { useParams, Link } from 'react-router-dom'
import { useChangelogHistory, useProjectVersion } from '../hooks/useChangelog'
import { useProjects } from '../hooks/useProjects'
import { useInfiniteList } from '../hooks/useInfiniteList'
import { ChangelogEntryCard } from '../components/cards/ChangelogEntryCard'
import { ScrollSentinel } from '../components/shared/ScrollSentinel'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { EmptyState } from '../components/shared/EmptyState'
import { timeAgo } from '../lib/formatters'

const CHANGE_TYPE_BADGE: Record<string, string> = {
  major: 'bg-emerald-500/20 text-emerald-400',
  minor: 'bg-blue-500/20 text-blue-400',
  patch: 'bg-slate-600/40 text-slate-400',
}

export function ProjectChangelogPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const { projects, isPending: loadingProjects } = useProjects()
  const { data: currentVersion, isPending: loadingVersion } = useProjectVersion(projectId ?? '')
  const { entries, isPending: loadingHistory, isError } = useChangelogHistory({ projectId })
  const { visible, sentinelRef, hasMore } = useInfiniteList(entries)

  if (loadingProjects) return <LoadingState />
  const project = projects.find((p) => p.project_id === projectId)
  if (!project) return <ErrorState message="Project not found" />

  const latestEntry = entries[0]
  const latestChangeType = latestEntry?.change_type

  return (
    <div>
      {/* Sticky header */}
      <div className="sticky top-0 z-10 bg-slate-900">
        <div className="px-4 pt-4 pb-3 space-y-2">
          <Link to={`/projects/${projectId}`} className="text-xs text-blue-400 inline-block">
            &larr; {project.name}
          </Link>

          {/* Version banner */}
          <div className="bg-slate-800 rounded-lg px-4 py-3">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                {loadingVersion ? (
                  <span className="text-lg font-bold text-slate-400">—</span>
                ) : (
                  <span className="text-lg font-bold text-slate-100">
                    v{currentVersion?.version ?? latestEntry?.version ?? '—'}
                  </span>
                )}
                {latestChangeType && (
                  <span
                    className={`text-xs px-1.5 py-0.5 rounded font-medium uppercase tracking-wide ${CHANGE_TYPE_BADGE[latestChangeType] ?? CHANGE_TYPE_BADGE.patch}`}
                  >
                    {latestChangeType}
                  </span>
                )}
              </div>
              {(currentVersion?.deployed_at ?? latestEntry?.deployed_at) && (
                <span className="text-xs text-slate-500">
                  {timeAgo(currentVersion?.deployed_at ?? latestEntry!.deployed_at)}
                </span>
              )}
            </div>
            {latestEntry?.release_summary && (
              <p className="text-sm text-slate-300 mt-1.5 leading-snug">{latestEntry.release_summary}</p>
            )}
          </div>

          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">
              Release History
            </span>
            <span className="text-xs text-slate-500">{entries.length} releases</span>
          </div>
        </div>
        <div className="h-px bg-slate-700/50" />
      </div>

      {/* Release list */}
      <div className="px-4 py-3 space-y-2">
        {loadingHistory ? (
          <LoadingState />
        ) : isError ? (
          <ErrorState />
        ) : visible.length ? (
          <>
            {visible.map((entry, i) => (
              <ChangelogEntryCard key={`${entry.spec_id}-${i}`} entry={entry} />
            ))}
            <ScrollSentinel sentinelRef={sentinelRef} hasMore={hasMore} />
          </>
        ) : (
          <EmptyState message="No deployment history yet" />
        )}
      </div>
    </div>
  )
}
