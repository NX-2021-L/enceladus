import { useState, useMemo, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { useProjects } from '../hooks/useProjects'
import { useTasks } from '../hooks/useTasks'
import { useIssues } from '../hooks/useIssues'
import { useFeatures } from '../hooks/useFeatures'
import { FreshnessBadge } from '../components/shared/FreshnessBadge'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { timeAgo } from '../lib/formatters'
import type { ProjectSummary, Task, Issue, Feature } from '../types/feeds'

/** A recent activity item with unified shape */
interface ActivityItem {
  id: string
  title: string
  updated_at: string
  type: 'task' | 'issue' | 'feature'
  href: string
}

/** Compute the activity label from the tiered heuristic */
function activityLabel(items: ActivityItem[]): string {
  if (items.length === 0) return 'No recent activity'
  const newest = new Date(items[0]!.updated_at)
  const now = Date.now()
  const diffMs = now - newest.getTime()
  const mins = diffMs / 60_000
  const hours = mins / 60
  const days = hours / 24
  if (mins < 15) return `${items.length} change${items.length !== 1 ? 's' : ''} recently`
  if (hours < 2) return `${items.length} change${items.length !== 1 ? 's' : ''} recently`
  if (days < 1) return `${items.length} change${items.length !== 1 ? 's' : ''} today`
  if (days < 2) return `${items.length} change${items.length !== 1 ? 's' : ''} yesterday`
  if (days < 7) return `${items.length} change${items.length !== 1 ? 's' : ''} this week`
  return 'recent changes'
}

/** Select up to 5 items using tiered heuristic: 15min → 2h → 24h → all-time */
function selectActivityItems(allItems: ActivityItem[]): ActivityItem[] {
  if (allItems.length === 0) return []
  const sorted = [...allItems].sort((a, b) => b.updated_at.localeCompare(a.updated_at))
  const now = Date.now()

  // Tier 1: last 15 minutes
  const t15 = sorted.filter((i) => now - new Date(i.updated_at).getTime() < 15 * 60_000)
  if (t15.length > 0) return t15.slice(0, 5)

  // Tier 2: last 2 hours
  const t2h = sorted.filter((i) => now - new Date(i.updated_at).getTime() < 2 * 3600_000)
  if (t2h.length > 0) return t2h.slice(0, 5)

  // Tier 3: last 24 hours
  const t24 = sorted.filter((i) => now - new Date(i.updated_at).getTime() < 24 * 3600_000)
  if (t24.length > 0) return t24.slice(0, 5)

  // Tier 4: most recent 5
  return sorted.slice(0, 5)
}

function recordHref(type: string, id: string): string {
  if (type === 'task') return `/tasks/${id}`
  if (type === 'issue') return `/issues/${id}`
  return `/features/${id}`
}

/** Build all activity items for a given project */
function projectActivityItems(
  projectId: string,
  tasks: Task[],
  issues: Issue[],
  features: Feature[],
): ActivityItem[] {
  const items: ActivityItem[] = []
  for (const t of tasks) {
    if (t.project_id === projectId && t.updated_at) {
      items.push({ id: t.task_id, title: t.title, updated_at: t.updated_at, type: 'task', href: recordHref('task', t.task_id) })
    }
  }
  for (const i of issues) {
    if (i.project_id === projectId && i.updated_at) {
      items.push({ id: i.issue_id, title: i.title, updated_at: i.updated_at, type: 'issue', href: recordHref('issue', i.issue_id) })
    }
  }
  for (const f of features) {
    if (f.project_id === projectId && f.updated_at) {
      items.push({ id: f.feature_id, title: f.title, updated_at: f.updated_at, type: 'feature', href: recordHref('feature', f.feature_id) })
    }
  }
  return items
}

const TYPE_COLORS: Record<string, string> = {
  task: 'text-blue-400',
  issue: 'text-amber-400',
  feature: 'text-emerald-400',
}

function ChevronDown({ open }: { open: boolean }) {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  )
}

function ProjectActivityCard({
  project,
  activity,
}: {
  project: ProjectSummary
  activity: ActivityItem[]
}) {
  const [expanded, setExpanded] = useState(false)
  const label = activityLabel(activity)
  const hasActivity = activity.length > 0

  const toggleExpand = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setExpanded((prev) => !prev)
  }, [])

  return (
    <div className="bg-slate-800 rounded-lg overflow-hidden">
      <Link
        to={`/projects/${project.project_id}`}
        className="block px-4 py-3 hover:bg-slate-750 active:bg-slate-700 transition-colors"
      >
        <div className="flex items-center justify-between mb-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-slate-200">{project.name}</span>
            <span className="text-xs font-mono text-slate-500">{project.prefix}</span>
          </div>
          <div className="flex gap-3 text-xs text-slate-500">
            <span><span className="text-blue-400">{project.open_tasks}</span> tasks</span>
            <span><span className="text-amber-400">{project.open_issues}</span> issues</span>
          </div>
        </div>
        {hasActivity ? (
          <button
            onClick={toggleExpand}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-300 transition-colors mt-1"
          >
            <ChevronDown open={expanded} />
            <span>{label}</span>
          </button>
        ) : (
          <span className="text-xs text-slate-600 mt-1 block">No recent activity</span>
        )}
      </Link>
      {expanded && hasActivity && (
        <div className="px-4 pb-3 space-y-1.5 border-t border-slate-700/50 pt-2">
          {activity.map((item) => (
            <Link
              key={item.id}
              to={item.href}
              className="flex items-center gap-2 text-xs hover:bg-slate-700/50 rounded px-2 py-1 -mx-2 transition-colors"
            >
              <span className={`font-mono flex-shrink-0 ${TYPE_COLORS[item.type] ?? 'text-slate-400'}`}>
                {item.id}
              </span>
              <span className="text-slate-300 truncate flex-1">{item.title}</span>
              <span className="text-slate-600 flex-shrink-0">{timeAgo(item.updated_at)}</span>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}

export function DashboardPage() {
  const { projects, generatedAt, isPending, isError } = useProjects()
  const { allTasks } = useTasks()
  const { allIssues } = useIssues()
  const { allFeatures } = useFeatures()

  /** Sort projects by latest activity across all record types */
  const sortedProjects = useMemo(() => {
    if (!projects.length) return []
    const projectActivity = new Map<string, { latest: string; items: ActivityItem[] }>()
    for (const p of projects) {
      const items = projectActivityItems(p.project_id, allTasks, allIssues, allFeatures)
      const sorted = [...items].sort((a, b) => b.updated_at.localeCompare(a.updated_at))
      projectActivity.set(p.project_id, {
        latest: sorted[0]?.updated_at ?? p.updated_at ?? '',
        items: selectActivityItems(items),
      })
    }
    return [...projects].sort((a, b) => {
      const aLatest = projectActivity.get(a.project_id)?.latest ?? ''
      const bLatest = projectActivity.get(b.project_id)?.latest ?? ''
      return bLatest.localeCompare(aLatest)
    }).map((p) => ({
      project: p,
      activity: projectActivity.get(p.project_id)?.items ?? [],
    }))
  }, [projects, allTasks, allIssues, allFeatures])

  if (isPending) return <LoadingState />
  if (isError) return <ErrorState />

  const openTasks = allTasks.filter((t) => t.status !== 'closed').length
  const openIssues = allIssues.filter((i) => i.status !== 'closed').length
  const completedFeatures = allFeatures.filter((f) => f.status === 'completed').length

  return (
    <div className="p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-slate-400">Overview</h2>
        <FreshnessBadge generatedAt={generatedAt} />
      </div>

      <div className="grid grid-cols-3 gap-3">
        <Link to="/feed?type=task" className="bg-slate-800 rounded-lg p-3 text-center active:bg-slate-700">
          <div className="text-2xl font-bold text-blue-400">{openTasks}</div>
          <div className="text-xs text-slate-500 mt-0.5">Open Tasks</div>
        </Link>
        <Link to="/feed?type=issue" className="bg-slate-800 rounded-lg p-3 text-center active:bg-slate-700">
          <div className="text-2xl font-bold text-amber-400">{openIssues}</div>
          <div className="text-xs text-slate-500 mt-0.5">Open Issues</div>
        </Link>
        <Link to="/feed?type=feature" className="bg-slate-800 rounded-lg p-3 text-center active:bg-slate-700">
          <div className="text-2xl font-bold text-emerald-400">{completedFeatures}</div>
          <div className="text-xs text-slate-500 mt-0.5">Live Features</div>
        </Link>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-slate-800 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-slate-200">{projects.length}</div>
          <div className="text-xs text-slate-500 mt-0.5">Projects</div>
        </div>
        <div className="bg-slate-800 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-slate-200">{allFeatures.length}</div>
          <div className="text-xs text-slate-500 mt-0.5">Total Features</div>
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-medium text-slate-400">Projects</h3>
          <Link to="/projects" className="text-xs text-blue-400">View all</Link>
        </div>
        <div className="space-y-2">
          {sortedProjects.map(({ project, activity }) => (
            <ProjectActivityCard
              key={project.project_id}
              project={project}
              activity={activity}
            />
          ))}
        </div>
      </div>
    </div>
  )
}
