import { useState, useMemo, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useProjects } from '../hooks/useProjects'
import { useTasks } from '../hooks/useTasks'
import { useIssues } from '../hooks/useIssues'
import { useFeatures } from '../hooks/useFeatures'
import { useInfiniteList } from '../hooks/useInfiniteList'
import { TaskRow } from '../components/cards/TaskRow'
import { IssueRow } from '../components/cards/IssueRow'
import { FeatureRow } from '../components/cards/FeatureRow'
import { FilterBar } from '../components/shared/FilterBar'
import { SortPicker } from '../components/shared/SortPicker'
import { ScrollSentinel } from '../components/shared/ScrollSentinel'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { EmptyState } from '../components/shared/EmptyState'
import {
  TASK_STATUSES,
  ISSUE_STATUSES,
  FEATURE_STATUSES,
  STATUS_LABELS,
  STATUS_COLORS,
  SORT_OPTIONS_TASKS,
  SORT_OPTIONS_ISSUES,
  SORT_OPTIONS_FEATURES,
} from '../lib/constants'

type Tab = 'tasks' | 'issues' | 'features'

function useArrayToggle(initial: string[] = []) {
  const [arr, setArr] = useState<string[]>(initial)
  const toggle = useCallback((value: string) => {
    setArr((prev) => {
      const next = prev.includes(value) ? prev.filter((v) => v !== value) : [...prev, value]
      return next
    })
  }, [])
  return [arr, toggle] as const
}

export function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const [activeTab, setActiveTab] = useState<Tab>('tasks')
  const [taskSort, setTaskSort] = useState('updated:desc')
  const [issueSort, setIssueSort] = useState('updated:desc')
  const [featureSort, setFeatureSort] = useState('updated:desc')
  const [taskStatIdx, setTaskStatIdx] = useState(0)
  const [issueStatIdx, setIssueStatIdx] = useState(0)
  const [featureStatIdx, setFeatureStatIdx] = useState(0)
  const [taskStatusFilter, toggleTaskStatus] = useArrayToggle()
  const [issueStatusFilter, toggleIssueStatus] = useArrayToggle()
  const [featureStatusFilter, toggleFeatureStatus] = useArrayToggle()

  const { projects, isPending: loadingProjects } = useProjects()

  // Filtered + sorted lists (status filter applied)
  const { tasks, allTasks } = useTasks({
    projectId,
    sortBy: taskSort,
    status: taskStatusFilter.length ? taskStatusFilter : undefined,
  })
  const { issues, allIssues } = useIssues({
    projectId,
    sortBy: issueSort,
    status: issueStatusFilter.length ? issueStatusFilter : undefined,
  })
  const { features, allFeatures } = useFeatures({
    projectId,
    sortBy: featureSort,
    status: featureStatusFilter.length ? featureStatusFilter : undefined,
  })

  const tasksPaged = useInfiniteList(tasks)
  const issuesPaged = useInfiniteList(issues)
  const featuresPaged = useInfiniteList(features)

  // Stat cards use unfiltered project-scoped data
  const projectTasks = useMemo(
    () => allTasks.filter((t) => t.project_id === projectId),
    [allTasks, projectId],
  )
  const projectIssues = useMemo(
    () => allIssues.filter((i) => i.project_id === projectId),
    [allIssues, projectId],
  )
  const projectFeatures = useMemo(
    () => allFeatures.filter((f) => f.project_id === projectId),
    [allFeatures, projectId],
  )

  const taskStats = useMemo(() => {
    const open = projectTasks.filter((t) => t.status === 'open').length
    const planned = projectTasks.filter((t) => t.status === 'planned').length
    const closed = projectTasks.filter((t) => t.status === 'closed').length
    const total = projectTasks.length
    const pct = total > 0 ? Math.round((closed / total) * 100) : 0
    return [
      { value: String(open), label: 'Open Tasks', color: 'text-blue-400' },
      { value: String(planned), label: 'Planned Tasks', color: 'text-purple-400' },
      { value: String(closed), label: 'Closed Tasks', color: 'text-rose-400' },
      { value: `${pct}%`, label: 'Closed', color: 'text-slate-200' },
    ]
  }, [projectTasks])

  const issueStats = useMemo(() => {
    const open = projectIssues.filter((i) => i.status === 'open').length
    const closed = projectIssues.filter((i) => i.status === 'closed').length
    const total = projectIssues.length
    const pct = total > 0 ? Math.round((closed / total) * 100) : 0
    return [
      { value: String(open), label: 'Open Issues', color: 'text-amber-400' },
      { value: String(closed), label: 'Closed Issues', color: 'text-rose-400' },
      { value: `${pct}%`, label: 'Closed', color: 'text-slate-200' },
    ]
  }, [projectIssues])

  const featureStats = useMemo(() => {
    const completed = projectFeatures.filter((f) => f.status === 'completed').length
    const total = projectFeatures.length
    const pct = total > 0 ? Math.round((completed / total) * 100) : 0
    return [
      { value: String(completed), label: 'Live', color: 'text-emerald-400' },
      { value: `${pct}%`, label: 'Launched', color: 'text-emerald-400' },
    ]
  }, [projectFeatures])

  if (loadingProjects) return <LoadingState />
  const project = projects.find((p) => p.project_id === projectId)
  if (!project) return <ErrorState message="Project not found" />

  const tabs: { key: Tab; label: string; count: number }[] = [
    { key: 'tasks', label: 'Tasks', count: tasks.length },
    { key: 'issues', label: 'Issues', count: issues.length },
    { key: 'features', label: 'Features', count: features.length },
  ]

  return (
    <div>
      {/* Sticky top section: project info + stats + tabs + sort/filter */}
      <div className="sticky top-0 z-10 bg-slate-900">
        <div className="px-4 pt-4 pb-3 space-y-3">
          <div>
            <Link to="/projects" className="text-xs text-blue-400 mb-1 inline-block">
              &larr; Projects
            </Link>
            <div className="flex items-baseline justify-between">
              <h2 className="text-lg font-semibold text-slate-100">{project.name}</h2>
              <div className="flex items-center gap-3">
                <Link
                  to={`/documents/${projectId}`}
                  className="text-[11px] font-bold tracking-widest text-slate-500 hover:text-blue-400 transition-colors"
                >
                  PRIMARY DOCS
                </Link>
                <Link
                  to={`/projects/${projectId}/reference`}
                  className="text-[11px] font-bold tracking-widest text-slate-500 hover:text-blue-400 transition-colors"
                >
                  REFERENCE
                </Link>
              </div>
            </div>
            <span className="text-xs font-mono text-slate-500">{project.prefix}</span>
            {project.summary && <p className="text-sm text-slate-400 mt-2">{project.summary}</p>}
          </div>

          <div className="grid grid-cols-3 gap-3">
            <button
              onClick={() => setTaskStatIdx((i) => (i + 1) % taskStats.length)}
              className="bg-slate-800 rounded-lg p-2.5 text-center active:bg-slate-700 transition-colors min-h-[60px]"
            >
              <div className={`text-lg font-bold ${taskStats[taskStatIdx].color}`}>
                {taskStats[taskStatIdx].value}
              </div>
              <div className="text-xs text-slate-500">{taskStats[taskStatIdx].label}</div>
            </button>
            <button
              onClick={() => setIssueStatIdx((i) => (i + 1) % issueStats.length)}
              className="bg-slate-800 rounded-lg p-2.5 text-center active:bg-slate-700 transition-colors min-h-[60px]"
            >
              <div className={`text-lg font-bold ${issueStats[issueStatIdx].color}`}>
                {issueStats[issueStatIdx].value}
              </div>
              <div className="text-xs text-slate-500">{issueStats[issueStatIdx].label}</div>
            </button>
            <button
              onClick={() => setFeatureStatIdx((i) => (i + 1) % featureStats.length)}
              className="bg-slate-800 rounded-lg p-2.5 text-center active:bg-slate-700 transition-colors min-h-[60px]"
            >
              <div className={`text-lg font-bold ${featureStats[featureStatIdx].color}`}>
                {featureStats[featureStatIdx].value}
              </div>
              <div className="text-xs text-slate-500">{featureStats[featureStatIdx].label}</div>
            </button>
          </div>

          <div className="flex border-b border-slate-700">
            {tabs.map(({ key, label, count }) => (
              <button
                key={key}
                onClick={() => setActiveTab(key)}
                className={`flex-1 py-2.5 text-sm font-medium text-center border-b-2 transition-colors min-h-[44px] ${
                  activeTab === key
                    ? 'border-blue-400 text-blue-400'
                    : 'border-transparent text-slate-500 hover:text-slate-300'
                }`}
              >
                {label} <span className="text-xs">({count})</span>
              </button>
            ))}
          </div>

          {activeTab === 'tasks' && (
            <div className="space-y-2">
              <SortPicker options={SORT_OPTIONS_TASKS} active={taskSort} onChange={setTaskSort} />
              <FilterBar
                options={TASK_STATUSES}
                selected={taskStatusFilter}
                onToggle={toggleTaskStatus}
                labels={STATUS_LABELS}
                colorMap={STATUS_COLORS}
              />
            </div>
          )}

          {activeTab === 'issues' && (
            <div className="space-y-2">
              <SortPicker options={SORT_OPTIONS_ISSUES} active={issueSort} onChange={setIssueSort} />
              <FilterBar
                options={ISSUE_STATUSES}
                selected={issueStatusFilter}
                onToggle={toggleIssueStatus}
                labels={STATUS_LABELS}
                colorMap={STATUS_COLORS}
              />
            </div>
          )}

          {activeTab === 'features' && (
            <div className="space-y-2">
              <SortPicker
                options={SORT_OPTIONS_FEATURES}
                active={featureSort}
                onChange={setFeatureSort}
              />
              <FilterBar
                options={FEATURE_STATUSES}
                selected={featureStatusFilter}
                onToggle={toggleFeatureStatus}
                labels={STATUS_LABELS}
                colorMap={STATUS_COLORS}
              />
            </div>
          )}
        </div>
        <div className="h-px bg-slate-700/50" />
      </div>

      {/* Scrollable item list */}
      <div className="px-4 py-3 space-y-2">
        {activeTab === 'tasks' && (
          <>
            {tasksPaged.visible.length ? (
              <>
                {tasksPaged.visible.map((t) => (
                  <TaskRow key={t.task_id} task={t} />
                ))}
                <ScrollSentinel sentinelRef={tasksPaged.sentinelRef} hasMore={tasksPaged.hasMore} />
              </>
            ) : (
              <EmptyState message="No tasks" />
            )}
          </>
        )}

        {activeTab === 'issues' && (
          <>
            {issuesPaged.visible.length ? (
              <>
                {issuesPaged.visible.map((i) => (
                  <IssueRow key={i.issue_id} issue={i} />
                ))}
                <ScrollSentinel
                  sentinelRef={issuesPaged.sentinelRef}
                  hasMore={issuesPaged.hasMore}
                />
              </>
            ) : (
              <EmptyState message="No issues" />
            )}
          </>
        )}

        {activeTab === 'features' && (
          <>
            {featuresPaged.visible.length ? (
              <>
                {featuresPaged.visible.map((f) => (
                  <FeatureRow key={f.feature_id} feature={f} />
                ))}
                <ScrollSentinel
                  sentinelRef={featuresPaged.sentinelRef}
                  hasMore={featuresPaged.hasMore}
                />
              </>
            ) : (
              <EmptyState message="No features" />
            )}
          </>
        )}
      </div>
    </div>
  )
}
