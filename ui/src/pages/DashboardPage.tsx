import { Link } from 'react-router-dom'
import { useProjects } from '../hooks/useProjects'
import { useTasks } from '../hooks/useTasks'
import { useIssues } from '../hooks/useIssues'
import { useFeatures } from '../hooks/useFeatures'
import { FreshnessBadge } from '../components/shared/FreshnessBadge'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'

export function DashboardPage() {
  const { projects, generatedAt, isPending, isError } = useProjects()
  const { allTasks } = useTasks()
  const { allIssues } = useIssues()
  const { allFeatures } = useFeatures()

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
          {projects.slice(0, 5).map((p) => (
            <Link
              key={p.project_id}
              to={`/projects/${p.project_id}`}
              className="flex items-center justify-between bg-slate-800 rounded-lg px-4 py-3 active:bg-slate-700"
            >
              <div>
                <span className="text-sm font-medium text-slate-200">{p.name}</span>
                <span className="text-xs text-slate-500 ml-2">{p.prefix}</span>
              </div>
              <div className="flex gap-3 text-xs text-slate-500">
                <span><span className="text-blue-400">{p.open_tasks}</span> tasks</span>
                <span><span className="text-amber-400">{p.open_issues}</span> issues</span>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  )
}
