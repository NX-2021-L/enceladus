import { Link } from 'react-router-dom'
import type { ProjectSummary } from '../../types/feeds'
import { timeAgo } from '../../lib/formatters'

export function ProjectCard({ project }: { project: ProjectSummary }) {
  return (
    <Link
      to={`/projects/${project.project_id}`}
      className="block bg-slate-800 rounded-lg p-4 hover:bg-slate-750 transition-colors active:bg-slate-700"
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-500">{project.prefix}</span>
          <h3 className="font-medium text-slate-100">{project.name}</h3>
        </div>
        <span className="text-xs text-slate-500">{timeAgo(project.updated_at)}</span>
      </div>
      {project.summary && (
        <p className="text-sm text-slate-400 mb-3 line-clamp-2">{project.summary}</p>
      )}
      <div className="flex gap-4 text-xs text-slate-500">
        <span>
          <span className="text-blue-400 font-medium">{project.open_tasks}</span> tasks
        </span>
        <span>
          <span className="text-amber-400 font-medium">{project.open_issues}</span> issues
        </span>
        <span>
          <span className="text-emerald-400 font-medium">{project.completed_features}</span> live features
        </span>
      </div>
    </Link>
  )
}
