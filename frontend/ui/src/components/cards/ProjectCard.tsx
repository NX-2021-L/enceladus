import { useState } from 'react'
import { Link } from 'react-router-dom'
import type { ProjectSummary } from '../../types/feeds'
import { timeAgo } from '../../lib/formatters'
import { EditProjectDialog } from '../projects/EditProjectDialog'

export function ProjectCard({ project }: { project: ProjectSummary }) {
  const [editing, setEditing] = useState(false)

  return (
    <>
      <Link
        to={`/projects/${project.project_id}`}
        className="block bg-slate-800 rounded-lg p-4 hover:bg-slate-750 transition-colors active:bg-slate-700"
      >
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-500">{project.prefix}</span>
            <h3 className="font-medium text-slate-100">{project.name}</h3>
          </div>
          <div className="flex items-center gap-1">
            <span className="text-xs text-slate-500">{timeAgo(project.updated_at)}</span>
            {/* The whole card is a Link, so this button must both stop propagation and
                prevent the default navigation — otherwise tapping Edit routes away to the
                detail page instead of opening the dialog. */}
            <button
              type="button"
              aria-label={`Edit project ${project.name}`}
              onClick={(e) => {
                e.preventDefault()
                e.stopPropagation()
                setEditing(true)
              }}
              className="min-h-11 min-w-11 flex items-center justify-center text-xs text-slate-400 hover:text-slate-100 rounded"
            >
              Edit
            </button>
          </div>
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

      {editing && (
        <EditProjectDialog
          projectId={project.project_id}
          onClose={() => setEditing(false)}
        />
      )}
    </>
  )
}
