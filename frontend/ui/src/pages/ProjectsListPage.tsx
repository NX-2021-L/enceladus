import { useNavigate } from 'react-router-dom'
import { useProjects } from '../hooks/useProjects'
import { ProjectCard } from '../components/cards/ProjectCard'
import { FreshnessBadge } from '../components/shared/FreshnessBadge'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { EmptyState } from '../components/shared/EmptyState'

export function ProjectsListPage() {
  const { projects, generatedAt, isPending, isError } = useProjects()
  const navigate = useNavigate()

  if (isPending) return <LoadingState />
  if (isError) return <ErrorState />
  if (!projects.length) return <EmptyState message="No projects found" />

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-500">{projects.length} projects</span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => navigate('/projects/create')}
            className="px-3 py-1.5 bg-blue-600 text-white text-xs font-medium rounded hover:bg-blue-700 transition-colors"
          >
            + New Project
          </button>
          <FreshnessBadge generatedAt={generatedAt} />
        </div>
      </div>
      {projects.map((p) => (
        <ProjectCard key={p.project_id} project={p} />
      ))}
    </div>
  )
}
