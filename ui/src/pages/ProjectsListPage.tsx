import { useProjects } from '../hooks/useProjects'
import { ProjectCard } from '../components/cards/ProjectCard'
import { FreshnessBadge } from '../components/shared/FreshnessBadge'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { EmptyState } from '../components/shared/EmptyState'

export function ProjectsListPage() {
  const { projects, generatedAt, isPending, isError } = useProjects()

  if (isPending) return <LoadingState />
  if (isError) return <ErrorState />
  if (!projects.length) return <EmptyState message="No projects found" />

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-500">{projects.length} projects</span>
        <FreshnessBadge generatedAt={generatedAt} />
      </div>
      {projects.map((p) => (
        <ProjectCard key={p.project_id} project={p} />
      ))}
    </div>
  )
}
