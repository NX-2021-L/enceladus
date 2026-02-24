import { useParams, Link } from 'react-router-dom'
import { useProjectReference } from '../hooks/useProjectReference'
import { useProjects } from '../hooks/useProjects'
import { MarkdownRenderer } from '../components/shared/MarkdownRenderer'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'

export function ProjectReferencePage() {
  const { projectId } = useParams<{ projectId: string }>()
  const { projects, isPending: loadingProjects } = useProjects()
  const { markdown, isPending, isError, errorMessage } = useProjectReference(projectId)

  if (loadingProjects || isPending) return <LoadingState />
  if (isError) return <ErrorState message={errorMessage} />

  const project = projects.find((p) => p.project_id === projectId)

  return (
    <div>
      {/* Sticky header */}
      <div className="sticky top-0 z-10 bg-slate-900 border-b border-slate-700">
        <div className="px-4 pt-3 pb-3 flex items-center gap-3">
          <Link
            to={`/projects/${projectId}`}
            className="text-xs text-blue-400 shrink-0"
          >
            &larr; {project?.name ?? projectId}
          </Link>
          <span className="text-xs text-slate-500 truncate">Reference Doc</span>
        </div>
      </div>

      {/* Markdown body */}
      <div className="px-4 py-4 pb-24">
        {markdown ? (
          <MarkdownRenderer content={markdown} />
        ) : (
          <p className="text-sm text-slate-500">No reference document available.</p>
        )}
      </div>
    </div>
  )
}
