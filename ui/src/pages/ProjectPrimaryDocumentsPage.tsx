import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { documentKeys, fetchPrimaryProjectReferenceDocs } from '../api/documents'
import { DocumentRow } from '../components/cards/DocumentRow'
import { EmptyState } from '../components/shared/EmptyState'
import { ErrorState } from '../components/shared/ErrorState'
import { LoadingState } from '../components/shared/LoadingState'

interface ProjectPrimaryDocumentsPageProps {
  projectId: string
}

export function ProjectPrimaryDocumentsPage({ projectId }: ProjectPrimaryDocumentsPageProps) {
  const normalizedProjectId = projectId.trim().toLowerCase()
  const { data, isPending, isError, error } = useQuery({
    queryKey: documentKeys.primaryReference(normalizedProjectId),
    queryFn: () => fetchPrimaryProjectReferenceDocs(normalizedProjectId),
    enabled: normalizedProjectId.length > 0,
    staleTime: 5 * 60 * 1000,
  })

  if (!normalizedProjectId) return <ErrorState message="Project id is required" />
  if (isPending) return <LoadingState />
  if (isError) {
    const message = error instanceof Error ? error.message : 'Failed to load primary reference files'
    return <ErrorState message={message} />
  }

  const docs = data ?? []

  return (
    <div className="p-4 space-y-3">
      <Link to={`/projects/${normalizedProjectId}`} className="text-xs text-blue-400 inline-block">
        &larr; Project
      </Link>

      <div className="bg-slate-800 rounded-lg p-4">
        <h2 className="text-sm font-semibold text-slate-100 mb-1">
          Primary Reference Files: {normalizedProjectId}
        </h2>
        <p className="text-xs text-slate-400">
          Includes the project reference and governance core files used for session context.
        </p>
      </div>

      {docs.length > 0 ? (
        <div className="space-y-2">
          {docs.map((doc) => (
            <DocumentRow key={doc.document_id} doc={doc} />
          ))}
        </div>
      ) : (
        <EmptyState message={`No primary reference files found for ${normalizedProjectId}`} />
      )}
    </div>
  )
}
