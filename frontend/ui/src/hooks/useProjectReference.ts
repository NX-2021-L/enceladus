import { useQuery } from '@tanstack/react-query'
import { feedKeys, fetchProjectReference } from '../api/feeds'

export function useProjectReference(projectId: string | undefined) {
  const { data, isPending, isError, error } = useQuery({
    queryKey: feedKeys.reference(projectId ?? ''),
    queryFn: () => fetchProjectReference(projectId!),
    enabled: !!projectId,
    staleTime: 5 * 60 * 1000, // 5 min — reference docs change infrequently
    retry: 1,
  })

  return {
    markdown: data ?? null,
    isPending,
    isError,
    errorMessage: isError && error instanceof Error ? error.message : 'Failed to load reference',
  }
}
