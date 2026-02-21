import { useQuery } from '@tanstack/react-query'
import { feedKeys, fetchProjects } from '../api/feeds'

export function useProjects() {
  const query = useQuery({ queryKey: feedKeys.projects, queryFn: fetchProjects })
  return {
    projects: query.data?.projects ?? [],
    generatedAt: query.data?.generated_at ?? null,
    ...query,
  }
}
