import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  changelogKeys,
  fetchChangelogHistory,
  fetchAllChangelogHistory,
  fetchProjectVersion,
  fetchAllVersions,
} from '../api/changelog'
import { useProjects } from './useProjects'
import type { ChangelogFilters } from '../types/filters'

export function useChangelogHistory(filters: ChangelogFilters) {
  const { projects } = useProjects()
  const projectId = filters.projectId
  const params = {
    limit: 50,
    change_type: filters.changeType,
  }

  const singleQuery = useQuery({
    queryKey: changelogKeys.history(projectId ?? '', params),
    queryFn: () => fetchChangelogHistory(projectId!, params),
    staleTime: 60_000,
    enabled: !!projectId && projects.length > 0,
  })

  const allQuery = useQuery({
    queryKey: changelogKeys.historyAll(
      projects.map((p) => p.project_id),
      params,
    ),
    queryFn: () => fetchAllChangelogHistory(projects.map((p) => p.project_id), params),
    staleTime: 60_000,
    enabled: !projectId && projects.length > 0,
  })

  const rawEntries = projectId
    ? (singleQuery.data?.entries ?? [])
    : (allQuery.data?.entries ?? [])

  const entries = useMemo(() => {
    const sortBy = filters.sortBy ?? 'deployed:desc'
    const colonIdx = sortBy.indexOf(':')
    const field = colonIdx > -1 ? sortBy.slice(0, colonIdx) : sortBy
    const dir = colonIdx > -1 ? sortBy.slice(colonIdx + 1) : 'desc'
    return [...rawEntries].sort((a, b) => {
      const cmp = a.deployed_at.localeCompare(b.deployed_at)
      return dir === 'asc' ? cmp : -cmp
    })
  }, [rawEntries, filters.sortBy])

  // projectCounts: how many entries per project_id (for pill filter)
  const projectCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const entry of rawEntries) {
      counts[entry.project_id] = (counts[entry.project_id] ?? 0) + 1
    }
    return counts
  }, [rawEntries])

  const activeQuery = projectId ? singleQuery : allQuery

  return {
    entries,
    projectCounts,
    isPending: activeQuery.isPending,
    isError: activeQuery.isError,
    refetch: activeQuery.refetch,
  }
}

export function useProjectVersion(projectId: string) {
  return useQuery({
    queryKey: changelogKeys.version(projectId),
    queryFn: () => fetchProjectVersion(projectId),
    staleTime: 120_000,
    enabled: !!projectId,
  })
}

export function useProjectVersions() {
  const { projects } = useProjects()
  return useQuery({
    queryKey: changelogKeys.versions(projects.map((p) => p.project_id)),
    queryFn: () => fetchAllVersions(projects.map((p) => p.project_id)),
    staleTime: 120_000,
    enabled: projects.length > 0,
  })
}
