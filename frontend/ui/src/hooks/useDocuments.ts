import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  docs2Keys,
  fetchProjectDocs,
  fetchAllProjectDocs,
  fetchProjectDocCounts,
  searchDocsByTitle,
} from '../api/documents2'
import { useProjects } from './useProjects'
import type { DocumentFilters } from '../types/filters'

export function useDocs2(filters: DocumentFilters) {
  const { projects } = useProjects()
  const projectId = filters.projectId

  const query = useQuery({
    queryKey: projectId ? docs2Keys.list(projectId) : docs2Keys.all(),
    queryFn: () =>
      projectId
        ? fetchProjectDocs(projectId)
        : fetchAllProjectDocs(projects.map((p) => p.project_id)),
    staleTime: 30_000,
    refetchOnWindowFocus: true,
    enabled: projects.length > 0,
  })

  const countsQuery = useQuery({
    queryKey: docs2Keys.counts(),
    queryFn: () => fetchProjectDocCounts(projects.map((p) => p.project_id)),
    staleTime: 60_000,
    enabled: projects.length > 0,
  })

  const searchQuery = useQuery({
    queryKey: docs2Keys.search({
      title: filters.search ?? '',
      project: projectId ?? '',
    }),
    queryFn: () => searchDocsByTitle(filters.search!, projectId),
    enabled: !!(filters.search && filters.search.length >= 2),
    staleTime: 10_000,
  })

  const rawDocs = filters.search
    ? (searchQuery.data?.documents ?? [])
    : (query.data?.documents ?? [])

  const documents = useMemo(() => {
    let docs = rawDocs
    if (filters.status?.length) {
      docs = docs.filter((d) => filters.status!.includes(d.status))
    }
    const sortBy = filters.sortBy ?? 'updated:desc'
    const colonIdx = sortBy.indexOf(':')
    const field = colonIdx > -1 ? sortBy.slice(0, colonIdx) : sortBy
    const dir = colonIdx > -1 ? sortBy.slice(colonIdx + 1) : 'desc'
    return [...docs].sort((a, b) => {
      let cmp: number
      if (field === 'size') {
        cmp = (a.size_bytes ?? 0) - (b.size_bytes ?? 0)
      } else if (field === 'created') {
        cmp = (a.created_at ?? '').localeCompare(b.created_at ?? '')
      } else {
        cmp = (a.updated_at ?? '').localeCompare(b.updated_at ?? '')
      }
      return dir === 'asc' ? cmp : -cmp
    })
  }, [rawDocs, filters.status, filters.sortBy])

  const defaultProject = useMemo(() => {
    if (!countsQuery.data) return undefined
    const entries = Object.entries(countsQuery.data)
    if (!entries.length) return undefined
    return entries.sort((a, b) =>
      b[1].latest_updated_at.localeCompare(a[1].latest_updated_at),
    )[0]![0]
  }, [countsQuery.data])

  return {
    documents,
    totalMatches: filters.search
      ? (searchQuery.data?.total_matches ?? 0)
      : (query.data?.total_matches ?? rawDocs.length),
    projectCounts: countsQuery.data ?? {},
    defaultProject,
    isPending: query.isPending || (filters.search ? searchQuery.isPending : false),
    isError: query.isError,
    refetch: () => {
      query.refetch()
      countsQuery.refetch()
    },
  }
}
