import { useRef, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { coordinationKeys, fetchCoordinationList, fetchCoordinationRequest } from '../api/coordination'
import { isSessionExpiredError } from '../lib/authSession'
import type { CoordinationFilters } from '../types/filters'

function compareDates(a: string | null | undefined, b: string | null | undefined): number {
  if (!a) return 1
  if (!b) return -1
  return b.localeCompare(a)
}

function parseSort(raw?: string): { field: string; dir: 1 | -1 } {
  if (!raw) return { field: 'updated', dir: 1 }
  const [field, d] = raw.split(':')
  return { field, dir: d === 'asc' ? -1 : 1 }
}

function arraysEqual<T>(a: T[] | undefined, b: T[] | undefined): boolean {
  if (a === b) return true
  if (!a || !b || a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

function useStableArray<T>(next: T[] | undefined): T[] | undefined {
  const ref = useRef(next)
  if (!arraysEqual(ref.current, next)) {
    ref.current = next
  }
  return ref.current
}

interface UseCoordinationListOptions {
  polling?: boolean
}

export function useCoordinationList(filters?: CoordinationFilters, options?: UseCoordinationListOptions) {
  const query = useQuery({
    queryKey: coordinationKeys.list,
    queryFn: fetchCoordinationList,
    refetchInterval: options?.polling ? 3000 : undefined,
    retry: (count, error) => {
      if (isSessionExpiredError(error)) return false
      return count < 2
    },
    throwOnError: false,
    meta: { suppressSessionExpired: true },
  })

  const stableRequests = useStableArray(query.data?.requests)

  const items = useMemo(() => {
    if (!stableRequests) return []

    let result = [...stableRequests]

    if (filters?.projectId) {
      result = result.filter((r) => r.project_id === filters.projectId)
    }
    if (filters?.state?.length) {
      result = result.filter((r) => filters.state!.includes(r.state))
    }
    if (filters?.search) {
      const q = filters.search.toLowerCase()
      result = result.filter(
        (r) =>
          r.initiative_title.toLowerCase().includes(q) ||
          r.request_id.toLowerCase().includes(q) ||
          r.outcomes.some((o) => o.toLowerCase().includes(q)),
      )
    }

    const { field, dir } = parseSort(filters?.sortBy)
    result.sort((a, b) => {
      let cmp: number
      if (field === 'created') {
        cmp = compareDates(a.created_at, b.created_at)
      } else {
        cmp = compareDates(a.updated_at, b.updated_at)
      }
      return cmp * dir
    })

    return result
  }, [stableRequests, filters?.projectId, filters?.state, filters?.search, filters?.sortBy])

  return {
    items,
    generatedAt: query.data?.generated_at ?? null,
    isPending: query.isPending,
    isError: query.isError,
  }
}

export function useCoordinationDetail(requestId: string | undefined) {
  const query = useQuery({
    queryKey: coordinationKeys.detail(requestId ?? ''),
    queryFn: () => fetchCoordinationRequest(requestId!),
    enabled: !!requestId,
    refetchInterval: 3000,
    retry: (count, error) => {
      if (isSessionExpiredError(error)) return false
      return count < 2
    },
    throwOnError: false,
    meta: { suppressSessionExpired: true },
  })

  return {
    request: query.data?.request ?? null,
    isPending: query.isPending,
    isError: query.isError,
  }
}
