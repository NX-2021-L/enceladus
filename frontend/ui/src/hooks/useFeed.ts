import { useRef, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { feedKeys, fetchTasks, fetchIssues, fetchFeatures, fetchLiveFeed } from '../api/feeds'
import { PRIORITY_ORDER } from '../lib/constants'
import { isSessionExpiredError } from '../lib/authSession'
import type { Task, Issue, Feature } from '../types/feeds'
import type { FeedItem } from '../types/feed'
import type { FeedFilters } from '../types/filters'

function compareDates(a: string | null, b: string | null): number {
  if (!a) return 1
  if (!b) return -1
  return b.localeCompare(a)
}

function parseSort(raw?: string): { field: string; dir: 1 | -1 } {
  if (!raw) return { field: 'updated', dir: 1 }
  const [field, d] = raw.split(':')
  return { field, dir: d === 'asc' ? -1 : 1 }
}

/** Shallow-compare two arrays by checking length + element identity. */
function arraysEqual<T>(a: T[] | undefined, b: T[] | undefined): boolean {
  if (a === b) return true
  if (!a || !b || a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

/**
 * Stabilise an array reference: return the previous ref when elements haven't
 * changed.  This prevents downstream useMemo / React re-renders when TanStack
 * Query hands us a structurally-identical but referentially-new array.
 */
function useStableArray<T>(next: T[] | undefined): T[] | undefined {
  const ref = useRef(next)
  if (!arraysEqual(ref.current, next)) {
    ref.current = next
  }
  return ref.current
}

interface UseFeedOptions {
  polling?: boolean
}

export function useFeed(filters?: FeedFilters, options?: UseFeedOptions) {
  // S3 feeds for initial load (fast, CloudFront-cached, no Lambda cold start)
  const tasksQuery = useQuery({ queryKey: feedKeys.tasks, queryFn: fetchTasks })
  const issuesQuery = useQuery({ queryKey: feedKeys.issues, queryFn: fetchIssues })
  const featuresQuery = useQuery({ queryKey: feedKeys.features, queryFn: fetchFeatures })

  // SINGLE live feed observer — one useQuery = one refetchInterval timer = one
  // network request per 3 s.  Previous approach used 4 observers which multiplied
  // the poll rate by 4x (DVP-ISS-021).
  //
  // throwOnError: suppress SessionExpiredError so it doesn't bubble to the
  // global QueryCache.onError handler and trigger the SessionExpiredOverlay.
  // Background polling should silently retry on the next cycle — the overlay
  // should only appear for user-initiated actions or initial data loads.
  const liveFeedQuery = useQuery({
    queryKey: feedKeys.liveFeed,
    queryFn: fetchLiveFeed,
    refetchInterval: options?.polling ? 3000 : undefined,
    enabled: options?.polling ?? false,
    retry: (count, error) => {
      if (isSessionExpiredError(error)) return false
      return count < 2
    },
    throwOnError: false,
    meta: { suppressSessionExpired: true },
  })

  // Pending only while S3 feeds are loading (live feed loading doesn't block UI)
  const isPending = tasksQuery.isPending || issuesQuery.isPending || featuresQuery.isPending
  const isError = tasksQuery.isError || issuesQuery.isError || featuresQuery.isError

  // Derive sub-arrays from the single live query response.  Stabilise refs so
  // that a new generated_at (changes every poll) doesn't cascade into a new
  // items array when the actual records are identical.
  const liveTasks = useStableArray(liveFeedQuery.data?.tasks)
  const liveIssues = useStableArray(liveFeedQuery.data?.issues)
  const liveFeatures = useStableArray(liveFeedQuery.data?.features)

  const tasks: Task[] | undefined = liveTasks ?? tasksQuery.data?.tasks
  const issues: Issue[] | undefined = liveIssues ?? issuesQuery.data?.issues
  const features: Feature[] | undefined = liveFeatures ?? featuresQuery.data?.features

  const generatedAt = liveFeedQuery.data?.generated_at
    ?? tasksQuery.data?.generated_at
    ?? issuesQuery.data?.generated_at
    ?? featuresQuery.data?.generated_at
    ?? null

  const items = useMemo(() => {
    const merged: FeedItem[] = []

    const types = filters?.recordType?.length ? filters.recordType : ['task', 'issue', 'feature']

    if (types.includes('task') && tasks) {
      for (const t of tasks) {
        merged.push({ _type: 'task', _id: t.task_id, _updated_at: t.updated_at, _created_at: t.created_at, data: t })
      }
    }
    if (types.includes('issue') && issues) {
      for (const i of issues) {
        merged.push({ _type: 'issue', _id: i.issue_id, _updated_at: i.updated_at, _created_at: i.created_at, data: i })
      }
    }
    if (types.includes('feature') && features) {
      for (const f of features) {
        merged.push({ _type: 'feature', _id: f.feature_id, _updated_at: f.updated_at, _created_at: f.created_at, data: f })
      }
    }

    let result = merged

    if (filters?.projectId) {
      result = result.filter((item) => item.data.project_id === filters.projectId)
    }
    if (filters?.status?.length) {
      result = result.filter((item) => filters.status!.includes(item.data.status))
    }
    if (filters?.priority?.length) {
      result = result.filter((item) => {
        if (item._type === 'task') return filters.priority!.includes(item.data.priority)
        if (item._type === 'issue') return filters.priority!.includes(item.data.priority)
        return true
      })
    }
    if (filters?.severity?.length) {
      result = result.filter((item) => {
        if (item._type === 'issue') return filters.severity!.includes(item.data.severity)
        return true
      })
    }
    if (filters?.search) {
      const q = filters.search.toLowerCase()
      result = result.filter(
        (item) => item.data.title.toLowerCase().includes(q) || item._id.toLowerCase().includes(q),
      )
    }

    const { field, dir } = parseSort(filters?.sortBy)
    result.sort((a, b) => {
      let cmp: number
      if (field === 'created') {
        cmp = compareDates(a._created_at, b._created_at)
      } else if (field === 'priority') {
        const pa = a._type !== 'feature' ? (PRIORITY_ORDER[(a.data as { priority: string }).priority] ?? 9) : 9
        const pb = b._type !== 'feature' ? (PRIORITY_ORDER[(b.data as { priority: string }).priority] ?? 9) : 9
        cmp = pa - pb
      } else {
        cmp = compareDates(a._updated_at, b._updated_at)
      }
      return cmp * dir
    })

    return result
  }, [
    tasks,
    issues,
    features,
    filters?.projectId,
    filters?.recordType,
    filters?.status,
    filters?.priority,
    filters?.severity,
    filters?.search,
    filters?.sortBy,
  ])

  return { items, generatedAt, isPending, isError }
}
