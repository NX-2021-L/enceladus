import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { feedKeys, fetchTasks, fetchIssues, fetchFeatures } from '../api/feeds'
import { useLiveFeed } from '../contexts/LiveFeedContext'
import { PRIORITY_ORDER } from '../lib/constants'
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

interface UseFeedOptions {
  /** @deprecated Polling is now handled globally by LiveFeedProvider. This option is a no-op. */
  polling?: boolean
}

export function useFeed(filters?: FeedFilters, _options?: UseFeedOptions) {
  // Live data from the global delta-polling provider (ENC-TSK-609).
  const { tasks: liveTasks, issues: liveIssues, features: liveFeatures, generatedAt: liveGeneratedAt, isPending: livePending, isError: liveError } = useLiveFeed()

  // S3 feeds as fallback for initial load before LiveFeedProvider hydrates.
  const tasksQuery = useQuery({ queryKey: feedKeys.tasks, queryFn: fetchTasks })
  const issuesQuery = useQuery({ queryKey: feedKeys.issues, queryFn: fetchIssues })
  const featuresQuery = useQuery({ queryKey: feedKeys.features, queryFn: fetchFeatures })

  const tasks: Task[] = liveTasks.length > 0 ? liveTasks : (tasksQuery.data?.tasks ?? [])
  const issues: Issue[] = liveIssues.length > 0 ? liveIssues : (issuesQuery.data?.issues ?? [])
  const features: Feature[] = liveFeatures.length > 0 ? liveFeatures : (featuresQuery.data?.features ?? [])

  // Pending only while live context hasn't loaded AND S3 feeds are still loading.
  const isPending = liveTasks.length === 0 && liveIssues.length === 0 && liveFeatures.length === 0
    && (tasksQuery.isPending || issuesQuery.isPending || featuresQuery.isPending)
  const isError = liveTasks.length === 0 && liveIssues.length === 0 && liveFeatures.length === 0
    && (tasksQuery.isError || issuesQuery.isError || featuresQuery.isError)

  const generatedAt = liveGeneratedAt
    ?? tasksQuery.data?.generated_at
    ?? issuesQuery.data?.generated_at
    ?? featuresQuery.data?.generated_at
    ?? null

  const items = useMemo(() => {
    const merged: FeedItem[] = []

    const types = filters?.recordType?.length ? filters.recordType : ['task', 'issue', 'feature']

    if (types.includes('task') && tasks.length) {
      for (const t of tasks) {
        merged.push({ _type: 'task', _id: t.task_id, _updated_at: t.updated_at, _created_at: t.created_at, data: t })
      }
    }
    if (types.includes('issue') && issues.length) {
      for (const i of issues) {
        merged.push({ _type: 'issue', _id: i.issue_id, _updated_at: i.updated_at, _created_at: i.created_at, data: i })
      }
    }
    if (types.includes('feature') && features.length) {
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
