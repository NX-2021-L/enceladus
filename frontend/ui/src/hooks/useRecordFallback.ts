/**
 * useRecordFallback — Shared hook that wraps the direct-API fallback pattern
 * previously inlined in Task/Issue/FeatureDetailPage (ENC-ISS-200 remediation).
 *
 * ENC-FTR-073 Phase 2a / ENC-TSK-D94.
 *
 * Behavior contract (DOC-BB658D8644DF §5):
 *   - No-op when the feed cache already holds the record (`cached` truthy).
 *     Returns { data: cached, isLoading: feedPending, isError: false,
 *     isNotFound: false }. No network I/O is issued.
 *   - Fetch gate: `!feedPending && !cached && !!recordId && !!projectId`.
 *   - Internally wraps TanStack Query (queryKey ['tracker', recordType,
 *     recordId]) so repeated mounts de-duplicate and AbortSignal cleanup on
 *     unmount is handled by the library.
 *   - Response is projected into feed shape via recordNormalizers.
 *   - `isNotFound` returns true when the fallback fetch throws a NotFoundError
 *     (or any error whose message matches /\b404\b/ for legacy parity).
 *   - `isError` returns true for non-404 failures when no data is available.
 */

import { useMemo } from 'react'
import { useQuery, type QueryFunctionContext } from '@tanstack/react-query'
import { useProjects } from './useProjects'
import {
  fetchDocument,
} from '../api/documents'
import {
  fetchFeatureById,
  fetchIssueById,
  fetchLessonById,
  fetchPlanById,
  fetchTaskById,
  isNotFoundError,
  resolveProjectFromRecordId,
  trackerKeys,
} from '../api/tracker'
import {
  normalizeRecord,
  type RecordType,
  type RecordTypeMap,
} from '../lib/recordNormalizers'

export interface UseRecordFallbackArgs<T extends RecordType> {
  recordType: T
  recordId: string | undefined
  /** Feed-cache lookup result. If present, the hook returns immediately
   *  without issuing any API request. */
  cached: RecordTypeMap[T] | undefined
  /** Loading flag for the owning feed hook (useTasks.isPending, etc.). */
  feedPending: boolean
  /** Error flag for the owning feed hook. Surfaces as `isError` only when no
   *  fallback data was returned. */
  feedError: boolean
}

export interface UseRecordFallbackResult<T extends RecordType> {
  data: RecordTypeMap[T] | undefined
  isLoading: boolean
  isError: boolean
  isNotFound: boolean
  /** Non-fatal warning from the normalizer (e.g. missing identifier). */
  warning?: string
  /** Callback for RecordFallbackError retry affordance. No-op when the
   *  fallback query is not active. */
  refetch: () => void
}

function queryKeyFor(recordType: RecordType, recordId: string) {
  switch (recordType) {
    case 'task':
      return trackerKeys.task(recordId)
    case 'issue':
      return trackerKeys.issue(recordId)
    case 'feature':
      return trackerKeys.feature(recordId)
    case 'plan':
      return trackerKeys.plan(recordId)
    case 'lesson':
      return trackerKeys.lesson(recordId)
    case 'document':
      return trackerKeys.document(recordId)
  }
}

async function fetchForType(
  recordType: RecordType,
  projectId: string,
  recordId: string,
  signal: AbortSignal | undefined,
): Promise<unknown> {
  switch (recordType) {
    case 'task':
      return fetchTaskById(projectId, recordId, { signal })
    case 'issue':
      return fetchIssueById(projectId, recordId, { signal })
    case 'feature':
      return fetchFeatureById(projectId, recordId, { signal })
    case 'plan':
      return fetchPlanById(projectId, recordId, { signal })
    case 'lesson':
      return fetchLessonById(projectId, recordId, { signal })
    case 'document':
      return fetchDocument(recordId, { signal })
  }
}

export function useRecordFallback<T extends RecordType>(
  args: UseRecordFallbackArgs<T>,
): UseRecordFallbackResult<T> {
  const { recordType, recordId, cached, feedPending, feedError } = args
  const { projects } = useProjects()

  const projectId = useMemo(() => {
    if (!recordId || cached) return null
    return resolveProjectFromRecordId(recordId, projects)
  }, [recordId, cached, projects])

  // ENC-FTR-073: Documents are routed through /api/v1/documents/{id} and do
  // not need a project prefix (document IDs like `DOC-...` do not match any
  // project prefix in the registry). Skip the projectId gate for documents.
  const projectIdRequired = recordType !== 'document'
  const fallbackEnabled =
    !feedPending &&
    !cached &&
    !!recordId &&
    (projectIdRequired ? !!projectId : true)

  const query = useQuery<unknown, Error>({
    queryKey: recordId ? queryKeyFor(recordType, recordId) : ['tracker', recordType, 'disabled'],
    queryFn: async ({ signal }: QueryFunctionContext) => {
      // projectId/recordId guaranteed present by `enabled` gate.
      return fetchForType(recordType, projectId as string, recordId as string, signal)
    },
    enabled: fallbackEnabled,
    retry: (failureCount, err) => {
      if (isNotFoundError(err)) return false
      return failureCount < 1
    },
  })

  const normalized = useMemo(() => {
    if (cached) return { data: cached, warning: undefined as string | undefined }
    if (query.data === undefined) return { data: undefined, warning: undefined as string | undefined }
    const result = normalizeRecord(recordType, query.data)
    return { data: result.data as RecordTypeMap[T], warning: result.warning }
  }, [cached, query.data, recordType])

  // Derived state
  const isNotFound =
    !cached && fallbackEnabled && query.isError && isNotFoundError(query.error)

  // Still loading while feed is pending, or while fallback is actively
  // fetching and no cached data is available. If no fallback path is
  // available (no projectId, invalid recordId), we do not spin forever —
  // instead collapse to isNotFound once the feed settles.
  const isLoading =
    (feedPending && !cached) ||
    (fallbackEnabled && query.isPending && !cached)

  // Error only when we have no data and the source is not a 404. Feed error
  // counts only when we have no fallback data either.
  const isError =
    !normalized.data && !isLoading && !isNotFound &&
    ((feedError && !fallbackEnabled) ||
      (fallbackEnabled && query.isError && !isNotFoundError(query.error)))

  return {
    data: normalized.data,
    isLoading,
    isError,
    isNotFound: Boolean(isNotFound),
    warning: normalized.warning,
    refetch: () => {
      if (fallbackEnabled) void query.refetch()
    },
  }
}
