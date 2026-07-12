/**
 * Typed queryOptions factories — the single source of truth for reading each
 * of the six governance primitives (AC-13). Route loaders call
 * `queryClient.ensureQueryData(recordQueryOptions.task(projectId, id))` and route
 * components call `useSuspenseQuery(recordQueryOptions.task(projectId, id))`, so the
 * data is typed `Task` (never `Task | undefined`) — that is AC-14.
 *
 * Every `queryFn` delegates to src/api/client.ts, which owns the only fetch()
 * calls in the app. No component ever fetches directly.
 *
 * Project slugs are threaded explicitly (ENC-TSK-L17) — never guessed from a
 * hard-coded prefix map.
 */

import { queryOptions } from '@tanstack/react-query'
import {
  readThroughDocumentRecord,
  readThroughTrackerRecord,
} from '../sync/readThrough'
import type {
  Document,
  Feature,
  Issue,
  Lesson,
  Plan,
  RecordShapeMap,
  RecordType,
  Task,
} from '../types/records'

/** Stable, hierarchical query keys — one namespace per record type + project. */
export const recordKeys = {
  all: ['record'] as const,
  detail: (type: RecordType, projectId: string, id: string) =>
    ['record', type, projectId, id] as const,
}

/**
 * ENC-TSK-M51 (B67 AC-8 part 2 / AC-14): record-detail reads are stale on
 * arrival, so a route loader's `ensureQueryData` always runs the queryFn (a
 * real per-record GET) on mount instead of being satisfied by a feed/corpus-
 * primed cache entry that is younger than the 2-minute global default
 * (src/api/queryClient.ts). While the page stays open the live
 * `/records/{recordId}` subscription (useRecordRealtimeSync) keeps the same
 * cache entry current via setQueryData — an idle mounted query is not refetched
 * merely because it is stale, so this forces network on load without churning.
 */
const DETAIL_STALE_TIME = 0

export const taskQueryOptions = (projectId: string, recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('task', projectId, recordId),
    queryFn: ({ signal }) =>
      readThroughTrackerRecord<Task>('task', projectId, recordId, { signal }),
    staleTime: DETAIL_STALE_TIME,
  })

export const issueQueryOptions = (projectId: string, recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('issue', projectId, recordId),
    queryFn: ({ signal }) =>
      readThroughTrackerRecord<Issue>('issue', projectId, recordId, { signal }),
    staleTime: DETAIL_STALE_TIME,
  })

export const featureQueryOptions = (projectId: string, recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('feature', projectId, recordId),
    queryFn: ({ signal }) =>
      readThroughTrackerRecord<Feature>('feature', projectId, recordId, { signal }),
    staleTime: DETAIL_STALE_TIME,
  })

export const planQueryOptions = (projectId: string, recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('plan', projectId, recordId),
    queryFn: ({ signal }) =>
      readThroughTrackerRecord<Plan>('plan', projectId, recordId, { signal }),
    staleTime: DETAIL_STALE_TIME,
  })

export const lessonQueryOptions = (projectId: string, recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('lesson', projectId, recordId),
    queryFn: ({ signal }) =>
      readThroughTrackerRecord<Lesson>('lesson', projectId, recordId, { signal }),
    staleTime: DETAIL_STALE_TIME,
  })

export const documentQueryOptions = (recordId: string, projectId = 'global') =>
  queryOptions({
    queryKey: recordKeys.detail('document', projectId, recordId),
    queryFn: ({ signal }) => readThroughDocumentRecord<Document>(recordId, { signal }),
    staleTime: DETAIL_STALE_TIME,
  })

/**
 * Registry of factories keyed by record type. Typed so `recordQueryOptions.task`
 * yields `Task` etc.; used by routes to stay DRY while preserving per-type types.
 */
export const recordQueryOptions = {
  task: taskQueryOptions,
  issue: issueQueryOptions,
  feature: featureQueryOptions,
  plan: planQueryOptions,
  lesson: lessonQueryOptions,
  document: documentQueryOptions,
} satisfies {
  [K in RecordType]: K extends 'document'
    ? (recordId: string, projectId?: string) => ReturnType<typeof queryOptions<RecordShapeMap[K]>>
    : (
        projectId: string,
        recordId: string,
      ) => ReturnType<typeof queryOptions<RecordShapeMap[K]>>
}
