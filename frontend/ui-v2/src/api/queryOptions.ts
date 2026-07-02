/**
 * Typed queryOptions factories — the single source of truth for reading each
 * of the six governance primitives (AC-13). Route loaders call
 * `queryClient.ensureQueryData(recordQueryOptions.task(id))` and route
 * components call `useSuspenseQuery(recordQueryOptions.task(id))`, so the data
 * is typed `Task` (never `Task | undefined`) — that is AC-14.
 *
 * Every `queryFn` delegates to src/api/client.ts, which owns the only fetch()
 * calls in the app. No component ever fetches directly.
 */

import { queryOptions } from '@tanstack/react-query'
import { fetchDocumentRecord, fetchTrackerRecord } from './client'
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

/**
 * Resolve the owning project from a record ID prefix. Real record IDs look like
 * `ENC-TSK-K21`; the middle segment is not the project. The tracker API keys on
 * a project slug, which for the Enceladus program is `enceladus`. A prefix map
 * lets other programs slot in without touching the factories.
 */
const PROJECT_BY_PREFIX: Record<string, string> = {
  ENC: 'enceladus',
}
const DEFAULT_PROJECT = 'enceladus'

export function resolveProject(recordId: string): string {
  const prefix = recordId.split('-')[0]?.toUpperCase() ?? ''
  return PROJECT_BY_PREFIX[prefix] ?? DEFAULT_PROJECT
}

/** Stable, hierarchical query keys — one namespace per record type. */
export const recordKeys = {
  all: ['record'] as const,
  detail: (type: RecordType, id: string) => ['record', type, id] as const,
}

export const taskQueryOptions = (recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('task', recordId),
    queryFn: ({ signal }) =>
      fetchTrackerRecord<Task>('task', resolveProject(recordId), recordId, { signal }),
  })

export const issueQueryOptions = (recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('issue', recordId),
    queryFn: ({ signal }) =>
      fetchTrackerRecord<Issue>('issue', resolveProject(recordId), recordId, { signal }),
  })

export const featureQueryOptions = (recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('feature', recordId),
    queryFn: ({ signal }) =>
      fetchTrackerRecord<Feature>('feature', resolveProject(recordId), recordId, { signal }),
  })

export const planQueryOptions = (recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('plan', recordId),
    queryFn: ({ signal }) =>
      fetchTrackerRecord<Plan>('plan', resolveProject(recordId), recordId, { signal }),
  })

export const lessonQueryOptions = (recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('lesson', recordId),
    queryFn: ({ signal }) =>
      fetchTrackerRecord<Lesson>('lesson', resolveProject(recordId), recordId, { signal }),
  })

export const documentQueryOptions = (recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('document', recordId),
    queryFn: ({ signal }) => fetchDocumentRecord<Document>(recordId, { signal }),
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
  [K in RecordType]: (
    recordId: string,
  ) => ReturnType<typeof queryOptions<RecordShapeMap[K]>>
}
