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

export const taskQueryOptions = (projectId: string, recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('task', projectId, recordId),
    queryFn: ({ signal }) =>
      readThroughTrackerRecord<Task>('task', projectId, recordId, { signal }),
  })

export const issueQueryOptions = (projectId: string, recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('issue', projectId, recordId),
    queryFn: ({ signal }) =>
      readThroughTrackerRecord<Issue>('issue', projectId, recordId, { signal }),
  })

export const featureQueryOptions = (projectId: string, recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('feature', projectId, recordId),
    queryFn: ({ signal }) =>
      readThroughTrackerRecord<Feature>('feature', projectId, recordId, { signal }),
  })

export const planQueryOptions = (projectId: string, recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('plan', projectId, recordId),
    queryFn: ({ signal }) =>
      readThroughTrackerRecord<Plan>('plan', projectId, recordId, { signal }),
  })

export const lessonQueryOptions = (projectId: string, recordId: string) =>
  queryOptions({
    queryKey: recordKeys.detail('lesson', projectId, recordId),
    queryFn: ({ signal }) =>
      readThroughTrackerRecord<Lesson>('lesson', projectId, recordId, { signal }),
  })

export const documentQueryOptions = (recordId: string, projectId = 'global') =>
  queryOptions({
    queryKey: recordKeys.detail('document', projectId, recordId),
    queryFn: ({ signal }) => readThroughDocumentRecord<Document>(recordId, { signal }),
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
