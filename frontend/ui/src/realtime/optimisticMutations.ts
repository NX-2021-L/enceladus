/**
 * Optimistic mutation layer (ENC-TSK-B67 AC-5, AC-6, AC-7, AC-19).
 *
 * Implements the canonical TanStack Query v5 cache-level `onMutate` pattern
 * (DOC-E470AC8CE9A8 §3) as a reusable factory. The five enforced steps:
 *
 *   1. cancelQueries for ALL affected keys simultaneously (detail + plans + feed)
 *   2. getQueryData snapshot of each affected key (atomic rollback context)
 *   3. setQueryData surgical update on the detail query + setQueriesData
 *      predicate update across every cached ['plan', ...] entry + feed prepend
 *   4. return the snapshot context for onError rollback
 *   5. onSettled invalidateQueries with fuzzy key matching for reconciliation
 *
 * Cross-page propagation (AC-6) uses a single `setQueriesData` predicate call —
 * no per-page manual cache walking. Failure rollback (AC-7) restores every
 * snapshot atomically. Conflict resolution (AC-19) detects HTTP 409 and applies
 * server-wins for governance-critical fields, surfacing a field-level merge for
 * independent fields.
 */

import type { QueryClient } from '@tanstack/react-query'

/** Governance-critical fields resolve server-wins, no user intervention (AC-19). */
export const GOVERNANCE_CRITICAL_FIELDS = [
  'status',
  'priority',
  'transition_type',
  'acceptance_criteria',
] as const

export interface RecordLike {
  recordId: string
  record_type?: string
  status?: string
  version?: number | string
  tasks?: RecordLike[]
  [key: string]: unknown
}

export interface StatusMutationVars {
  recordId: string
  recordType: string
  patch: Partial<RecordLike>
  /** Current record version → sent as If-Match for optimistic concurrency. */
  version?: number | string
}

export interface OptimisticContext {
  snapshots: Array<[readonly unknown[], unknown]>
}

export class ConflictError extends Error {
  status = 409
  serverRecord?: RecordLike
  divergentFields: string[]
  constructor(message: string, divergentFields: string[], serverRecord?: RecordLike) {
    super(message)
    this.name = 'ConflictError'
    this.divergentFields = divergentFields
    this.serverRecord = serverRecord
  }
}

export interface FieldMerge {
  field: string
  resolution: 'server-wins' | 'merge-ui'
  serverValue: unknown
  localValue: unknown
}

/**
 * Compute the conflict resolution plan for a 409 (AC-19): governance-critical
 * fields resolve server-wins automatically; independent fields surface a merge.
 */
export function resolveConflict(
  local: Partial<RecordLike>,
  server: RecordLike,
): FieldMerge[] {
  const fields = new Set<string>([...Object.keys(local), ...Object.keys(server)])
  const merges: FieldMerge[] = []
  for (const field of fields) {
    if (field === 'recordId' || field === 'version') continue
    const serverValue = server[field]
    const localValue = (local as Record<string, unknown>)[field]
    if (JSON.stringify(serverValue) === JSON.stringify(localValue)) continue
    const critical = (GOVERNANCE_CRITICAL_FIELDS as readonly string[]).includes(field)
    merges.push({
      field,
      resolution: critical ? 'server-wins' : 'merge-ui',
      serverValue,
      localValue,
    })
  }
  return merges
}

/** Build the If-Match request header for optimistic concurrency (AC-19). */
export function ifMatchHeaders(version: number | string | undefined): Record<string, string> {
  return version === undefined ? {} : { 'If-Match': String(version) }
}

export interface OptimisticHandlersDeps {
  queryClient: QueryClient
  detailKey: (recordType: string, recordId: string) => readonly unknown[]
  planKeyPrefix?: readonly unknown[]
  feedKey?: readonly unknown[]
  /** Register the optimistic eventId so the WS echo dedups (AC-9 layer 1). */
  registerOptimistic?: (eventId: string) => void
  /** Generate a temporary optimistic eventId. */
  makeEventId?: () => string
}

/**
 * Create the `{ onMutate, onError, onSettled }` trio for a record-field/status
 * mutation. Attach to any TanStack Query `useMutation`.
 */
export function createOptimisticHandlers(deps: OptimisticHandlersDeps) {
  const { queryClient, detailKey, planKeyPrefix, feedKey } = deps

  return {
    async onMutate(vars: StatusMutationVars): Promise<OptimisticContext> {
      const detail = detailKey(vars.recordType, vars.recordId)
      const affected: ReadonlyArray<readonly unknown[]> = [
        detail,
        ...(planKeyPrefix ? [planKeyPrefix] : []),
        ...(feedKey ? [feedKey] : []),
      ]

      // Step 1: cancel all affected refetches simultaneously.
      await Promise.all(affected.map((key) => queryClient.cancelQueries({ queryKey: key })))

      // Step 2: snapshot every affected key for atomic rollback.
      const snapshots: Array<[readonly unknown[], unknown]> = []
      snapshots.push([detail, queryClient.getQueryData(detail)])
      if (planKeyPrefix) {
        for (const [key, data] of queryClient.getQueriesData({ queryKey: planKeyPrefix })) {
          snapshots.push([key, data])
        }
      }
      if (feedKey) snapshots.push([feedKey, queryClient.getQueryData(feedKey)])

      // Step 3a: surgical detail update.
      queryClient.setQueryData<RecordLike>(detail, (old) =>
        old ? { ...old, ...vars.patch } : old,
      )

      // Step 3b: cross-page propagation across ALL cached plan entries in ONE
      // predicate call — no per-page manual walking (AC-6).
      if (planKeyPrefix) {
        queryClient.setQueriesData<RecordLike>({ queryKey: planKeyPrefix }, (plan) => {
          if (!plan?.tasks?.some((t) => t.recordId === vars.recordId)) return plan
          return {
            ...plan,
            tasks: plan.tasks.map((t) =>
              t.recordId === vars.recordId ? { ...t, ...vars.patch } : t,
            ),
          }
        })
      }

      // Step 3c: feed prepend with a pending optimistic event (AC-9 dedup setup).
      if (feedKey) {
        const eventId = deps.makeEventId?.()
        if (eventId) deps.registerOptimistic?.(eventId)
        queryClient.setQueryData<{ events: unknown[] }>(feedKey, (old) => {
          const optimistic = {
            eventId,
            recordId: vars.recordId,
            record_type: vars.recordType,
            action: vars.patch.status === 'closed' ? 'closed' : 'updated',
            pending: true,
          }
          if (!old?.events) return { events: [optimistic] }
          return { ...old, events: [optimistic, ...old.events] }
        })
      }

      // Step 4: return snapshots for onError.
      return { snapshots }
    },

    onError(_err: unknown, _vars: StatusMutationVars, context?: OptimisticContext): void {
      // Step 4 (cont.): atomically roll back every snapshot (AC-7).
      if (!context) return
      for (const [key, data] of context.snapshots) {
        queryClient.setQueryData(key, data)
      }
    },

    onSettled(_data: unknown, _err: unknown, vars: StatusMutationVars): void {
      // Step 5: reconcile with server truth via fuzzy invalidation (AC-9 L2).
      queryClient.invalidateQueries({ queryKey: detailKey(vars.recordType, vars.recordId) })
      if (planKeyPrefix) queryClient.invalidateQueries({ queryKey: planKeyPrefix })
      if (feedKey) queryClient.invalidateQueries({ queryKey: feedKey })
    },
  }
}
