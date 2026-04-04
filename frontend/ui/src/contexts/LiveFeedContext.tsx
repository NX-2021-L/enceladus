/**
 * LiveFeedContext — Global live feed provider with incremental delta polling.
 *
 * ENC-TSK-608: Polls GET /api/v1/feed?since=<ts> every 3 seconds, merges
 * deltas into local state via Map-based upsert, and exposes live data to all
 * pages (feed list + detail).  Replaces the page-level polling in useFeed.ts.
 *
 * Timing budget:
 *   3 s poll interval + ~200 ms API response + ~50 ms merge/render = ~3.25 s
 *   worst-case latency from DynamoDB write to UI render.
 */

import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  useCallback,
  type ReactNode,
} from 'react'
import { fetchLiveFeed, fetchLiveFeedDelta } from '../api/feeds'
import { isSessionExpiredError } from '../lib/authSession'
import type { Task, Issue, Feature, Lesson, Plan } from '../types/feeds'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface LiveFeedState {
  tasks: Task[]
  issues: Issue[]
  features: Feature[]
  lessons: Lesson[]
  plans: Plan[]
  generatedAt: string | null
  isPending: boolean
  isError: boolean
}

const INITIAL_STATE: LiveFeedState = {
  tasks: [],
  issues: [],
  features: [],
  lessons: [],
  plans: [],
  generatedAt: null,
  isPending: true,
  isError: false,
}

const LiveFeedCtx = createContext<LiveFeedState>(INITIAL_STATE)

// ---------------------------------------------------------------------------
// Merge helpers
// ---------------------------------------------------------------------------

const POLL_INTERVAL = 3_000
const FULL_REFRESH_AGE_MS = 30 * 60 * 1_000 // 30 min

/**
 * Returns true if `val` is an "empty sentinel" that the live feed API uses
 * as a placeholder for fields it doesn't populate (e.g. `""`, `[]`).
 * These should not overwrite richer data already held in state.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isEmptySentinel(val: any): boolean {
  if (val === '' || val === null || val === undefined) return true
  if (Array.isArray(val) && val.length === 0) return true
  return false
}

/**
 * Shallow-merge `incoming` into `existing`, skipping empty sentinel values
 * in `incoming` when `existing` has richer data for that field (ENC-ISS-148).
 * The live feed API returns sparse records with hardcoded empty strings and
 * empty arrays for fields like description, history, and checklist.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function shallowMergeRecord<T extends Record<string, any>>(existing: T, incoming: T): T {
  const merged = { ...existing }
  for (const key of Object.keys(incoming)) {
    const incomingVal = incoming[key]
    const existingVal = existing[key]
    // Only skip the incoming value if it's an empty sentinel AND the existing
    // value is richer. If both are empty, or the field is new, take incoming.
    if (isEmptySentinel(incomingVal) && !isEmptySentinel(existingVal)) {
      continue
    }
    merged[key] = incomingVal
  }
  return merged as T
}

/**
 * Upsert `delta` into `existing` by `idKey`, removing any IDs in `closedIds`.
 * Delta items are shallow-merged into existing records, preserving richer
 * field values from prior loads when the delta carries empty sentinels
 * (fixes ENC-ISS-148: acceptance_criteria / intent / history disappearing).
 * Returns a new array only when contents actually changed.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mergeById<T extends Record<string, any>>(
  existing: T[],
  delta: T[],
  idKey: keyof T & string,
  closedIds: Set<string>,
): T[] {
  if (delta.length === 0 && closedIds.size === 0) return existing

  const map = new Map<string, T>()
  for (const item of existing) {
    const id = String(item[idKey])
    if (!closedIds.has(id)) map.set(id, item)
  }
  for (const item of delta) {
    const id = String(item[idKey])
    const prev = map.get(id)
    map.set(id, prev ? shallowMergeRecord(prev, item) : item)
  }

  const merged = Array.from(map.values())

  // Cheap reference-equality check: if nothing changed, return original.
  if (
    merged.length === existing.length &&
    delta.length === 0 &&
    closedIds.size === 0
  ) {
    return existing
  }
  return merged
}

/** Shallow-compare two arrays by length + element identity. */
function arraysEqual<T>(a: T[], b: T[]): boolean {
  if (a === b) return true
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export function LiveFeedProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<LiveFeedState>(INITIAL_STATE)

  // Mutable refs so the polling callback always reads current values without
  // causing effect re-registrations.
  const stateRef = useRef(state)
  stateRef.current = state

  const sinceRef = useRef<string | null>(null)
  const mountedRef = useRef(true)
  const inflight = useRef(false)

  // ---- Full refresh (on mount or after long idle) ----
  const doFullRefresh = useCallback(async () => {
    if (inflight.current) return
    inflight.current = true
    try {
      const data = await fetchLiveFeed()
      if (!mountedRef.current) return
      sinceRef.current = data.generated_at
      setState({
        tasks: data.tasks,
        issues: data.issues,
        features: data.features,
        lessons: data.lessons ?? [],
        plans: data.plans ?? [],
        generatedAt: data.generated_at,
        isPending: false,
        isError: false,
      })
    } catch (err) {
      if (!mountedRef.current) return
      if (isSessionExpiredError(err)) return // silent — session overlay handles it
      setState((prev) => ({ ...prev, isPending: false, isError: true }))
    } finally {
      inflight.current = false
    }
  }, [])

  // ---- Delta poll ----
  const doDelta = useCallback(async () => {
    const since = sinceRef.current
    if (!since || inflight.current) return
    inflight.current = true

    // Fall back to full refresh if since is too old.
    const sinceAge = Date.now() - new Date(since).getTime()
    if (sinceAge > FULL_REFRESH_AGE_MS) {
      inflight.current = false
      await doFullRefresh()
      return
    }

    try {
      const data = await fetchLiveFeedDelta(since)
      if (!mountedRef.current) return

      sinceRef.current = data.generated_at
      const closedSet = new Set(data.closed_ids ?? [])
      const prev = stateRef.current

      const nextTasks = mergeById(prev.tasks, data.tasks, 'task_id', closedSet)
      const nextIssues = mergeById(prev.issues, data.issues, 'issue_id', closedSet)
      const nextFeatures = mergeById(prev.features, data.features, 'feature_id', closedSet)
      const nextLessons = mergeById(prev.lessons, data.lessons ?? [], 'lesson_id', closedSet)
      const nextPlans = mergeById(prev.plans, data.plans ?? [], 'plan_id', closedSet)

      // Only trigger a re-render when record content changes.
      if (
        !arraysEqual(nextTasks, prev.tasks) ||
        !arraysEqual(nextIssues, prev.issues) ||
        !arraysEqual(nextFeatures, prev.features) ||
        !arraysEqual(nextLessons, prev.lessons) ||
        !arraysEqual(nextPlans, prev.plans)
      ) {
        setState({
          tasks: nextTasks,
          issues: nextIssues,
          features: nextFeatures,
          lessons: nextLessons,
          plans: nextPlans,
          generatedAt: data.generated_at,
          isPending: false,
          isError: false,
        })
      }
    } catch (err) {
      if (!mountedRef.current) return
      if (isSessionExpiredError(err)) return
      // Don't overwrite data on transient errors — just skip this cycle.
    } finally {
      inflight.current = false
    }
  }, [doFullRefresh])

  // ---- Lifecycle ----
  useEffect(() => {
    mountedRef.current = true
    doFullRefresh()

    const id = setInterval(() => {
      if (document.visibilityState === 'visible') {
        doDelta()
      }
    }, POLL_INTERVAL)

    // Refetch on tab focus after a period of being hidden.
    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        doDelta()
      }
    }
    document.addEventListener('visibilitychange', onVisibility)

    return () => {
      mountedRef.current = false
      clearInterval(id)
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [doFullRefresh, doDelta])

  return <LiveFeedCtx.Provider value={state}>{children}</LiveFeedCtx.Provider>
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useLiveFeed(): LiveFeedState {
  return useContext(LiveFeedCtx)
}
