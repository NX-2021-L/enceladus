/**
 * ENC-TSK-S98-0C (ENC-PLN-108 W3.3): the one piece of I/O the Plans page has.
 *
 * The lens itself is pure (DOC-5E1E205FA664 section 5.6) and knows nothing about the corpus or the kit. This hook is
 * the adapter between them: it maps the live corpus into `PlansRow`s and overlays the three lifecycle timestamps
 * from ENC-TSK-T05's plan-scoped read.
 *
 * Why two sources rather than one:
 *   - STRUCTURE (parent, wave, objectives_set, status) comes from the CORPUS, which is already seeded and healed on
 *     every route. Ruling D-28 keeps `parent` on the corpus row precisely so wave resolution needs no extra read.
 *   - TIME (created_at, first_checked_out_at, closed_at) comes from the PLAN-SCOPED READ. Ruling D-26 took these
 *     three off the corpus row because they were about 89 percent of the widening's cost.
 *
 * So the page renders complete wave structure immediately from the corpus and fills in the time scale when the
 * single plan-scope request lands. That request is made ONCE per page open and by no other route (ENC-TSK-T05 AC-4);
 * the page adds no polling of its own, because freshness is already owned by the corpus heal loop (section 5.8).
 */

import { useEffect, useMemo, useRef, useState } from 'react'
import { useEnceladusCorpus } from '../search/CorpusProvider'
import { fetchPlanScope, type PlanScopeTimes } from '../api/planScope'
import type { PlansRow } from './planView'

/** Row types the Plans page can draw. Anything else in the corpus is not its business. */
const LENS_TYPES = new Set(['plan', 'task'])

const text = (v: unknown): string | null => {
  if (typeof v !== 'string') return null
  const t = v.trim()
  return t ? t : null
}

const list = (v: unknown): readonly string[] | null => {
  if (!Array.isArray(v)) return null
  const out = v.map((x) => text(x)).filter((x): x is string => x !== null)
  return out.length ? out : null
}

/**
 * One corpus `IndexRow` as the lens reads it.
 *
 * `created_at` is read here too, even though the corpus does not carry it at corpus scope (D-26): if a future scope
 * ever does, the row simply arrives complete and the overlay below becomes a no-op rather than a conflict.
 */
function toLensRow(row: { id: string; type?: string; title?: string | null; fields?: Record<string, unknown> }): PlansRow {
  const f = row.fields ?? {}
  return {
    item_id: row.id,
    record_type: String(row.type ?? f.record_type ?? ''),
    title: text(row.title) ?? text(f.title),
    project_id: text(f.project_id),
    status: text(f.status),
    checkout_state: text(f.checkout_state),
    parent: text(f.parent),
    wave: text(f.wave),
    objectives_set: list(f.objectives_set),
    created_at: text(f.created_at),
  }
}

/** Apply the plan-scope overlay without discarding anything the corpus already knew. */
function withTimes(row: PlansRow, times: PlanScopeTimes | undefined): PlansRow {
  if (!times) return row
  const created = times.created_at ?? row.created_at ?? null
  const firstOut = times.first_checked_out_at ?? row.first_checked_out_at ?? null
  const closed = times.closed_at ?? row.closed_at ?? null
  if (created === row.created_at && firstOut === (row.first_checked_out_at ?? null) && closed === (row.closed_at ?? null)) {
    return row
  }
  return { ...row, created_at: created, first_checked_out_at: firstOut, closed_at: closed }
}

export interface PlansLens {
  /** Every row the page may draw, structure from the corpus and time from the plan-scoped read. */
  rows: readonly PlansRow[]
  /** Corpus `lastSeededAt` — the honest freshness signal (section 5.8), not a manual-refresh stamp. */
  asOf: string | null
  stale: boolean
  /** True until the corpus has something to draw. The plan-scope read does not block the first paint. */
  loading: boolean
  /**
   * FATAL only: the corpus could not be read, so there is nothing to draw. A failed plan-scope read is NOT fatal and
   * is reported separately -- the page keeps its wave structure and loses only the time scale.
   */
  error: string | null
  /** The time scale could not be read. Structure still draws; bars and rings are missing. */
  timeScaleError: string | null
  /** The plan-scope tree walk hit a bound and the time scale may be incomplete. */
  truncated: boolean
  refresh: () => void
}

export function usePlansLens(): PlansLens {
  const corpus = useEnceladusCorpus()
  const [times, setTimes] = useState<ReadonlyMap<string, PlanScopeTimes>>(() => new Map())
  const [truncated, setTruncated] = useState(false)
  const [scopeError, setScopeError] = useState<string | null>(null)
  // One request per page open (ENC-TSK-T05 AC-4). StrictMode double-invokes effects in development, so the ref
  // guards against a second call that would make the network capture lie.
  const asked = useRef(false)

  useEffect(() => {
    if (asked.current) return
    asked.current = true
    const ac = new AbortController()
    fetchPlanScope({ signal: ac.signal })
      .then((result) => {
        setTimes(result.times)
        setTruncated(result.truncated)
        setScopeError(null)
      })
      .catch((err: unknown) => {
        if (ac.signal.aborted) return
        // A failed overlay is not a failed page: structure still draws, the time scale is just missing.
        setScopeError(err instanceof Error ? err.message : 'Could not read the plan time scale')
      })
    return () => ac.abort()
  }, [])

  const rows = useMemo(() => {
    const out: PlansRow[] = []
    for (const row of corpus.rows ?? []) {
      const type = String((row as { type?: string }).type ?? '').toLowerCase()
      if (!LENS_TYPES.has(type)) continue
      out.push(withTimes(toLensRow(row as never), times.get((row as { id: string }).id)))
    }
    return out
  }, [corpus.rows, times])

  return {
    rows,
    asOf: corpus.lastSeededAt ?? null,
    stale: Boolean(corpus.staleNotice),
    loading: corpus.status === 'seeding' && rows.length === 0,
    // Deliberately NOT merged with scopeError: PlansPage treats `error` as fatal and replaces the whole page with
    // "Plans could not be loaded". Losing the time scale must not cost io the structure, which comes from the corpus
    // and is still perfectly good. Found on gamma, where /feed/plan-scope 404'd and blanked a page showing 60 plans.
    error: corpus.error ? String(corpus.error) : null,
    timeScaleError: scopeError,
    truncated,
    /**
     * AUTHORITATIVE: `{ seed: true }` is what forces a full re-seed. Without it the kit's sync() takes the
     * heal-only branch whenever the stored seed is younger than seedMaxAgeMs, which W2.5 set to 24 hours --
     * `doSeed = o.seed === true || !(fresh && haveCursors)`. A plain refresh() therefore issues /feed/delta and
     * never /feed/corpus, and a delta only returns rows whose version_seq moved.
     *
     * That matters here more than anywhere else in the app: W2.1 widened the corpus ROW SHAPE, and a row whose
     * record has not changed since never comes down again. On gamma this left plans sitting at their pre-W2.1
     * fields -- no objectives_set, no parent, no wave -- so every card read "0 tree tasks in 0 waves" and the
     * page's own refresh control could not repair it. CorpusRefreshButton already passes the flag for its
     * authoritative mode; this one did not.
     */
    refresh: () => {
      void corpus.refresh({ seed: true })
    },
  }
}
