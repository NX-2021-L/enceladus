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

import { useEffect, useRef, useState } from 'react'
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
 * All THREE lifecycle timestamps are read here, even though no corpus or delta row carries them at corpus scope
 * (ruling D-26). They are read because a LIVE row can: ENC-TSK-S97-0B (W2.2) puts recordCreatedAt,
 * recordFirstCheckedOutAt and recordClosedAt on the /feed/updates event, and `@io-kit/search`'s mergeHeadline writes
 * them into `IndexRow.fields` in snake_case. The seeded row has none of them; a row that has since received a live
 * event has whichever ones its record carried.
 *
 * ENC-TSK-T22 (ENC-ISS-922): before this, only `created_at` was read, so `withTimes`'s fallback to the row's own
 * value was dead code and the event fields W2.2 ships were delivered and then dropped. That is what stopped criterion
 * 8 firing. ENC-TSK-T05's plan-scoped read runs ONCE per page open, so on an already-open page a task's FIRST
 * checkout has no other route to the lens -- and `hot(w)` is defined on first_checked_out_at alone, so without it a
 * freshly checked-out wave turns `active` (which `isCheckedOut` widens to cover) but never `hot`, and
 * `expandedDefault` never opens it.
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
    first_checked_out_at: text(f.first_checked_out_at),
    closed_at: text(f.closed_at),
  }
}

/**
 * ENC-TSK-T27 (ENC-ISS-925): the newer of two values for a stamp that only ever moves forward.
 *
 * All three lifecycle stamps are monotonic by W1's design: `created_at` and `first_checked_out_at` are written once
 * (`first_checked_out_at` through `if_not_exists`) and never change, and `closed_at` is only ever overwritten by a
 * LATER close -- never cleared. They are ISO 8601 UTC with a fixed shape, so a lexicographic compare is a time
 * compare. That makes "newest non-null wins" correct for all three and removes the question of source precedence.
 */
const newest = (a: string | null | undefined, b: string | null | undefined): string | null => {
  const x = a ?? null
  const y = b ?? null
  if (x === null) return y
  if (y === null) return x
  return y > x ? y : x
}

/**
 * Resolve each lifecycle stamp from the three places the page can learn it, newest non-null winning.
 *
 * The three: `times`, ENC-TSK-T05's plan-scoped read, made ONCE per page open; `row`, whatever the last live event
 * left on the corpus row (ENC-TSK-S97-0B writes them, ENC-TSK-T22 made the lens read them); and `seen`, what this
 * mount has already been told by either of the other two (ENC-TSK-T27).
 *
 * ENC-TSK-T27 (ENC-ISS-925) replaced T22's one-way "the plan-scope value WINS", and the change is deliberate rather
 * than incidental. That rule is wrong for `closed_at`: the plan-scope read never happens again, so on a page left
 * open, a re-entry and re-close would go on showing the FIRST close time for as long as the page stayed open. Taking
 * the newest is correct because every one of these stamps only moves forward (see `newest`). For `created_at` and
 * `first_checked_out_at` the two rules cannot genuinely disagree, since both are written once and every event
 * carries the same value.
 *
 * `seen` is what makes the whole thing hold: see `rememberRowStamps`.
 */
function withTimes(row: PlansRow, times: PlanScopeTimes | undefined, seen: PlanScopeTimes | undefined): PlansRow {
  if (!times && !seen) return row
  const created = newest(newest(times?.created_at, seen?.created_at), row.created_at)
  const firstOut = newest(newest(times?.first_checked_out_at, seen?.first_checked_out_at), row.first_checked_out_at)
  const closed = newest(newest(times?.closed_at, seen?.closed_at), row.closed_at)
  if (created === (row.created_at ?? null) && firstOut === (row.first_checked_out_at ?? null) && closed === (row.closed_at ?? null)) {
    return row
  }
  return { ...row, created_at: created, first_checked_out_at: firstOut, closed_at: closed }
}

/**
 * ENC-TSK-T27 (ENC-ISS-925): remember any stamp a corpus row is carrying, so a later row cannot un-say it.
 *
 * This is the whole fix. A live `/feed/updates` event enriches the corpus row with the three stamps (ENC-TSK-S97-0B
 * writes them, `mergeHeadline` lands them in `IndexRow.fields`, ENC-TSK-T22 made `toLensRow` read them), which is
 * what lets a freshly checked-out wave turn hot and open. But ruling D-26 deliberately keeps those stamps OFF every
 * corpus and delta row, so the NEXT 60-second heal delta replaces the enriched row with a bare one and the stamp is
 * gone again -- measured on prod as a wave that expanded on the checkout and re-collapsed 29 seconds later, with
 * nobody touching it. The stamp is a write-once fact, so losing it is never right, and the honest fix is to keep it
 * rather than to put the timestamps back on the delta row, which D-26 and D-30's seed-size bar both forbid.
 *
 * The memory is MODULE-scoped, not a ref and not state, and that is forced rather than chosen. `react-hooks/refs`
 * forbids reading a ref during render, and `react-hooks/set-state-in-effect` forbids the state version, so neither
 * React-held option is available; a module value may be written from an effect and read during render, which is
 * exactly the access pattern this needs. It is also the honest scope: these are immutable facts about records,
 * identical for every component that asks, so there is nothing per-instance about them. It costs test isolation,
 * which `__resetStampMemory` gives back.
 *
 * Monotonic: a field already held can only be replaced by a strictly newer value, so running it twice, or over rows
 * it has already seen, changes nothing.
 */
const stampMemory = new Map<string, PlanScopeTimes>()

/** Every stamp any corpus row has carried in this tab, newest per field. Read during render; written only below. */
export const recallStamps = (id: string): PlanScopeTimes | undefined => stampMemory.get(id)

/** Test seam. The memory is module-scoped on purpose (see `rememberRowStamps`), so tests must clear it themselves. */
export const __resetStampMemory = (): void => {
  stampMemory.clear()
}

function rememberRowStamps(rows: readonly { id: string; fields?: Record<string, unknown> }[]): void {
  const seen = stampMemory
  for (const row of rows) {
    const f = row.fields
    if (!f) continue
    const created = text(f.created_at)
    const firstOut = text(f.first_checked_out_at)
    const closed = text(f.closed_at)
    if (created === null && firstOut === null && closed === null) continue
    const held = seen.get(row.id)
    seen.set(row.id, {
      created_at: newest(held?.created_at, created),
      first_checked_out_at: newest(held?.first_checked_out_at, firstOut),
      closed_at: newest(held?.closed_at, closed),
    })
  }
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
  /**
   * The device cache could not be used, so this session is memory-only (@io-kit/search 1.1.3). NOT an error: rows
   * still arrive over the network and every card draws. Surfaced only so a user whose warm start silently vanished
   * can see why the first paint got slower, instead of the page looking broken for no stated reason.
   */
  storageFault: string | null
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

  /**
   * ENC-TSK-T27 (ENC-ISS-925): remember every stamp a corpus row has ever carried.
   *
   * Keyed on `corpus.rows` alone, so it runs once per corpus change rather than once per render, and it writes a ref
   * rather than state, so it triggers no render of its own -- the render that follows the live event already has the
   * value on the row itself, and this only has to make it survive the NEXT one. Rows with no stamps, which is nearly
   * all of them, cost three property reads and nothing else.
   */
  useEffect(() => {
    const rows = corpus.rows
    if (!rows || rows.length === 0) return
    rememberRowStamps(rows as readonly { id: string; fields?: Record<string, unknown> }[])
  }, [corpus.rows])

  // No useMemo: the React Compiler is active and memoizes this on [corpus.rows, times] (eslint AC-16).
  const rows: PlansRow[] = (() => {
    const out: PlansRow[] = []
    for (const row of corpus.rows ?? []) {
      const type = String((row as { type?: string }).type ?? '').toLowerCase()
      if (!LENS_TYPES.has(type)) continue
      const id = (row as { id: string }).id
      out.push(withTimes(toLensRow(row as never), times.get(id), recallStamps(id)))
    }
    return out
  })()

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
    storageFault: corpus.storageFault ?? null,
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
