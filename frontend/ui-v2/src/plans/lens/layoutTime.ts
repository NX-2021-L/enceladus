/**
 * ENC-TSK-S98-0A (ENC-PLN-108 W3.1): layoutTime, DOC-5E1E205FA664 section 5.6 item 4.
 *
 * The piecewise-linear time scale proven in the prototype. Idle gaps longer than a threshold fold to a fixed-width break
 * with the skipped duration printed, so a plan whose work happened in three bursts across four days stays readable. Pure:
 * it reads no clock (the caller passes `now` when a bar is open) and does no I/O. Positions are percentages of the track;
 * pixel positions are derived from `width`.
 *
 * Constants fixed by the approved design for version 1 (section 5.6):
 *   fold threshold      180 minutes, a gap strictly longer than this folds (no user control, ruling D-18)
 *   folded gap          4 percent of the track, prints the skipped duration
 *   live segment        never narrower than 6 percent
 *   open bar            the plan ends in a 6 percent segment labelled now
 *   tick steps          15, 30, 60, 120, 240 and 720 minutes, chosen per segment so labels sit at least 13 percent apart
 *   tick alignment      Pacific wall-clock time (ruling D-19)
 *
 * When there are more bursts than the constants can satisfy at once (100 percent is not enough for the fixed widths), every
 * segment is scaled by the same factor so the track is still exactly 100 percent.
 */

export const FOLD_MINUTES = 180
export const FOLD_SEGMENT_PCT = 4
export const MIN_LIVE_PCT = 6
export const NOW_SEGMENT_PCT = 6
export const TICK_STEPS_MINUTES = [15, 30, 60, 120, 240, 720] as const
export const TICK_MIN_SPACING_PCT = 13
export const TICK_TIME_ZONE = 'America/Los_Angeles'

export type TimeInput = string | number | Date

export interface TimeTick {
  /** Epoch ms. */
  at: number
  pct: number
  /** Pacific wall clock, HH:mm. */
  label: string
  /** Pacific calendar date, YYYY-MM-DD, so a renderer can mark the day change. */
  date: string
}

export type TimeSegmentKind = 'live' | 'fold' | 'now'

export interface TimeSegment {
  kind: TimeSegmentKind
  startMs: number
  endMs: number
  startPct: number
  widthPct: number
  startPx: number
  widthPx: number
  /** Chosen tick step for a live or now segment that spans time; null otherwise. */
  stepMinutes: number | null
  ticks: TimeTick[]
  /** Fold segments: the skipped duration, for the tick line. */
  skippedMs: number | null
  skippedLabel: string | null
  /** The now segment is labelled `now`. */
  label: 'now' | null
}

export interface TimeLayout {
  segments: TimeSegment[]
  foldMinutes: number
  /** The track width the pixel fields were computed for; 0 when none was given. */
  widthPx: number
  hasNow: boolean
  /** Position of an instant on the track, 0 to 100. Instants outside the span clamp to the ends. */
  toPct: (at: TimeInput) => number
  toPx: (at: TimeInput) => number
}

const MIN = 60_000

const toMs = (t: TimeInput): number => (t instanceof Date ? t.getTime() : typeof t === 'number' ? t : Date.parse(t))

let zoneFormat: Intl.DateTimeFormat | undefined
const zone = (): Intl.DateTimeFormat =>
  (zoneFormat ??= new Intl.DateTimeFormat('en-US', {
    timeZone: TICK_TIME_ZONE,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }))

const wallClock = (ms: number) => {
  const p: Record<string, string> = {}
  for (const part of zone().formatToParts(new Date(ms))) p[part.type] = part.value
  return { year: p.year ?? '', month: p.month ?? '', day: p.day ?? '', hour: p.hour ?? '', minute: p.minute ?? '', second: p.second ?? '' }
}

/** Pacific offset from UTC at an instant, in ms (negative). Deterministic: it reads the zone rules, not the clock. */
const pacificOffsetMs = (ms: number): number => {
  const w = wallClock(ms)
  const local = Date.UTC(Number(w.year), Number(w.month) - 1, Number(w.day), Number(w.hour), Number(w.minute), Number(w.second))
  return local - Math.floor(ms / 1000) * 1000
}

/** "3h 1m", "2d 4h", "45m": the skipped duration printed on a fold. */
export function formatSkipped(ms: number): string {
  const totalMin = Math.max(0, Math.floor(ms / MIN))
  const d = Math.floor(totalMin / 1440)
  const h = Math.floor((totalMin % 1440) / 60)
  const m = totalMin % 60
  const parts: string[] = []
  if (d > 0) {
    parts.push(`${d}d`)
    if (h > 0) parts.push(`${h}h`)
  } else if (h > 0) {
    parts.push(`${h}h`)
    if (m > 0) parts.push(`${m}m`)
  } else {
    parts.push(`${m}m`)
  }
  return parts.join(' ')
}

/** Split `remaining` percent among live segments in proportion to duration, none narrower than `min` (water-filling). */
function allocateLive(durations: readonly number[], remaining: number, min: number): number[] {
  const widths = new Array<number>(durations.length).fill(0)
  const locked = new Set<number>()
  for (;;) {
    const free = durations.map((_, i) => i).filter((i) => !locked.has(i))
    if (free.length === 0) break
    const pool = remaining - locked.size * min
    const sum = free.reduce((a, i) => a + (durations[i] as number), 0)
    const share = (i: number): number => (sum > 0 ? (pool * (durations[i] as number)) / sum : pool / free.length)
    const under = free.filter((i) => share(i) < min)
    if (under.length === 0) {
      for (const i of free) widths[i] = share(i)
      break
    }
    for (const i of under) {
      locked.add(i)
      widths[i] = min
    }
  }
  return widths
}

/** Ticks at multiples of `stepMin` of Pacific wall-clock time inside [startMs, endMs]. */
function ticksFor(startMs: number, endMs: number, stepMin: number, pctOf: (ms: number) => number): TimeTick[] {
  const stepMs = stepMin * MIN
  const out: TimeTick[] = []
  const startOffset = pacificOffsetMs(startMs)
  let k = Math.ceil((startMs + startOffset) / stepMs)
  for (let guard = 0; guard < 1000; guard += 1, k += 1) {
    const local = k * stepMs
    // Resolve the offset at the tick itself so a DST change inside a long burst does not shift the labels.
    const at = local - pacificOffsetMs(local - startOffset)
    if (at > endMs) break
    if (at < startMs) continue
    const w = wallClock(at)
    out.push({ at, pct: pctOf(at), label: `${w.hour}:${w.minute}`, date: `${w.year}-${w.month}-${w.day}` })
  }
  return out
}

/**
 * @param events instants that matter on the plan: creations, first checkouts and closes of its tasks
 * @param width track width in pixels, used only for the pixel fields
 * @param fold gap threshold in minutes; defaults to FOLD_MINUTES (there is no user control, ruling D-18)
 * @param now when a bar is open, the current time: the layout then ends in the 6 percent `now` segment
 */
export function layoutTime(events: readonly TimeInput[], width: number, fold: number = FOLD_MINUTES, now: TimeInput | null = null): TimeLayout {
  const foldMinutes = Number.isFinite(fold) && fold >= 0 ? fold : FOLD_MINUTES
  const foldMs = foldMinutes * MIN
  const widthPx = Number.isFinite(width) && width > 0 ? width : 0
  const times = [...new Set(events.map(toMs).filter((t) => Number.isFinite(t)))].sort((a, b) => a - b)
  const nowMs = now === null ? null : toMs(now)

  type Raw = { kind: TimeSegmentKind; startMs: number; endMs: number }
  const raw: Raw[] = []
  let hasNow = false

  if (times.length > 0) {
    let burstStart = times[0] as number
    let prev = burstStart
    for (const t of times.slice(1)) {
      if (t - prev > foldMs) {
        raw.push({ kind: 'live', startMs: burstStart, endMs: prev }, { kind: 'fold', startMs: prev, endMs: t })
        burstStart = t
      }
      prev = t
    }
    raw.push({ kind: 'live', startMs: burstStart, endMs: prev })
    if (nowMs !== null && Number.isFinite(nowMs)) {
      // The clock only ever moves the now edge; it cannot pull the edge before the last event.
      const end = Math.max(nowMs, prev)
      hasNow = true
      if (end - prev > foldMs) raw.push({ kind: 'fold', startMs: prev, endMs: end })
      raw.push({ kind: 'now', startMs: end - prev > foldMs ? end : prev, endMs: end })
    }
  }

  const fixed = raw.reduce((a, s) => a + (s.kind === 'fold' ? FOLD_SEGMENT_PCT : s.kind === 'now' ? NOW_SEGMENT_PCT : 0), 0)
  const liveIdx = raw.flatMap((s, i) => (s.kind === 'live' ? [i] : []))
  const liveWidths = allocateLive(
    liveIdx.map((i) => (raw[i] as Raw).endMs - (raw[i] as Raw).startMs),
    100 - fixed,
    MIN_LIVE_PCT,
  )
  const widths = raw.map((s, i) => (s.kind === 'fold' ? FOLD_SEGMENT_PCT : s.kind === 'now' ? NOW_SEGMENT_PCT : (liveWidths[liveIdx.indexOf(i)] as number)))
  const total = widths.reduce((a, w) => a + w, 0)
  const scale = total > 100 ? 100 / total : 1

  const segments: TimeSegment[] = []
  let cursor = 0
  raw.forEach((s, i) => {
    const widthPct = (widths[i] as number) * scale
    segments.push({
      kind: s.kind,
      startMs: s.startMs,
      endMs: s.endMs,
      startPct: cursor,
      widthPct,
      startPx: (cursor * widthPx) / 100,
      widthPx: (widthPct * widthPx) / 100,
      stepMinutes: null,
      ticks: [],
      skippedMs: s.kind === 'fold' ? s.endMs - s.startMs : null,
      skippedLabel: s.kind === 'fold' ? formatSkipped(s.endMs - s.startMs) : null,
      label: s.kind === 'now' ? 'now' : null,
    })
    cursor += widthPct
  })

  const locate = (ms: number): number => {
    if (segments.length === 0) return 0
    // Prefer a live or now segment: an instant on the edge of a fold belongs to the work beside it, and a lone event sits
    // in the middle of its 6 percent segment.
    const seg =
      segments.find((s) => s.kind !== 'fold' && ms >= s.startMs && ms <= s.endMs) ?? segments.find((s) => ms >= s.startMs && ms <= s.endMs)
    if (!seg) return ms < (segments[0] as TimeSegment).startMs ? 0 : 100
    if (seg.endMs === seg.startMs) return seg.startPct + (seg.kind === 'now' ? seg.widthPct : seg.widthPct / 2)
    return seg.startPct + (seg.widthPct * (ms - seg.startMs)) / (seg.endMs - seg.startMs)
  }

  for (const s of segments) {
    if (s.kind === 'fold' || s.endMs <= s.startMs) continue
    const pctPerMinute = s.widthPct / ((s.endMs - s.startMs) / MIN)
    s.stepMinutes = TICK_STEPS_MINUTES.find((step) => step * pctPerMinute >= TICK_MIN_SPACING_PCT) ?? (TICK_STEPS_MINUTES.at(-1) as number)
    s.ticks = ticksFor(s.startMs, s.endMs, s.stepMinutes, (ms) => s.startPct + (s.widthPct * (ms - s.startMs)) / (s.endMs - s.startMs))
  }

  const toPct = (at: TimeInput): number => {
    const ms = toMs(at)
    return Number.isFinite(ms) ? locate(ms) : 0
  }
  return { segments, foldMinutes, widthPx, hasNow, toPct, toPx: (at) => (toPct(at) * widthPx) / 100 }
}
