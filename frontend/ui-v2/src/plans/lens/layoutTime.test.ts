import { describe, expect, it } from 'vitest'
import {
  FOLD_MINUTES,
  FOLD_SEGMENT_PCT,
  MIN_LIVE_PCT,
  NOW_SEGMENT_PCT,
  TICK_MIN_SPACING_PCT,
  TICK_STEPS_MINUTES,
  formatSkipped,
  layoutTime,
  type TimeLayout,
} from './layoutTime'

const T0 = Date.UTC(2026, 10, 19, 18, 0, 0) // 10:00 Pacific (PST)
const min = (n: number) => n * 60_000
const at = (minutes: number) => T0 + min(minutes)
const sum = (xs: readonly number[]) => xs.reduce((a, b) => a + b, 0)
const kinds = (l: TimeLayout) => l.segments.map((s) => s.kind)
const widthOf = (l: TimeLayout) => sum(l.segments.map((s) => s.widthPct))
/** Events every `every` minutes from `from` to `to` (epoch ms): one burst, because no gap exceeds the fold threshold. */
const burst = (from: number, to: number, every = 60): number[] => {
  const out: number[] = []
  for (let t = from; t < to; t += min(every)) out.push(t)
  out.push(to)
  return out
}

describe('constants of section 5.6', () => {
  it('are the ones the approved design fixed', () => {
    expect(FOLD_MINUTES).toBe(180)
    expect(FOLD_SEGMENT_PCT).toBe(4)
    expect(MIN_LIVE_PCT).toBe(6)
    expect(NOW_SEGMENT_PCT).toBe(6)
    expect([...TICK_STEPS_MINUTES]).toEqual([15, 30, 60, 120, 240, 720])
    expect(TICK_MIN_SPACING_PCT).toBe(13)
  })
})

describe('folding gaps over 180 minutes', () => {
  it('does not fold a gap of exactly 180 minutes', () => {
    const l = layoutTime([at(0), at(180)], 800)
    expect(kinds(l)).toEqual(['live'])
  })

  it('folds a gap of 181 minutes into a 4 percent break', () => {
    const l = layoutTime([at(0), at(181)], 800)
    expect(kinds(l)).toEqual(['live', 'fold', 'live'])
    expect(l.segments[1]?.widthPct).toBe(4)
  })

  it('takes the threshold from the fold argument, in minutes', () => {
    expect(kinds(layoutTime([at(0), at(61)], 800, 60))).toEqual(['live', 'fold', 'live'])
    expect(kinds(layoutTime([at(0), at(60)], 800, 60))).toEqual(['live'])
    expect(layoutTime([at(0), at(60)], 800, 60).foldMinutes).toBe(60)
  })

  it('falls back to 180 for a threshold that is not a finite, non-negative number', () => {
    for (const bad of [Number.NaN, -1, Number.POSITIVE_INFINITY]) expect(layoutTime([at(0), at(181)], 800, bad).foldMinutes).toBe(180)
  })

  it('reads a plan whose work happened in three bursts across four days: two folds, each 4 percent, the track exactly 100', () => {
    const day = 24 * 60
    const l = layoutTime([at(0), at(30), at(60), at(day + 0), at(day + 90), at(3 * day), at(3 * day + 20)], 1000)
    expect(kinds(l)).toEqual(['live', 'fold', 'live', 'fold', 'live'])
    expect(l.segments.filter((s) => s.kind === 'fold').map((s) => s.widthPct)).toEqual([4, 4])
    expect(widthOf(l)).toBeCloseTo(100, 9)
    // The live share (92 percent) follows duration: 60, 90 and 20 minutes.
    const live = l.segments.filter((s) => s.kind === 'live').map((s) => s.widthPct)
    expect(live[1]! / live[0]!).toBeCloseTo(90 / 60, 9)
    for (const w of live) expect(w).toBeGreaterThanOrEqual(6)
  })

  it('prints the skipped duration on each fold', () => {
    const l = layoutTime([at(0), at(60), at(60 + 5 * 60 + 12), at(60 + 5 * 60 + 12 + 26 * 60)], 800)
    const folds = l.segments.filter((s) => s.kind === 'fold')
    expect(folds.map((s) => s.skippedMs)).toEqual([min(5 * 60 + 12), min(26 * 60)])
    expect(folds.map((s) => s.skippedLabel)).toEqual(['5h 12m', '1d 2h'])
    expect(l.segments.filter((s) => s.kind !== 'fold').every((s) => s.skippedLabel === null)).toBe(true)
  })

  it('formats skipped durations', () => {
    expect(formatSkipped(min(45))).toBe('45m')
    expect(formatSkipped(min(181))).toBe('3h 1m')
    expect(formatSkipped(min(180))).toBe('3h')
    expect(formatSkipped(min(48 * 60))).toBe('2d')
    expect(formatSkipped(min(49 * 60 + 30))).toBe('2d 1h')
    expect(formatSkipped(0)).toBe('0m')
  })
})

describe('live segments', () => {
  it('a segment is never narrower than 6 percent, even a burst of a single instant', () => {
    const l = layoutTime([at(0), at(600), at(601), at(1200), at(1201), at(1202), at(1203), at(1500), at(1501)], 800)
    const live = l.segments.filter((s) => s.kind === 'live')
    expect(live.length).toBeGreaterThan(1)
    for (const s of live) expect(s.widthPct).toBeGreaterThanOrEqual(6 - 1e-9)
    expect(widthOf(l)).toBeCloseTo(100, 9)
  })

  it('shares the remainder equally when every burst is an instant', () => {
    const l = layoutTime([at(0), at(1000), at(2000)], 800)
    for (const s of l.segments.filter((x) => x.kind === 'live')) expect(s.widthPct).toBeCloseTo(92 / 3, 9)
  })

  it('a lone event is one segment of the whole track, drawn at its middle', () => {
    const l = layoutTime([at(5)], 800)
    expect(l.segments).toHaveLength(1)
    expect(l.segments[0]?.widthPct).toBe(100)
    expect(l.toPct(at(5))).toBe(50)
  })

  it('scales every segment alike when the constants cannot all fit, so the track is still 100 percent', () => {
    const times = Array.from({ length: 20 }, (_, i) => at(i * 1000))
    const l = layoutTime(times, 800)
    expect(l.segments).toHaveLength(39)
    expect(widthOf(l)).toBeCloseTo(100, 9)
    const [live, fold] = [l.segments[0]!.widthPct, l.segments[1]!.widthPct]
    // The 6:4 ratio of a minimum live segment to a fold survives the scaling (196 raw percent scaled to 100).
    expect(live / fold).toBeCloseTo(6 / 4, 9)
    expect(l.segments.filter((s) => s.kind === 'fold').every((s) => Math.abs(s.widthPct - fold) < 1e-9)).toBe(true)
  })

  it('is contiguous: each segment starts where the previous one ends', () => {
    const l = layoutTime([at(0), at(90), at(700), at(730), at(2000)], 800, 180, at(2050))
    let cursor = 0
    for (const s of l.segments) {
      expect(s.startPct).toBeCloseTo(cursor, 9)
      cursor += s.widthPct
    }
    expect(cursor).toBeCloseTo(100, 9)
  })
})

describe('an open bar ends in a 6 percent segment labelled now', () => {
  it('the now segment is 6 percent, labelled now, the last one, and now sits at 100', () => {
    const l = layoutTime([at(0), at(60)], 800, 180, at(100))
    expect(kinds(l)).toEqual(['live', 'now'])
    const now = l.segments.at(-1)
    expect(now?.widthPct).toBe(6)
    expect(now?.label).toBe('now')
    expect(l.hasNow).toBe(true)
    expect(l.toPct(at(100))).toBeCloseTo(100, 9)
    expect(widthOf(l)).toBeCloseTo(100, 9)
  })

  it('a layout without an open bar has no now segment', () => {
    const l = layoutTime([at(0), at(60)], 800)
    expect(l.hasNow).toBe(false)
    expect(l.segments.some((s) => s.kind === 'now' || s.label === 'now')).toBe(false)
  })

  it('folds the gap to now when the last event is more than 180 minutes old, then ends in the now segment', () => {
    const l = layoutTime([at(0), at(60)], 800, 180, at(60 + 400))
    expect(kinds(l)).toEqual(['live', 'fold', 'now'])
    expect(l.segments[1]).toMatchObject({ widthPct: 4, skippedLabel: '6h 40m' })
    expect(l.segments[2]?.widthPct).toBe(6)
    expect(l.toPct(at(460))).toBeCloseTo(100, 9)
  })

  it('a clock earlier than the last event cannot pull the now edge back', () => {
    const l = layoutTime([at(0), at(60)], 800, 180, at(10))
    expect(kinds(l)).toEqual(['live', 'now'])
    expect(l.toPct(at(60))).toBeCloseTo(l.segments[0]!.widthPct, 9)
  })

  it('moving now forward within the threshold moves only the cap, not the earlier segments', () => {
    const a = layoutTime([at(0), at(60)], 800, 180, at(70))
    const b = layoutTime([at(0), at(60)], 800, 180, at(160))
    expect(a.segments[0]?.widthPct).toBeCloseTo(b.segments[0]?.widthPct as number, 9)
    expect(a.toPct(at(60))).toBeCloseTo(b.toPct(at(60)), 9)
  })
})

describe('positions', () => {
  const l = layoutTime([at(0), at(100), at(400), at(450)], 800)

  it('is monotonic and inside 0 to 100 for every instant in the span', () => {
    let last = -1
    for (let m = -30; m <= 500; m += 5) {
      const p = l.toPct(at(m))
      expect(p).toBeGreaterThanOrEqual(0)
      expect(p).toBeLessThanOrEqual(100)
      expect(p).toBeGreaterThanOrEqual(last - 1e-9)
      last = p
    }
  })

  it('puts the first event at 0 and the last at 100, and clamps outside the span', () => {
    expect(l.toPct(at(0))).toBe(0)
    expect(l.toPct(at(450))).toBeCloseTo(100, 9)
    expect(l.toPct(at(-1000))).toBe(0)
    expect(l.toPct(at(99999))).toBe(100)
  })

  it('is linear inside a live segment', () => {
    const first = l.segments[0]!
    expect(l.toPct(at(50))).toBeCloseTo(first.startPct + first.widthPct / 2, 9)
  })

  it('derives pixels from the track width', () => {
    expect(l.toPx(at(450))).toBeCloseTo(800, 9)
    expect(l.widthPx).toBe(800)
    for (const s of l.segments) {
      expect(s.startPx).toBeCloseTo((s.startPct * 800) / 100, 9)
      expect(s.widthPx).toBeCloseTo((s.widthPct * 800) / 100, 9)
    }
  })

  it('a missing or invalid width gives zero pixels and leaves percentages alone', () => {
    for (const w of [0, -5, Number.NaN]) {
      const x = layoutTime([at(0), at(100)], w)
      expect(x.widthPx).toBe(0)
      expect(x.toPx(at(50))).toBe(0)
      expect(x.toPct(at(100))).toBeCloseTo(100, 9)
    }
  })

  it('accepts ISO strings, numbers and Dates, ignores invalid and duplicate events', () => {
    const iso = (m: number) => new Date(at(m)).toISOString()
    const x = layoutTime([iso(0), at(100), new Date(at(100)), 'not a time', Number.NaN, iso(0)], 800)
    expect(x.segments).toHaveLength(1)
    expect(x.toPct(iso(100))).toBeCloseTo(100, 9)
    expect(x.toPct('garbage')).toBe(0)
  })

  it('has no segments for no events, and does not throw', () => {
    const x = layoutTime([], 800, 180, at(0))
    expect(x.segments).toEqual([])
    expect(x.hasNow).toBe(false)
    expect(x.toPct(at(0))).toBe(0)
  })

  it('does not depend on the order of the events', () => {
    const ev = [at(0), at(100), at(400), at(450)]
    const a = layoutTime(ev, 800)
    const b = layoutTime([...ev].reverse(), 800)
    expect(b.segments.map((s) => [s.kind, s.startMs, s.endMs, s.widthPct])).toEqual(a.segments.map((s) => [s.kind, s.startMs, s.endMs, s.widthPct]))
  })
})

describe('ticks', () => {
  it('chooses, per segment, the smallest step whose labels sit at least 13 percent apart', () => {
    // 30 minutes over 100 percent: 15 minutes is already 50 percent apart.
    expect(layoutTime([at(0), at(30)], 800).segments[0]?.stepMinutes).toBe(15)
    // 360 minutes over 100 percent: 60 minutes is 16.7 percent apart, 30 is 8.3 percent.
    expect(layoutTime(burst(at(0), at(360)), 800).segments[0]?.stepMinutes).toBe(60)
    // 180 minutes over 100 percent: 30 minutes is 16.7 percent apart, 15 is 8.3 percent.
    expect(layoutTime([at(0), at(90), at(180)], 800).segments[0]?.stepMinutes).toBe(30)
  })

  it('falls back to the largest step when no step reaches 13 percent', () => {
    const l = layoutTime(burst(at(0), at(60 * 24 * 40), 180), 800)
    expect(l.segments).toHaveLength(1)
    expect(l.segments[0]?.stepMinutes).toBe(720)
  })

  it('keeps tick labels at least 13 percent apart inside every segment it can (steps 15 to 720)', () => {
    for (const span of [20, 45, 90, 180, 360, 700, 1500]) {
      const l = layoutTime(burst(at(0), at(span), 15), 800)
      expect(l.segments).toHaveLength(1)
      for (const s of l.segments) {
        if (s.stepMinutes === null || s.stepMinutes === 720) continue
        for (let i = 1; i < s.ticks.length; i += 1) expect(s.ticks[i]!.pct - s.ticks[i - 1]!.pct, `span ${span}`).toBeGreaterThanOrEqual(13 - 1e-9)
      }
    }
  })

  it('aligns ticks to Pacific wall-clock time in winter (PST, UTC-8)', () => {
    // 10:30 to 16:30 Pacific on 2026-11-19.
    const l = layoutTime(burst(Date.UTC(2026, 10, 19, 18, 30), Date.UTC(2026, 10, 20, 0, 30)), 800)
    const s = l.segments[0]!
    expect(s.stepMinutes).toBe(60)
    expect(s.ticks.map((t) => t.label)).toEqual(['11:00', '12:00', '13:00', '14:00', '15:00', '16:00'])
    expect(s.ticks.every((t) => t.date === '2026-11-19')).toBe(true)
  })

  it('aligns ticks to Pacific wall-clock time in summer (PDT, UTC-7), not to UTC', () => {
    // 05:00 to 17:00 Pacific on 2026-07-01: 120-minute steps land on even PACIFIC hours, which are odd UTC hours.
    const l = layoutTime(burst(Date.UTC(2026, 6, 1, 12, 0), Date.UTC(2026, 6, 2, 0, 0)), 800)
    const s = l.segments[0]!
    expect(s.stepMinutes).toBe(120)
    expect(s.ticks.map((t) => t.label)).toEqual(['06:00', '08:00', '10:00', '12:00', '14:00', '16:00'])
    expect(s.ticks.map((t) => new Date(t.at).getUTCHours())).toEqual([13, 15, 17, 19, 21, 23])
  })

  it('puts each tick at its own position on the track and inside its segment', () => {
    const l = layoutTime(burst(at(0), at(360)), 800)
    const s = l.segments[0]!
    expect(s.ticks.length).toBeGreaterThan(3)
    for (const t of s.ticks) {
      expect(t.pct).toBeCloseTo(l.toPct(t.at), 9)
      expect(t.pct).toBeGreaterThanOrEqual(s.startPct)
      expect(t.pct).toBeLessThanOrEqual(s.startPct + s.widthPct)
    }
  })

  it('labels a tick after midnight Pacific with the new date', () => {
    // 23:00 Pacific on 2026-11-19 to 02:00 on the 20th (07:00Z to 10:00Z).
    const l = layoutTime(burst(Date.UTC(2026, 10, 20, 7, 0), Date.UTC(2026, 10, 20, 10, 0), 30), 800)
    const s = l.segments[0]!
    expect(s.stepMinutes).toBe(30)
    expect(s.ticks.map((t) => `${t.date} ${t.label}`)).toEqual([
      '2026-11-19 23:00', '2026-11-19 23:30', '2026-11-20 00:00', '2026-11-20 00:30', '2026-11-20 01:00', '2026-11-20 01:30', '2026-11-20 02:00',
    ])
  })

  it('draws no ticks on a fold, and none on an instant', () => {
    const l = layoutTime([at(0), at(500), at(501)], 800)
    for (const s of l.segments) {
      if (s.kind === 'fold') expect([s.stepMinutes, s.ticks]).toEqual([null, []])
    }
    const lone = layoutTime([at(0)], 800)
    expect(lone.segments[0]).toMatchObject({ stepMinutes: null, ticks: [] })
  })

  it('is deterministic: the same input gives the same layout', () => {
    const a = layoutTime([at(0), at(100), at(900)], 640, 180, at(1000))
    const b = layoutTime([at(0), at(100), at(900)], 640, 180, at(1000))
    expect(b.segments).toEqual(a.segments)
  })
})
