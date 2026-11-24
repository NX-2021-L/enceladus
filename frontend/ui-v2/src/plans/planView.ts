/**
 * ENC-TSK-S98-0B (ENC-PLN-108 W3.2): the view model of one plan card, DOC-5E1E205FA664 sections 5.5 to 5.7.
 *
 * Pure glue over the W3.1 lens: `resolveWaves` groups the objectives, `waveStatus` gives each wave its state and hotness,
 * `layoutTime` places every stamp on one folded time scale. Nothing here reads a clock (the caller passes `now`) and
 * nothing is remembered, so a cold load and a live session end on the same picture (invariant 7).
 *
 * Positions are percentages of the track, 0 to 100, exactly what the approved canvas writes into its inline styles.
 */
import { statusRole, type StatusRole } from '../status/statusRole'
import { formatDay, formatStamp, formatStampZone, toMs } from './format'
import { formatSkipped, layoutTime, type TimeInput, type TimeLayout } from './lens/layoutTime'
import { resolveWaves } from './lens/resolveWaves'
import type { LensRow } from './lens/types'
import { isCheckedOut, isTerminal, waveStatus, type WaveFacts, type WaveState, type WaveTaskFacts } from './lens/waveState'

/** One corpus row as the page reads it: the lens row, the task facts of waveState, and the close stamp. */
export type PlansRow = LensRow & WaveTaskFacts & { closed_at?: string | null }

/** Heading of the Unassigned group, which the page draws as a wave tagged `none` after every wave (D-20). */
export const UNASSIGNED_TITLE = 'Unassigned: no wave label and no wave number in the title'
export const UNASSIGNED_TAG = 'none'
export const UNASSIGNED_KEY = 'unassigned'

export interface Bar {
  leftPct: number
  widthPct: number
  /** The bar has no close yet: it fades toward now. */
  open: boolean
}

export interface TaskView {
  id: string
  title: string
  status: string | null
  /** The task's status role: the colour of its bar and nothing else (priority and record type never touch it). */
  role: StatusRole
  tip: string
  /** The creation ring; null when the row has no usable created_at. */
  createdPct: number | null
  wait: Bar | null
  work: (Bar & { role: StatusRole }) | null
  closedPct: number | null
  waitText: string
  workText: string
  /** Checked out before the backfill, so no stamps: the status pill stands in for the bar (invariant 6). */
  showStatusPill: boolean
}

export interface WaveView {
  /** `<plan id>/<wave key>`: the key a manual toggle is remembered under. */
  key: string
  tag: string
  parentId: string | null
  title: string
  state: WaveState
  hot: boolean
  settling: boolean
  closed: number
  total: number
  tally: string
  ariaLabel: (open: boolean) => string
  /** The inputs of waveState, kept so a toggle can be recorded and judged against the wave as it now is. */
  facts: WaveFacts
  band: Bar | null
  windowText: string
  tasks: TaskView[]
  unassigned: boolean
}

export interface AxisDay {
  label: string
  /** Placed from the left edge; the `now` label is placed from the right instead. */
  leftPct: number | null
}
export interface AxisTick {
  label: string
  leftPct: number
  /** The skipped duration printed on a fold. */
  fold: boolean
}
export interface AxisView {
  days: AxisDay[]
  ticks: AxisTick[]
  gridsPct: number[]
  gaps: { leftPct: number; widthPct: number }[]
  hasNow: boolean
}

export interface PlanStats {
  nTasks: number
  nWaves: number
  nClosed: number
  /** Two or more tasks have a checkout and a close: only then are the span and the medians meaningful. */
  hasStats: boolean
  span: string
  medianWait: string
  medianWork: string
}

export interface PlanView {
  id: string
  project: string
  status: string
  title: string
  createdAt: string | null
  createdText: string
  /** Non-task objectives: code tags on the plan header (D-7). */
  chips: string[]
  /** Objectives with no row in the corpus (their type is unknown). */
  missing: number
  stats: PlanStats
  waves: WaveView[]
  axis: AxisView
}

const median = (xs: readonly number[]): number | null => {
  if (xs.length === 0) return null
  const s = [...xs].sort((a, b) => a - b)
  const i = s.length >> 1
  return s.length % 2 ? (s[i] as number) : ((s[i - 1] as number) + (s[i] as number)) / 2
}

const dur = (ms: number): string => formatSkipped(Math.max(0, ms))

/** Plan statuses on which a hot wave expands and a waiting task shows its dashed wait line (R7). */
const STARTED: ReadonlySet<string> = new Set(['started', 'incomplete'])
const isStarted = (status: string | null | undefined): boolean => STARTED.has((status ?? '').trim().toLowerCase().replace(/_/g, '-'))

/** The group a wave row is drawn from, before its marks are placed. */
interface Group {
  key: string
  tag: string
  title: string
  parentId: string | null
  unassigned: boolean
  parent: PlansRow | null
  members: PlansRow[]
}

const placementTitle = (placement: string): string =>
  placement === 'label' ? 'grouped by wave label' : placement === 'title' ? 'grouped by objective title' : ''

export function buildPlanView(plan: PlansRow, rows: readonly PlansRow[], now: TimeInput): PlanView {
  const resolved = resolveWaves(plan, rows)
  const byId = new Map<string, PlansRow>()
  for (const row of rows) if (!byId.has(row.item_id)) byId.set(row.item_id, row)
  const get = (id: string): PlansRow | null => byId.get(id) ?? null
  const present = (ids: readonly string[]): PlansRow[] => ids.flatMap((id) => get(id) ?? [])

  const groups: Group[] = resolved.waves.map((w) => {
    const parent = w.parent_id ? get(w.parent_id) : null
    return {
      key: w.key,
      tag: w.label,
      title: parent ? (parent.title ?? parent.item_id) : placementTitle(w.placement),
      parentId: w.parent_id,
      unassigned: false,
      parent,
      members: present(w.members),
    }
  })
  if (resolved.unassigned.length > 0) {
    groups.push({ key: UNASSIGNED_KEY, tag: UNASSIGNED_TAG, title: UNASSIGNED_TITLE, parentId: null, unassigned: true, parent: null, members: present(resolved.unassigned) })
  }

  const members = groups.flatMap((g) => g.members)
  const closedAtOf = (t: PlansRow): number | null => (isTerminal(t) ? toMs(t.closed_at) : null)
  const checkoutOf = (t: PlansRow): number | null => toMs(t.first_checked_out_at)

  // Events on the scale: creation, first checkout and close of every member, and the close of every wave parent.
  const events: number[] = []
  for (const t of members) {
    for (const v of [toMs(t.created_at), checkoutOf(t), closedAtOf(t)]) if (v !== null) events.push(v)
  }
  for (const g of groups) {
    const z = g.parent ? closedAtOf(g.parent) : null
    if (z !== null) events.push(z)
  }
  // An open bar (checked out, not closed) runs to now, so the scale ends in the `now` segment.
  const anyOpenBar = members.some((t) => checkoutOf(t) !== null && !isTerminal(t))
  const nowMs = toMs(now)
  const layout = layoutTime(events, 0, undefined, anyOpenBar && nowMs !== null ? nowMs : null)
  const at = (ms: number): number => layout.toPct(ms)

  const started = isStarted(plan.status)

  const taskView = (t: PlansRow): TaskView => {
    const c = toMs(t.created_at)
    const co = checkoutOf(t)
    const z = closedAtOf(t)
    const fin = isTerminal(t)
    const role = statusRole('task', t.status)
    // Waiting means not yet checked out: a task that is in flight without a stamp (before the backfill) is not waiting.
    const waitOpen = c !== null && co === null && started && !fin && !isCheckedOut(t)
    const hasWork = co !== null && (z !== null || !fin)
    const cPct = c === null ? null : at(c)
    const tipParts = [
      t.status ?? 'no status',
      c !== null ? `created ${formatStamp(c)}` : null,
      co !== null ? `first checkout ${formatStamp(co)}` : null,
      z !== null ? `closed ${formatStamp(z)}` : null,
    ].filter((p): p is string => p !== null)
    return {
      id: t.item_id,
      title: t.title ?? t.item_id,
      status: t.status ?? null,
      role,
      tip: tipParts.join(' · '),
      createdPct: cPct,
      wait:
        cPct !== null && (co !== null || waitOpen)
          ? { leftPct: cPct, widthPct: (co !== null ? at(co) : 100) - cPct, open: waitOpen }
          : null,
      work:
        co !== null && hasWork
          ? { leftPct: at(co), widthPct: (z !== null ? at(z) : 100) - at(co), open: z === null, role }
          : null,
      closedPct: z !== null ? at(z) : null,
      waitText: c !== null && co !== null ? dur(co - c) : '',
      workText: co !== null && z !== null ? dur(z - co) : co !== null && hasWork ? 'open' : '',
      showStatusPill: co === null && isCheckedOut(t),
    }
  }

  const waves: WaveView[] = groups.map((g) => {
    const facts: WaveFacts = { parent: g.parent, members: g.members }
    const st = waveStatus(facts)
    const closed = g.members.filter(isTerminal).length
    const total = g.members.length
    const checkouts = g.members.flatMap((t) => checkoutOf(t) ?? [])
    const a = checkouts.length > 0 ? Math.min(...checkouts) : null
    const closes = [...g.members.map(closedAtOf), g.parent ? closedAtOf(g.parent) : null].filter((v): v is number => v !== null)
    // A hot wave's window runs to now; otherwise to its last close, or it is a point when nothing has closed.
    const b = a === null ? null : st.hot && nowMs !== null ? nowMs : closes.length > 0 ? Math.max(...closes) : a
    const band: Bar | null =
      a !== null && b !== null ? { leftPct: at(a), widthPct: Math.max(0, at(Math.max(a, b)) - at(a)), open: st.hot } : null
    const ariaTail = st.settling ? ', waiting for its parent to close' : ''
    return {
      key: `${plan.item_id}/${g.key}`,
      tag: g.tag,
      parentId: g.parentId,
      title: g.title,
      state: st.state,
      hot: st.hot,
      settling: st.settling,
      closed,
      total,
      tally: total > 0 ? `${closed} of ${total}` : 'no tasks',
      ariaLabel: (open) => `${open ? 'Collapse' : 'Expand'} wave ${g.tag}, ${st.state}, ${closed} of ${total} closed${ariaTail}`,
      facts,
      band,
      windowText: a === null || b === null ? '' : st.hot ? 'open' : dur(b - a),
      tasks: g.members.map(taskView),
      unassigned: g.unassigned,
    }
  })

  const waits = members.flatMap((t) => {
    const c = toMs(t.created_at)
    const co = checkoutOf(t)
    return c !== null && co !== null ? co - c : []
  })
  const works = members.flatMap((t) => {
    const co = checkoutOf(t)
    const z = closedAtOf(t)
    return co !== null && z !== null ? z - co : []
  })
  const lastEvent = events.length > 0 ? Math.max(...events) : null
  const firstEvent = events.length > 0 ? Math.min(...events) : null
  const created = toMs(plan.created_at)

  return {
    id: plan.item_id,
    project: plan.project_id ?? '',
    status: plan.status ?? '',
    title: plan.title ?? plan.item_id,
    createdAt: plan.created_at ?? null,
    createdText: created === null ? '' : formatStampZone(created),
    chips: resolved.chips,
    missing: resolved.missing.length,
    stats: {
      nTasks: members.length,
      nWaves: waves.length,
      nClosed: members.filter(isTerminal).length,
      hasStats: works.length > 1,
      span: lastEvent !== null && firstEvent !== null ? dur(lastEvent - firstEvent) : '',
      medianWait: dur(median(waits) ?? 0),
      medianWork: dur(median(works) ?? 0),
    },
    waves,
    axis: axisOf(layout),
  }
}

/** Day labels, ticks, grid lines, folded gaps and the now edge, from the layout's segments. */
export function axisOf(layout: TimeLayout): AxisView {
  const days: AxisDay[] = []
  const ticks: AxisTick[] = []
  const gridsPct: number[] = []
  const gaps: { leftPct: number; widthPct: number }[] = []
  let previousDay: string | null = null
  for (const seg of layout.segments) {
    if (seg.kind === 'fold') {
      gaps.push({ leftPct: seg.startPct, widthPct: seg.widthPct })
      ticks.push({ label: seg.skippedLabel ?? '', leftPct: seg.startPct + seg.widthPct / 2, fold: true })
      continue
    }
    if (seg.kind === 'now') {
      days.push({ label: 'now', leftPct: null })
    } else {
      const label = formatDay(seg.startMs)
      if (label !== previousDay) days.push({ label, leftPct: seg.startPct })
      previousDay = label
    }
    for (const tick of seg.ticks) {
      ticks.push({ label: tick.label, leftPct: tick.pct, fold: false })
      gridsPct.push(tick.pct)
    }
  }
  return { days, ticks, gridsPct, gaps, hasNow: layout.hasNow }
}
