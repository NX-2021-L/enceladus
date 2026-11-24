/**
 * ENC-TSK-S98-0A (ENC-PLN-108 W3.1): wave state and default expansion, DOC-5E1E205FA664 section 5.5.
 *
 * For a task t, co(t) is first_checked_out_at. For a wave w with member tasks M(w) (all descendants, the parent excluded)
 * and optional parent p(w):
 *
 *   touched(w)  = some t in M(w) has co(t)
 *   hot(w)      = some t in M(w) has co(t) and open(t)
 *   resolved(w) = p(w) exists ? status(p(w)) = closed : M(w) is non-empty and every t in M(w) is terminal
 *   state(w)    = done    if resolved(w)
 *                 active  if touched(w) and not resolved(w)
 *                 todo    otherwise
 *   expanded_default(w) = plan.status in {started, incomplete} and hot(w) and state(w) != done
 *   shown(w)    = override(w) if the user set one since the last change of state(w) or hot(w), else expanded_default(w)
 *
 * Pure: state is recomputed from the rows every time and never remembered, so regression is legal (invariant 7): a task
 * that re-enters after close, or a wave whose parent is reopened, redraws as active.
 */
import { statusRole } from '../../status/statusRole'

export type WaveState = 'todo' | 'active' | 'done'

/** What the lens reads of a task. Every field is optional: a row without stamps is legal (invariant 6). */
export interface WaveTaskFacts {
  status?: string | null
  /** co(t). Absent before the backfill, and on tasks that were never checked out. */
  first_checked_out_at?: string | null
  checkout_state?: string | null
}

export interface WaveFacts {
  /** p(w): the wave parent, when the wave has one. */
  parent?: WaveTaskFacts | null
  /** M(w): the members, the parent excluded. */
  members: readonly WaveTaskFacts[]
}

export interface WaveStatus {
  touched: boolean
  hot: boolean
  resolved: boolean
  /** Every member is closed while the parent is still open (decision D-2). The state stays active and nothing is hot. */
  settling: boolean
  state: WaveState
}

/** Plan statuses on which a wave may expand by default (R7: a drafted plan fails this conjunct). */
const EXPANDING_PLAN_STATUSES: ReadonlySet<string> = new Set(['started', 'incomplete'])

const norm = (v: string | null | undefined): string => (v ?? '').trim().toLowerCase().replace(/_/g, '-')

/** terminal(t): closed or superseded. open(t) is its negation. */
export const isTerminal = (t: WaveTaskFacts): boolean => {
  const s = norm(t.status)
  return s === 'closed' || s === 'superseded'
}

const hasCheckout = (t: WaveTaskFacts): boolean => typeof t.first_checked_out_at === 'string' && t.first_checked_out_at.trim() !== ''

/**
 * Until the backfill lands co(t) may be empty on a task that was checked out, so touched(w) also accepts
 * checkout_state = checked_out or an in-flight status, both already in the corpus row (section 5.5). In flight is any task
 * status the status map draws with the active, waiting or caution role: in-progress through deployed, pr and coding-updates.
 */
export const isCheckedOut = (t: WaveTaskFacts): boolean => {
  if (hasCheckout(t)) return true
  if (norm(t.checkout_state) === 'checked-out') return true
  const role = statusRole('task', t.status)
  return role === 'active' || role === 'waiting' || role === 'caution'
}

export function waveStatus(wave: WaveFacts): WaveStatus {
  const { parent, members } = wave
  const touched = members.some(isCheckedOut)
  // hot is defined on co(t) alone: the section 5.5 fallback is stated for touched(w) only.
  const hot = members.some((t) => hasCheckout(t) && !isTerminal(t))
  const allTerminal = members.length > 0 && members.every(isTerminal)
  const resolved = parent ? norm(parent.status) === 'closed' : allTerminal
  const state: WaveState = resolved ? 'done' : touched ? 'active' : 'todo'
  const settling = Boolean(parent) && !resolved && allTerminal
  return { touched, hot, resolved, settling, state }
}

export const waveState = (wave: WaveFacts): WaveState => waveStatus(wave).state

export const isHot = (wave: WaveFacts): boolean => waveStatus(wave).hot

/** expanded_default(w): the plan is started or incomplete, the wave is hot, and the wave is not done. */
export function expandedDefault(wave: WaveFacts, planStatus: string | null | undefined): boolean {
  const { hot, state } = waveStatus(wave)
  return EXPANDING_PLAN_STATUSES.has(norm(planStatus)) && hot && state !== 'done'
}

/** A manual toggle, remembered with the state and hotness it was made under (decision D-3). */
export interface WaveOverride {
  expanded: boolean
  state: WaveState
  hot: boolean
}

/** Records a toggle against the wave as it is now. */
export function makeOverride(wave: WaveFacts, expanded: boolean): WaveOverride {
  const { state, hot } = waveStatus(wave)
  return { expanded, state, hot }
}

/**
 * shown(w): the override while it still holds, otherwise expanded_default(w). An override lasts until state(w) or hot(w)
 * next changes, so the automatic behaviour always fires on a real transition and never fights a deliberate click between.
 */
export function shown(wave: WaveFacts, planStatus: string | null | undefined, override?: WaveOverride | null): boolean {
  if (override) {
    const { state, hot } = waveStatus(wave)
    if (override.state === state && override.hot === hot) return override.expanded
  }
  return expandedDefault(wave, planStatus)
}
