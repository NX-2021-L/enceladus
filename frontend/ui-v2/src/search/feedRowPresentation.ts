/**
 * ENC-TSK-M35 -- pure hit -> presentation mappings for the dense Feed row,
 * bound exclusively to Enceladus-v4-Feed-Review.md §4/§5 tokens (never a raw
 * hex, never an invented color). Kept side-effect-free and framework-free so
 * the severity/badge logic is unit-testable without rendering React.
 *
 * The left-accent bar is SEVERITY-keyed (§4.5 / §5.4), not a fixed
 * per-record-type hue: Feed.dc.html (the binding pixel contract) assigns
 * `--enc-teal-light` to an active Plan, `--enc-slate` to a closed Issue AND a
 * closed Task, and `--enc-crimson` to an open P0 Issue -- i.e. the same
 * record type gets different accents depending on state. Per the dispatch
 * directive the .dc.html wins over the AC's "record-type signature colors"
 * prose.
 */
import type { BadgeColor } from '../components/Badge'
import type { SearchResultHit } from '../types/search'

const ACCENT = {
  alert: 'var(--enc-crimson)',
  active: 'var(--enc-teal-light)',
  neutral: 'var(--enc-teal)',
  closed: 'var(--enc-slate)',
} as const

const CLOSED_STATUSES = new Set(['closed', 'archived', 'retired', 'deprecated'])
const ACTIVE_STATUSES = new Set(['in-progress', 'started', 'active'])
const ALERT_STATUSES = new Set(['blocked'])

/** 3px left-accent bar color (Enceladus-v4-Feed-Review.md §4.5 / §5.4, PAR-06). */
export function feedRowAccent(hit: Pick<SearchResultHit, 'status' | 'priority'>): string {
  const status = hit.status?.trim().toLowerCase() ?? ''
  if (hit.priority?.trim().toLowerCase() === 'p0' || ALERT_STATUSES.has(status)) return ACCENT.alert
  if (ACTIVE_STATUSES.has(status)) return ACCENT.active
  if (CLOSED_STATUSES.has(status)) return ACCENT.closed
  return ACCENT.neutral
}

/** Priority -> Badge color (§4.4 / §5.2, PAR-02). */
export function priorityBadgeColor(priority: string): BadgeColor {
  const p = priority.trim().toLowerCase()
  if (p === 'p0') return 'crimson'
  if (p === 'p1') return 'amber'
  return 'dust'
}

/** Session/checkout state -> Badge (§4.4 / §5.3, PAR-03). Suppressed (null)
 *  when the record carries no checkout_state signal at all -- never renders
 *  a fabricated default. */
export function sessionStateBadge(
  checkoutState: string | undefined,
): { label: string; color: BadgeColor } | null {
  if (!checkoutState) return null
  return checkoutState.trim().toLowerCase() === 'checked_out'
    ? { label: 'CHECKED OUT', color: 'amber' }
    : { label: 'CHECKED IN', color: 'teal' }
}
