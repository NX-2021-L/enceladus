/**
 * ENC-TSK-M35 -- pure hit -> presentation mappings for the dense Feed row,
 * bound exclusively to Enceladus-v4-Feed-Review.md §4/§5 tokens (never a raw
 * hex, never an invented color). Kept side-effect-free and framework-free so
 * the severity/badge logic is unit-testable without rendering React.
 *
 * The feed row's left rail no longer lives here: ENC-TSK-S61-0A moved it to
 * RecordCard, which reads the same status role as the pill (src/status/statusRole.ts,
 * Design System v1.1 spec 4.4) so the rail and the pill cannot disagree, and
 * priority is never an input.
 */
import type { BadgeColor } from '../components/Badge'

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
