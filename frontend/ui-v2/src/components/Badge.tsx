import type { ReactNode } from 'react'
import './badge.css'

/** Enceladus-v4-Feed-Review.md §4.4 -- the only five sanctioned Badge hues. */
export type BadgeColor = 'crimson' | 'amber' | 'dust' | 'teal' | 'lavender'

const BADGE_COLOR_TOKEN: Record<BadgeColor, string> = {
  crimson: 'var(--enc-crimson)',
  amber: 'var(--v2-status-warning)',
  dust: 'var(--enc-dust)',
  teal: 'var(--enc-teal)',
  lavender: 'var(--enc-lavender)',
}

/**
 * Badge -- small bordered mono chip for priority / CCI / PR / deploy signals
 * (Enceladus-v4-Feed-Review.md §4.4, §5.2, §5.3). Crimson badges glow on
 * hover (P0 escalation), matching the DS `--glow-crimson` treatment used
 * elsewhere (StatusChip, evidence tiles).
 */
export function Badge({ color, children }: { color: BadgeColor; children: ReactNode }) {
  const token = BADGE_COLOR_TOKEN[color]
  return (
    <span
      className={color === 'crimson' ? 'ev2-badge ev2-badge--crimson' : 'ev2-badge'}
      style={{ color: token, borderColor: token }}
    >
      {children}
    </span>
  )
}
