import type { SearchTier } from '../types/search'

const TIER_LABEL: Record<SearchTier, string> = {
  local: 'Local',
  hybrid: 'Hybrid',
}

const TIER_COLOR: Record<SearchTier, string> = {
  local: 'var(--status-open)',
  hybrid: 'var(--accent)',
}

/** Tier label for merged search results (FTR-127 — local vs hybrid semantic tier). */
export function SearchTierBadge({ tier }: { tier: SearchTier }) {
  const color = TIER_COLOR[tier]
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        fontFamily: 'var(--font-heading)',
        fontSize: 'var(--text-xs)',
        fontWeight: 'var(--fw-medium)',
        textTransform: 'uppercase',
        letterSpacing: 'var(--tracking-label)',
        color,
        border: `1px solid ${color}`,
        borderRadius: 'var(--radius-sm)',
        padding: '1px var(--space-2)',
      }}
    >
      {TIER_LABEL[tier]}
    </span>
  )
}
