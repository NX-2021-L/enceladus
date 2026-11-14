import type { SearchTier } from '../types/search'
import { Tag } from './Pill'

const TIER_LABEL: Record<SearchTier, string> = {
  local: 'Local',
  hybrid: 'Hybrid',
}

/**
 * Tier label for merged search results (FTR-127 local vs hybrid semantic tier).
 * ENC-TSK-S62-0A: a code tag; the two tiers differ by glyph (single ring vs linked rings),
 * not by a status hue (Design System v1.1 spec 4.5).
 */
export function SearchTierBadge({ tier }: { tier: SearchTier }) {
  return (
    <Tag code glyph={tier}>
      {TIER_LABEL[tier]}
    </Tag>
  )
}
