/**
 * Minimal client-side PropertyFilter apply for the coordination monitor page
 * (ENC-TSK-L34). The design-system PropertyFilter emits `{ tokens, operation }`
 * where each token is `{ propertyKey, operator, value }`; this filters an
 * array of heterogeneous record rows (sessions/agent-types/lessons/
 * escalations/CRQ docs) by substring match on the named field, ANDed or ORed
 * per `operation`. Extracted from CoordinationRoute.tsx so it is unit-testable
 * without a DOM/React-Testing-Library dependency (none exists in this repo yet).
 */
import type { PropertyFilterQuery } from '../../../design-system-2/v2/components/PropertyFilter/PropertyFilter.jsx'

type RecordRow = Record<string, unknown>

export function applyTokens<T extends RecordRow>(items: T[], query: PropertyFilterQuery): T[] {
  if (query.tokens.length === 0) return items
  return items.filter((item) => {
    const results = query.tokens.map((token) => {
      const raw = item[token.propertyKey]
      const haystack = raw == null ? '' : String(raw).toLowerCase()
      return haystack.includes(token.value.toLowerCase())
    })
    return query.operation === 'or' ? results.some(Boolean) : results.every(Boolean)
  })
}
