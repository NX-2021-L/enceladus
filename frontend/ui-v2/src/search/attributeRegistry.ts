import type { LocalSearchRecord } from '../types/search'

/** Governance dictionary ∪ observed feed fields (FTR-127 AC-6/7). */
const GOVERNANCE_FILTER_PROPERTIES = [
  { key: 'status', operators: ['=', '!=', ':'] },
  { key: 'record_type', operators: ['=', '!=', ':'] },
  { key: 'project_id', operators: ['=', '!=', ':'] },
  { key: 'record_id', operators: ['=', '!=', ':'] },
  { key: 'title', operators: ['=', '!=', ':'] },
  // ENC-FTR-130 Band-B: wired so Home's counts-strip deep links (status +
  // priority + checkout_state) actually filter Feed instead of landing on
  // an unfiltered/zero result set. 'in' matches a comma-separated value
  // list (e.g. priority in "p0,p1"), mirroring the backend's own
  // comma-list query convention (backend/lambda/feed_query/corpus.py).
  { key: 'priority', operators: ['=', '!=', 'in'] },
  { key: 'checkout_state', operators: ['=', '!=', 'in'] },
] as const

export type FilteringProperty = {
  key: string
  operators?: string[]
}

export function buildAttributeRegistry(corpus: LocalSearchRecord[]): FilteringProperty[] {
  const keys = new Map<string, Set<string>>()
  for (const prop of GOVERNANCE_FILTER_PROPERTIES) {
    keys.set(prop.key, new Set(prop.operators ?? ['=']))
  }

  for (const row of corpus) {
    if (row.status) observe(keys, 'status', row.status)
    observe(keys, 'record_type', row.recordType)
    observe(keys, 'project_id', row.projectId)
    observe(keys, 'record_id', row.recordId)
    observe(keys, 'title', row.title)
    if (row.priority) observe(keys, 'priority', row.priority)
    if (row.checkoutState) observe(keys, 'checkout_state', row.checkoutState)
  }

  return [...keys.entries()].map(([key, operators]) => ({
    key,
    operators: [...operators],
  }))
}

function observe(map: Map<string, Set<string>>, key: string, _value: string) {
  if (!map.has(key)) {
    map.set(key, new Set(['=', '!=', ':']))
  }
}

/** Resolve a hit field for property-filter token matching. */
export function fieldValueForProperty(
  hit: LocalSearchRecord,
  propertyKey: string,
): string | undefined {
  switch (propertyKey) {
    case 'status':
      return hit.status
    case 'record_type':
      return hit.recordType
    case 'project_id':
      return hit.projectId
    case 'record_id':
      return hit.recordId
    case 'title':
      return hit.title
    case 'priority':
      return hit.priority
    case 'checkout_state':
      return hit.checkoutState
    default:
      return undefined
  }
}

/** Distinct observed values for a property key (value autosuggest corpus). */
export function observedValuesForProperty(
  corpus: LocalSearchRecord[],
  propertyKey: string,
): string[] {
  const values = new Set<string>()
  for (const row of corpus) {
    const v = fieldValueForProperty(row, propertyKey)
    if (v) values.add(v)
  }
  return [...values].sort()
}

/** Prefix match property keys — intended to complete within 100ms (sync, bounded). */
export function suggestPropertyKeys(
  prefix: string,
  properties: FilteringProperty[],
  limit = 12,
): FilteringProperty[] {
  const q = prefix.trim().toLowerCase()
  if (!q) return properties.slice(0, limit)
  return properties
    .filter((p) => p.key.toLowerCase().includes(q))
    .slice(0, limit)
}

/** Prefix match observed values for the active property key. */
export function suggestPropertyValues(
  propertyKey: string,
  prefix: string,
  corpus: LocalSearchRecord[],
  limit = 12,
): string[] {
  const q = prefix.trim().toLowerCase()
  const values = observedValuesForProperty(corpus, propertyKey)
  if (!q) return values.slice(0, limit)
  return values.filter((v) => v.toLowerCase().includes(q)).slice(0, limit)
}
