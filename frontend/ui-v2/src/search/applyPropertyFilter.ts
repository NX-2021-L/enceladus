import { fieldValueForProperty } from './attributeRegistry'
import type { LocalSearchRecord } from '../types/search'

export interface PropertyFilterToken {
  propertyKey: string
  operator: string
  value: string
}

export interface PropertyFilterQuery {
  tokens: PropertyFilterToken[]
  operation?: 'and' | 'or'
}

function compareToken(actual: string, operator: string, expected: string): boolean {
  const a = actual.toLowerCase()
  const e = expected.toLowerCase()
  switch (operator) {
    case '=':
    case ':':
      return a === e
    case '!=':
      return a !== e
    case '>':
      return a > e
    case '<':
      return a < e
    case '>=':
      return a >= e
    case '<=':
      return a <= e
    case 'in':
      // ENC-FTR-130 Band-B: comma-separated OR-membership (e.g. priority
      // "in" "p0,p1"), mirroring the backend's comma-list query convention
      // (backend/lambda/feed_query/corpus.py) so Home's counts-strip links
      // can express "P0 or P1" as a single filter token.
      return expected
        .split(',')
        .map((v) => v.trim().toLowerCase())
        .filter(Boolean)
        .includes(a)
    default:
      return a.includes(e)
  }
}

function tokenMatches<T extends LocalSearchRecord>(hit: T, token: PropertyFilterToken): boolean {
  const actual = fieldValueForProperty(hit, token.propertyKey)
  if (actual === undefined) {
    // ENC-TSK-P59 verification fix (ENC-ISS-725): "field is not <value>" is
    // TRUE for a record that does not carry the field at all — the server
    // counter counts exactly that way (checkout_state absent ≠ checked_out),
    // and the old blanket false made `checkout_state != checked_out` return
    // 0 hits against a 588 counter. Every other operator still requires the
    // field to exist.
    return token.operator === '!='
  }
  return compareToken(actual, token.operator, token.value)
}

/** Apply PropertyFilter token pills to search hits (AND by default). */
export function applyPropertyFilter<T extends LocalSearchRecord>(
  hits: T[],
  query: PropertyFilterQuery | undefined,
): T[] {
  const tokens = query?.tokens ?? []
  if (tokens.length === 0) return hits
  const op = query?.operation ?? 'and'
  return hits.filter((hit) => {
    if (op === 'or') {
      return tokens.some((token) => tokenMatches(hit, token))
    }
    return tokens.every((token) => tokenMatches(hit, token))
  })
}
