export function cacheKey(projectId: string, recordId: string): string {
  return `${projectId || 'global'}:${recordId}`
}

export function versionSeqFromUpdatedAt(updatedAt?: string | null): string {
  return updatedAt?.trim() || '0'
}

export function versionSeqFromItem(item: { version_seq?: number; updated_at?: string | null }): string {
  if (item.version_seq != null && Number.isFinite(item.version_seq)) {
    return String(item.version_seq)
  }
  return versionSeqFromUpdatedAt(item.updated_at)
}

const INTEGER_TOKEN = /^\d+$/

function integerToken(token: string | null | undefined): number | null {
  if (!token || !INTEGER_TOKEN.test(token)) return null
  return Number(token)
}

function timeToken(token: string | null | undefined): number | null {
  if (!token || INTEGER_TOKEN.test(token)) return null
  const parsed = Date.parse(token)
  return Number.isNaN(parsed) ? null : parsed
}

/**
 * ENC-TSK-Q34 (ENC-ISS-731): compare two version tokens WITHIN one domain.
 * Integer tokens (server version_seq) compare numerically, ISO tokens
 * (updated_at) compare as parsed times. A mixed pair returns null: the
 * tokens are not comparable, and a plain string compare ('2026-…' vs '8412',
 * or '5101' vs '850') silently froze cached rows.
 */
export function compareVersionTokens(a: string | null | undefined, b: string | null | undefined): number | null {
  const ai = integerToken(a)
  const bi = integerToken(b)
  if (ai !== null && bi !== null) return Math.sign(ai - bi)
  const at = timeToken(a)
  const bt = timeToken(b)
  if (at !== null && bt !== null) return Math.sign(at - bt)
  return null
}

/** Token-only gate (tier2 bodies, realtime record frames). '0' means "no
 *  version information" and never displaces a known version; an
 *  incomparable pair accepts the incoming value, which is the fresher fetch. */
export function shouldAcceptVersion(current: string | undefined, incoming: string): boolean {
  if (!current) return true
  if (current === incoming) return true
  if (incoming === '0') return false
  const cmp = compareVersionTokens(incoming, current)
  return cmp === null ? true : cmp >= 0
}

export interface VersionedRow {
  versionSeq?: string
  updatedAt?: string | null
}

/** ENC-TSK-Q34 (ENC-ISS-731): tier1 accept gate. Same-domain tokens decide;
 *  a mixed pair (delta/corpus integer seq vs realtime ISO token) falls back to
 *  the rows' updated_at, so neither path can freeze the other out. */
export function shouldAcceptRecord(existing: VersionedRow | null | undefined, incoming: VersionedRow): boolean {
  if (!existing) return true
  const cmp = compareVersionTokens(incoming.versionSeq, existing.versionSeq)
  if (cmp !== null) return cmp >= 0
  const incomingTime = timeToken(incoming.updatedAt ?? null)
  const existingTime = timeToken(existing.updatedAt ?? null)
  if (incomingTime !== null && existingTime !== null) return incomingTime >= existingTime
  if (incomingTime !== null) return true
  if (existingTime !== null) return false
  return true
}

/** True only when `incoming` is a strictly newer version than `reference`
 *  in the same domain (used to lift a versioned tombstone). */
export function isStrictlyNewerVersion(incoming: string | undefined, reference: string | undefined): boolean {
  return compareVersionTokens(incoming, reference) === 1
}
