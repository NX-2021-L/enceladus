import { formatRelativeTime } from '../format/relativeTime'

/**
 * ENC-TSK-Q33 (ENC-ISS-830): when the corpus seed fails, /docs and /feed keep
 * rendering the IndexedDB slice. Say so instead of presenting it as live.
 */
export function staleCorpusNotice(
  seedError: string | null,
  lastSeededAt: string | null,
  now: number = Date.now(),
): string | null {
  if (!seedError) return null
  const age = lastSeededAt ? formatRelativeTime(lastSeededAt, now) : null
  const cached = lastSeededAt
    ? `Showing the list cached on this device, last refreshed ${age ?? lastSeededAt} (${lastSeededAt}).`
    : 'Showing the list cached on this device; it has never completed a live refresh.'
  return `${cached} The live refresh failed: ${seedError}. Newer records may be missing.`
}
