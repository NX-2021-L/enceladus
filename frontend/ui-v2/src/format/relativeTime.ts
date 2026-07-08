/**
 * ENC-TSK-M35 (PAR-01, Enceladus-v4-Feed-Review.md §3): the v3 feed stamped a
 * relative timestamp ("37m ago") on every row -- v4 dropped it entirely. This
 * restores it from real data (Tier1Record.updatedAt, already cached but
 * previously dropped on the floor before reaching the search/filter layer --
 * the same class of gap FTR-130 Band-B fixed for priority/checkout_state).
 *
 * Never fabricates a time: returns null when there is no real timestamp to
 * report (e.g. cold-start realtime-events-only corpus), so callers can omit
 * the meta slot entirely rather than render a fake "just now".
 */
export function formatRelativeTime(iso: string | null | undefined, now: number = Date.now()): string | null {
  if (!iso) return null
  const then = Date.parse(iso)
  if (Number.isNaN(then)) return null

  const diffMs = now - then
  if (diffMs < 0) return 'just now'

  const MINUTE = 60_000
  const HOUR = 60 * MINUTE
  const DAY = 24 * HOUR

  if (diffMs < MINUTE) return 'just now'
  if (diffMs < HOUR) return `${Math.floor(diffMs / MINUTE)}m ago`
  if (diffMs < DAY) return `${Math.floor(diffMs / HOUR)}h ago`
  return `${Math.floor(diffMs / DAY)}d ago`
}
