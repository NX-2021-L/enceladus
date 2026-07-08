/**
 * Pure data-shaping helpers for the Home "Requires io" queue (ENC-TSK-M19 /
 * UX-B1 / FND-HOME). Side-effect-free, framework-free -- same convention as
 * routes/homeDashboard.ts.
 */

import type { EscalationRecord } from '../api/coordination'

export interface QueueRow {
  id: string
  kindLabel: string
  title: string
  description?: string
  status?: string
  /** Present only for real, navigable rows. Gap rows omit this. */
  href?: string
  /** True for a static row that documents a known data-gap instead of a
   * live record -- rendered non-interactively, never as a Link. */
  gap?: boolean
}

/** Pending escalations (status=requested) are the only human-actionable
 * escalation state -- terminal/resolved rows are noise on the "Requires io"
 * queue (they remain visible on /coordination's Escalations tab). Each row
 * links to that tab, the one surface for this record type per
 * CoordinationRoute's own doc comment. */
export function pendingEscalationRows(escalations: EscalationRecord[]): QueueRow[] {
  return escalations
    .filter((escalation) => (escalation.status ?? '').toLowerCase() === 'requested')
    .map((escalation) => {
      const id = escalation.item_id ?? escalation.record_id ?? '(unknown)'
      const target = escalation.target_record_id
      return {
        id,
        kindLabel: 'Escalation',
        title: target ? `Unblock ${target}` : `Review ${id}`,
        description: target ? `Target record: ${target}` : undefined,
        status: escalation.status,
        href: '/coordination?tab=escalations',
      }
    })
}

/** Static rows documenting queue slices with no PWA-reachable data source
 * today (see api/homeQueue.ts module docstring). Kept as data, not inline
 * JSX, so the "what's real vs. a gap" list is reviewable/testable on its
 * own. */
export const GAP_QUEUE_ROWS: QueueRow[] = [
  {
    id: 'gap-paused-prod',
    kindLabel: 'Paused prod runs',
    title: 'Paused v3-prod Environment approvals',
    description:
      'No PWA-reachable data source yet -- GitHub Actions Environment protection state isn’t exposed by any Enceladus HTTP API. Check the workflow run’s Environment approval gate directly in GitHub Actions.',
    gap: true,
  },
  {
    id: 'gap-stale-lock',
    kindLabel: 'Stale locks',
    title: 'Stale-lock / backfill flags',
    description:
      'No PWA-reachable data source yet -- worktree/session lock bookkeeping (ENC-ISS-071) and retirement-sweep backfills aren’t exposed by any Enceladus HTTP API today.',
    gap: true,
  },
]
