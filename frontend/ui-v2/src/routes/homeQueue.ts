/**
 * Pure data-shaping helpers for the Home "Requires io" queue (ENC-TSK-M19 /
 * UX-B1 / FND-HOME). Side-effect-free, framework-free -- same convention as
 * routes/homeDashboard.ts.
 */

import type { EscalationRecord } from '../api/coordination'
import type { PausedApprovalRun, StaleLockEntry } from '../api/homeQueue'

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

/** ENC-TSK-M27: GitHub Actions runs paused on the v3-prod Environment's
 * required-reviewer gate, one row per run. Links straight to the GitHub run
 * so io can approve/reject there -- the PWA surfaces the queue, GitHub
 * remains the (only) approval action surface. */
export function pausedApprovalRows(runs: PausedApprovalRun[]): QueueRow[] {
  return runs.map((run) => ({
    id: `paused-approval-${run.id}`,
    kindLabel: 'Paused prod run',
    title: run.requesting_workflow
      ? `${run.requesting_workflow} awaiting v3-prod approval`
      : `Run ${run.id} awaiting v3-prod approval`,
    description: run.head_sha ? `Commit ${run.head_sha.slice(0, 7)}` : undefined,
    href: run.run_url,
  }))
}

/** ENC-TSK-M27: checkout locks held past the stale-checkout threshold, one
 * row per lock. Not directly actionable in the PWA (no new mutation path
 * per AC3) -- surfaces the record + holder + age so io knows what to chase
 * down via the tracker or a terminal session.
 *
 * ENC-ISS-513 / FND-01: `id` is the bare record id (no synthetic prefix) so
 * RecordCard's header shows the real, clean id -- and `title` no longer
 * repeats it as text. One id per card, per the RecordCard contract. */
export function staleLockRows(locks: StaleLockEntry[]): QueueRow[] {
  return locks.map((lock, index) => ({
    id: lock.record_id ?? `stale-lock-${index}`,
    kindLabel: 'Stale lock',
    title: 'Checkout is stale',
    description: [
      lock.holder_session ? `Held by ${lock.holder_session}` : undefined,
      typeof lock.age_minutes === 'number' ? `${lock.age_minutes}m` : undefined,
    ]
      .filter(Boolean)
      .join(' — '),
  }))
}
