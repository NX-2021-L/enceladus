/**
 * DVP-TSK-A20: row model of the restored escalations cockpit, adapted from the pre-970
 * escalationRows.ts to @io-kit/gates GateCards (any kind, any project). Pure functions only.
 */
import type { GateCard } from '@io-kit/gates'

export type EscalationBucket = 'pending' | 'approved' | 'denied' | 'all'

export interface EscalationRow {
  key: string
  id: string
  projectId: string
  kind: string
  risk: string
  state: string
  status: string
  title: string
  targetRecordId: string
  requestedBy: string
  expiresAt: string | undefined
  expiresLabel: string
  createdAt: string | undefined
  ageLabel: string
  bucket: Exclude<EscalationBucket, 'all'> | 'closed'
  decidable: boolean
  /** Filing-time drift (hub diff.filed_against, ENC-TSK-R50). Informational: it never blocks a verdict. */
  filedAgainst: FiledAgainst | undefined
  card: GateCard
}

export interface FiledAgainst {
  expectedVersion: string
  currentVersion: string
  changed: boolean
}

/** The hub's diff carries `filed_against` next to the kit GateDiff fields; read it defensively. */
export function filedAgainstOf(card: GateCard): FiledAgainst | undefined {
  const raw = (card.diff as unknown as { filed_against?: Record<string, unknown> } | undefined)?.filed_against
  if (raw === null || typeof raw !== 'object') return undefined
  return {
    expectedVersion: String(raw.expected_version ?? ''),
    currentVersion: String(raw.current_sync_version ?? ''),
    changed: raw.changed === true,
  }
}

function requesterOf(card: GateCard): string | undefined {
  const session = (card as GateCard & { requested_by?: { session_id?: unknown } }).requested_by?.session_id
  return typeof session === 'string' && session !== '' ? session : undefined
}

const MIN = 60_000
const HOUR = 60 * MIN
const DAY = 24 * HOUR

export function ageLabel(iso: string | undefined, now: number): string {
  const t = iso ? Date.parse(iso) : NaN
  if (Number.isNaN(t)) return '—'
  const d = Math.max(0, now - t)
  if (d < MIN) return '<1m'
  if (d < HOUR) return `${Math.floor(d / MIN)}m`
  if (d < DAY) return `${Math.floor(d / HOUR)}h`
  return `${Math.floor(d / DAY)}d`
}

export function expiryLabel(iso: string | undefined, now: number): string {
  const t = iso ? Date.parse(iso) : NaN
  if (Number.isNaN(t)) return '—'
  const d = t - now
  if (d <= 0) return 'expired'
  if (d < HOUR) return `in ${Math.max(1, Math.floor(d / MIN))}m`
  if (d < DAY) return `in ${Math.floor(d / HOUR)}h`
  return `in ${Math.floor(d / DAY)}d`
}

export function statusOf(card: GateCard): string {
  if (card.state === 'decided') {
    const d = card.decision?.decision
    return d === 'deny' ? 'denied' : d === 'approve' ? 'approved' : 'decided'
  }
  return card.state === 'pending' ? 'requested' : card.state
}

export function bucketOf(card: GateCard): EscalationRow['bucket'] {
  if (card.state === 'pending' || card.state === 'snoozed') return 'pending'
  if (card.state === 'decided') return card.decision?.decision === 'deny' ? 'denied' : 'approved'
  return 'closed'
}

export function cardId(card: GateCard): string {
  return card.id ?? card.item_id ?? card.title ?? card.subject.record_id
}

export function toEscalationRows(cards: readonly GateCard[], now: number = Date.now()): EscalationRow[] {
  const rows = cards.map((card): EscalationRow => {
    const id = cardId(card)
    const projectId = card.project_id ?? card.subject.project ?? '—'
    return {
      key: `${projectId}/${id}`,
      id,
      projectId,
      kind: card.kind,
      risk: card.risk,
      state: card.state,
      status: statusOf(card),
      title: card.title ?? card.proposedCalls?.[0]?.capability ?? card.why?.summary ?? id,
      targetRecordId: card.subject.record_id,
      requestedBy: card.requestedBy ?? card.sourcePrincipal ?? requesterOf(card) ?? '—',
      expiresAt: card.expiresAt,
      expiresLabel: expiryLabel(card.expiresAt, now),
      createdAt: card.createdAt,
      ageLabel: ageLabel(card.createdAt, now),
      bucket: bucketOf(card),
      decidable:
        (card.state === 'pending' || card.state === 'snoozed') &&
        card.etag !== undefined && card.id !== undefined && card.project_id !== undefined,
      filedAgainst: filedAgainstOf(card),
      card,
    }
  })
  // Pending: soonest expiry first (undecided gates that lapse first lead); terminal: newest first.
  const when = (r: EscalationRow) => Date.parse(r.card.decision?.decidedAt ?? r.createdAt ?? '') || 0
  return rows.sort((a, b) => {
    if ((a.bucket === 'pending') !== (b.bucket === 'pending')) return a.bucket === 'pending' ? -1 : 1
    if (a.bucket === 'pending') {
      const ea = a.expiresAt ? Date.parse(a.expiresAt) : Infinity
      const eb = b.expiresAt ? Date.parse(b.expiresAt) : Infinity
      return ea - eb
    }
    return when(b) - when(a)
  })
}

export function countByBucket(rows: readonly EscalationRow[]): Record<EscalationBucket, number> {
  const c: Record<EscalationBucket, number> = { pending: 0, approved: 0, denied: 0, all: rows.length }
  for (const r of rows) if (r.bucket === 'pending' || r.bucket === 'approved' || r.bucket === 'denied') c[r.bucket] += 1
  return c
}

export function filterRows(rows: readonly EscalationRow[], bucket: EscalationBucket): EscalationRow[] {
  return bucket === 'all' ? [...rows] : rows.filter((r) => r.bucket === bucket)
}
