/**
 * StatusPill (ENC-TSK-S61-0A; Design System v1.1 spec DOC-8253497AC9FC sections 4.1 and 6.1).
 *
 * Lifecycle status by meaning. The status string and the record kind go through
 * src/status/statusRole.ts (status-map.json) to one of nine roles; the role picks the
 * color, the glyph and the border style in statusPill.css. Priority, severity, record
 * type and checkout are never inputs: a closed P0 task is a done pill, and a lesson
 * shows its lifecycle like every other record.
 *
 * Replaces the shipped StatusChip (17 string matches, P0 and lesson overrides, glowing dot).
 */
import { statusLabel, statusRole, type StatusRole } from '../status/statusRole'
import './statusPill.css'

export interface StatusPillProps {
  /** The status string as stored on the record. Shown with separators as spaces. */
  status: string
  /** Record kind the status belongs to (task, issue, plan, lesson, escalation, project, ...). */
  kind?: string
  /** Override the looked-up role (for previews and tests). */
  role?: StatusRole
}

export function StatusPill({ status, kind, role }: StatusPillProps) {
  const r = role ?? statusRole(kind, status)
  return (
    <span className="enc-pill" data-role={r} data-status={status} title={r === 'unknown' ? `Unmapped status: ${status}` : undefined}>
      {statusLabel(status)}
    </span>
  )
}
