/**
 * ChipRow -- the additional record-detail chips beyond status (ENC-TSK-M33
 * / DOC-B6B52E3BB9BB §7 chip-row parity): priority, severity, category, the
 * ●Active green-dot session indicator, checkout Checked-Out(gold)/Checked-In,
 * and component. Tokens bound per Enceladus-v4-LookFeel-Implementation-Spec
 * §5.2/5.3 ("Never render a status/priority/CCI in a color outside this
 * table") -- crimson=P0, amber(--v2-status-warning)=P1/CHECKED OUT,
 * dust=P2/P3, lavender=category tag, teal=CHECKED IN / active dot.
 */
import type { ReactNode } from 'react'
import './chipRow.css'

function Chip({
  label,
  color,
  title,
  dot,
}: {
  label: ReactNode
  color: string
  title?: string
  dot?: boolean
}) {
  return (
    <span className="ev2-chip" style={{ color, borderColor: color }} title={title}>
      {dot ? (
        <span
          aria-hidden
          className="ev2-chip__dot"
          style={{ background: color, boxShadow: `0 0 6px ${color}` }}
        />
      ) : null}
      {label}
    </span>
  )
}

const PRIORITY_COLOR: Record<string, string> = {
  P0: 'var(--enc-crimson, var(--danger, #C85060))',
  P1: 'var(--v2-status-warning, #C9A15C)',
  P2: 'var(--enc-dust, var(--fg-muted, #6B8A94))',
  P3: 'var(--enc-dust, var(--fg-muted, #6B8A94))',
}

export function PriorityChip({ priority }: { priority?: string | null }) {
  if (!priority) return null
  const color = PRIORITY_COLOR[priority.toUpperCase()] ?? PRIORITY_COLOR.P2
  return <Chip label={priority.toUpperCase()} color={color} />
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--enc-crimson, var(--danger, #C85060))',
  high: 'var(--enc-crimson, var(--danger, #C85060))',
  medium: 'var(--v2-status-warning, #C9A15C)',
  low: 'var(--enc-dust, var(--fg-muted, #6B8A94))',
}

export function SeverityChip({ severity }: { severity?: string | null }) {
  if (!severity) return null
  const color = SEVERITY_COLOR[severity.toLowerCase()] ?? SEVERITY_COLOR.low
  return <Chip label={severity} color={color} />
}

export function CategoryChip({ category }: { category?: string | null }) {
  if (!category) return null
  return <Chip label={category} color="var(--enc-lavender, var(--accent-secondary, #8A8CB5))" />
}

export function ComponentChips({ components }: { components?: string[] }) {
  if (!components?.length) return null
  return (
    <>
      {components.map((c) => (
        <Chip key={c} label={c} color="var(--enc-teal-light, var(--accent, #7AC8D4))" />
      ))}
    </>
  )
}

/** The ●Active green-dot indicator -- an agent session is live on this
 *  record right now (distinct from the gold Checked-Out chip, which merely
 *  states the lock is held). */
export function ActiveSessionChip({
  active,
  sessionId,
}: {
  active?: boolean
  sessionId?: string | null
}) {
  if (!active) return null
  return (
    <Chip
      label="Active"
      color="var(--enc-teal, var(--accent, #3D9BA8))"
      dot
      title={sessionId ? `Active session: ${sessionId}` : 'Active agent session'}
    />
  )
}

export function CheckoutChip({
  checkedOut,
  checkedOutBy,
  checkedInBy,
}: {
  checkedOut: boolean
  checkedOutBy?: string | null
  checkedInBy?: string | null
}) {
  const color = checkedOut
    ? 'var(--v2-status-warning, #C9A15C)'
    : 'var(--enc-teal, var(--accent, #3D9BA8))'
  const label = checkedOut ? 'Checked Out' : 'Checked In'
  const title = checkedOut
    ? checkedOutBy
      ? `Checked out by ${checkedOutBy}`
      : undefined
    : checkedInBy
      ? `Checked in by ${checkedInBy}`
      : undefined
  return <Chip label={label} color={color} title={title} />
}
