/**
 * ChipRow -- the record-detail chips beyond status (ENC-TSK-M33 / DOC-B6B52E3BB9BB §7
 * chip-row parity). ENC-TSK-S62-0A re-bases every chip on the Design System v1.1 pill
 * family (components/Pill.tsx, spec DOC-8253497AC9FC 4.5 and 6.2 to 6.4), so a fact looks
 * the same here as on the feed row:
 *   priority, severity  -> UrgencyBadge (neutral four-step scale, mono, bar glyph)
 *   category            -> taxonomy Tag (lavender, one look for every value)
 *   component           -> code Tag (mono, neutral)
 *   active session      -> OpChip session (accent, signal glyph)
 *   checkout            -> OpChip held / free (neutral, lock glyph)
 * Order on the detail page (spec 6.8): urgency, operational, tags.
 */
import { OpChip, Tag, UrgencyBadge } from './Pill'

export function PriorityChip({ priority }: { priority?: string | null }) {
  return <UrgencyBadge value={priority} />
}

export function SeverityChip({ severity }: { severity?: string | null }) {
  return <UrgencyBadge value={severity} />
}

export function CategoryChip({ category }: { category?: string | null }) {
  if (!category) return null
  return <Tag>{category}</Tag>
}

export function ComponentChips({ components }: { components?: string[] | string | null }) {
  const list = Array.isArray(components)
    ? components
    : typeof components === 'string' && components.trim()
      ? [components.trim()]
      : []
  if (!list.length) return null
  return (
    <>
      {list.map((c) => (
        <Tag key={c} code>
          {c}
        </Tag>
      ))}
    </>
  )
}

export function ActiveSessionChip({ active, sessionId }: { active?: boolean; sessionId?: string | null }) {
  if (!active) return null
  return (
    <OpChip op="session" title={sessionId ? `Active session: ${sessionId}` : 'Active agent session'}>
      Active
    </OpChip>
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
  const title = checkedOut
    ? checkedOutBy
      ? `Checked out by ${checkedOutBy}`
      : undefined
    : checkedInBy
      ? `Checked in by ${checkedInBy}`
      : undefined
  return (
    <OpChip op={checkedOut ? 'held' : 'free'} title={title}>
      {checkedOut ? 'Checked Out' : 'Checked In'}
    </OpChip>
  )
}
