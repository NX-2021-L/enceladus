/**
 * Pill family (ENC-TSK-S62-0A; Design System v1.1 spec DOC-8253497AC9FC sections 4.5, 6.2 to 6.4).
 *
 * Every non-lifecycle fact on a card has its own channel and one look, the same on the feed
 * and on the detail page:
 *   UrgencyBadge  priority P0-P3, severity critical-low, gate risk: one neutral four-step
 *                 scale, mono, a four-bar glyph; level 0 is the only filled badge.
 *   OpChip        checkout (held / free) and an active agent session.
 *   Tag           taxonomy (category, escalation kind), code identifiers (component, project,
 *                 transition type, search tier, subtype pattern) and document type.
 * None of them uses a status hue or the capsule shape, and none changes the status pill or
 * the feed rail. Replaces the Badge atom and ChipRow's inline Chip (two outlined anatomies
 * that drew the same fact differently on different pages).
 */
import type { ReactNode } from 'react'
import './pills.css'

export type UrgencyLevel = 0 | 1 | 2 | 3

const URGENCY: Record<string, UrgencyLevel> = {
  p0: 0,
  p1: 1,
  p2: 2,
  p3: 3,
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

/** Priority, severity or gate risk to the urgency step (spec 4.5). Unknown values sit at 3. */
export function urgencyLevel(value: string | null | undefined): UrgencyLevel {
  return URGENCY[(value ?? '').trim().toLowerCase()] ?? 3
}

export function UrgencyBadge({ value, title }: { value?: string | null; title?: string }) {
  if (!value) return null
  const v = value.trim()
  const shown = /^p\d$/i.test(v) ? v.toUpperCase() : v
  return (
    <span className="enc-badge" data-level={urgencyLevel(v)} title={title}>
      {shown}
    </span>
  )
}

export type OpKind = 'held' | 'free' | 'session'

export function OpChip({ op, children, title }: { op: OpKind; children: ReactNode; title?: string }) {
  return (
    <span className="enc-op" data-op={op} title={title}>
      {children}
    </span>
  )
}

export function Tag({
  children,
  code = false,
  glyph,
  doctype,
  title,
}: {
  children: ReactNode
  /** Identifier tag: mono, case as given, neutral outline. */
  code?: boolean
  /** Search tier glyph (local single ring, hybrid linked rings). */
  glyph?: 'local' | 'hybrid'
  /** Document type (document_subtype); unlisted types take the doc treatment. */
  doctype?: string
  title?: string
}) {
  return (
    <span
      className="enc-tag"
      data-kind={code ? 'code' : undefined}
      data-glyph={glyph}
      data-doctype={doctype ? doctype.trim().toLowerCase() : undefined}
      title={title}
    >
      {children}
    </span>
  )
}

/** Whether a checkout_state value means the record is held (checked out). */
export function isCheckedOut(checkoutState: string | null | undefined): boolean {
  return (checkoutState ?? '').trim().toLowerCase() === 'checked_out'
}
