import type { ReactNode } from 'react'
import { Link } from '@tanstack/react-router'
import { RecordId } from './RecordId'
import { StatusChip } from './StatusChip'
import './recordCard.css'

/**
 * RecordCard organism (ENC-TSK-M16 / FND-01/FND-04/FND-08). Mobile-compact
 * full-width is the base case (`variant="compact"`, the default); `standard`
 * gets more breathing room at wider breakpoints (>= 48.0625rem, CSS-only —
 * no JS layout branch); `selectable` renders as a real <button> so it can be
 * a Cards-style selection target (min 44px touch target either way).
 *
 * One record ID per card. Empty fields (title/description/status) are
 * suppressed rather than rendered as placeholders.
 */
export interface RecordCardProps {
  recordId: string
  /** Governed record kind, e.g. "task" — also escalates StatusChip (lesson -> lavender). */
  recordType?: string
  /** Human label shown above the record ID, e.g. "Task". */
  kindLabel?: string
  title?: string
  description?: string
  status?: string
  priority?: string
  href?: string
  variant?: 'compact' | 'standard' | 'selectable'
  selected?: boolean
  onSelect?: () => void
  /** Extra accessory rendered in the header (e.g. a tier badge). */
  trailing?: ReactNode
}

export function RecordCard({
  recordId,
  recordType,
  kindLabel,
  title,
  description,
  status,
  priority,
  href,
  variant = 'compact',
  selected = false,
  onSelect,
  trailing,
}: RecordCardProps) {
  const className = `ev2-rc ev2-rc--${variant}${selected ? ' ev2-rc--selected' : ''}`

  const body = (
    <>
      <div className="ev2-rc__header">
        {kindLabel ? <span className="ev2-rc__kind">{kindLabel}</span> : null}
        <RecordId id={recordId} />
        {trailing}
      </div>
      {title ? <h4 className="ev2-rc__title">{title}</h4> : null}
      {description ? <p className="ev2-rc__desc">{description}</p> : null}
      {status ? (
        <div className="ev2-rc__footer">
          <StatusChip status={status} priority={priority} recordType={recordType} />
        </div>
      ) : null}
    </>
  )

  if (variant === 'selectable') {
    return (
      <button type="button" className={className} aria-pressed={selected} onClick={onSelect}>
        {body}
      </button>
    )
  }

  if (href) {
    return (
      <Link to={href} className={className} onClick={onSelect}>
        {body}
      </Link>
    )
  }

  return <article className={className}>{body}</article>
}
