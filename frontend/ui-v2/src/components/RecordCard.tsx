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
  variant?: 'compact' | 'standard' | 'selectable' | 'feed'
  selected?: boolean
  onSelect?: () => void
  /** Extra accessory rendered in the header (e.g. a tier badge). */
  trailing?: ReactNode
  /**
   * ENC-TSK-M35 -- dense feed-row extras (Enceladus-v4-Feed-Review.md §3/§4).
   * Only consumed by `variant="feed"`.
   */
  projectLabel?: string
  /** Pre-formatted relative time ("37m ago"), PAR-01. Omitted when unknown. */
  timestamp?: string
  /** 3px left-accent color, e.g. from `feedRowAccent()` (PAR-06, §4.5/§5.4). */
  accentColor?: string
  /** Priority/CCI/PR/deploy Badge strip rendered after the StatusChip (PAR-02/03/04/05). */
  badges?: ReactNode
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
  projectLabel,
  timestamp,
  accentColor,
  badges,
}: RecordCardProps) {
  const className = `ev2-rc ev2-rc--${variant}${selected ? ' ev2-rc--selected' : ''}`
  const style = variant === 'feed' && accentColor ? { borderLeftColor: accentColor } : undefined

  const body =
    variant === 'feed' ? (
      <>
        <div className="ev2-rc__feed-top">
          <span className="ev2-rc__feed-ids">
            <RecordId id={recordId} />
            {projectLabel ? <span className="ev2-rc__feed-project">{projectLabel}</span> : null}
          </span>
          {timestamp ? <span className="ev2-rc__feed-time">{timestamp}</span> : null}
        </div>
        {title ? <div className="ev2-rc__feed-title">{title}</div> : null}
        {status || badges ? (
          <div className="ev2-rc__feed-chips">
            {status ? <StatusChip status={status} priority={priority} recordType={recordType} /> : null}
            {badges}
          </div>
        ) : null}
      </>
    ) : (
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
      <button type="button" className={className} style={style} aria-pressed={selected} onClick={onSelect}>
        {body}
      </button>
    )
  }

  if (href) {
    return (
      <Link to={href} className={className} style={style} onClick={onSelect}>
        {body}
      </Link>
    )
  }

  // ENC-TSK-M35: a "feed" row with no href (wide master-detail viewport,
  // FTR-128 AC-18) still needs to be clickable to drive the reading pane —
  // render as a button rather than an inert <article> whenever a caller
  // supplies onSelect without a navigable href.
  if (onSelect) {
    return (
      <button
        type="button"
        className={className}
        style={style}
        aria-pressed={variant === 'feed' ? selected : undefined}
        onClick={onSelect}
      >
        {body}
      </button>
    )
  }

  return (
    <article className={className} style={style}>
      {body}
    </article>
  )
}
