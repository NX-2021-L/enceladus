import type { ReactNode } from 'react'
import { Link } from '@tanstack/react-router'
import { CopyIdButton } from './CopyIdButton'
import { RecordId } from './RecordId'
import { StatusPill } from './StatusPill'
import { railOverrides, statusRole } from '../status/statusRole'
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
  /** Governed record kind, e.g. "task". Picks the status vocabulary and, on the feed row, the default rail. */
  recordType?: string
  /** Human label shown above the record ID, e.g. "Task". */
  kindLabel?: string
  title?: string
  description?: string
  status?: string
  /** Kept for callers; priority is drawn by the badge strip, never by the status pill or rail. */
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
  /** Priority/CCI/PR/deploy Badge strip rendered after the StatusPill (PAR-02/03/04/05). */
  badges?: ReactNode
}

export function RecordCard({
  recordId,
  recordType,
  kindLabel,
  title,
  description,
  status,
  href,
  variant = 'compact',
  selected = false,
  onSelect,
  trailing,
  projectLabel,
  timestamp,
  badges,
}: RecordCardProps) {
  const className = `ev2-rc ev2-rc--${variant}${selected ? ' ev2-rc--selected' : ''}`
  // Feed rail (spec 4.4): record type by default; the status role's own rail for caution,
  // waiting and failed. Read from the same lookup as the pill, so the two cannot disagree.
  const role = status ? statusRole(recordType, status) : undefined
  const railAttrs =
    variant === 'feed'
      ? { 'data-type': recordType?.toLowerCase() || undefined, 'data-rail': role && railOverrides(role) ? role : undefined }
      : {}

  const body =
    variant === 'feed' ? (
      <>
        <div className="ev2-rc__feed-top">
          <span className="ev2-rc__feed-ids">
            <RecordId id={recordId} />
            {/* ENC-FTR-151 AC-1: the card itself is a link/button, so the copy control is a nested span[role=button]. */}
            <CopyIdButton id={recordId} nested />
            {projectLabel ? <span className="ev2-rc__feed-project">{projectLabel}</span> : null}
          </span>
          {timestamp ? <span className="ev2-rc__feed-time">{timestamp}</span> : null}
        </div>
        {title ? <div className="ev2-rc__feed-title">{title}</div> : null}
        {status || badges ? (
          <div className="ev2-rc__feed-chips">
            {status ? <StatusPill status={status} kind={recordType} /> : null}
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
            <StatusPill status={status} kind={recordType} />
          </div>
        ) : null}
      </>
    )

  if (variant === 'selectable') {
    return (
      <button type="button" className={className} {...railAttrs} aria-pressed={selected} onClick={onSelect}>
        {body}
      </button>
    )
  }

  if (href) {
    return (
      <Link to={href} className={className} {...railAttrs} onClick={onSelect}>
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
        {...railAttrs}
        aria-pressed={variant === 'feed' ? selected : undefined}
        onClick={onSelect}
      >
        {body}
      </button>
    )
  }

  return (
    <article className={className} {...railAttrs}>
      {body}
    </article>
  )
}
