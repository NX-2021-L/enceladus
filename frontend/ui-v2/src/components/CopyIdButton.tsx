import { useEffect, useRef, useState } from 'react'
import type { KeyboardEvent, MouseEvent } from 'react'
import { copyText } from '../utils/copyText'
import './copyIdButton.css'

/** How long the "Copied" confirmation stays visible (ENC-FTR-151 AC-2: ~1.5 s). */
export const COPIED_CONFIRMATION_MS = 1500

/**
 * ENC-TSK-R80-0H / ENC-FTR-151 — copy-the-bare-ID button.
 *
 * Rendered by RecordLink when `copyable` is set, and directly by RecordCard's
 * feed variant. Click (or Enter/Space) copies `id` without navigating
 * (preventDefault + stopPropagation), then shows a "Copied" confirmation.
 *
 * `nested` renders a `span[role=button]` instead of a `<button>` for use inside
 * an element that is itself a link or button (the whole feed card is one):
 * nested `<button>`/`<a>` is invalid HTML, so keyboard activation is handled
 * here and the event is kept away from the card.
 *
 * The hit area is >= 32px (see copyIdButton.css) via negative margins, so it
 * adds no height/width to the row and cannot wrap or shift layout.
 */
export function CopyIdButton({ id, nested = false }: { id: string; nested?: boolean }) {
  const [copied, setCopied] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current)
    },
    [],
  )

  const doCopy = async () => {
    const ok = await copyText(id)
    if (!ok) return
    setCopied(true)
    if (timer.current) clearTimeout(timer.current)
    timer.current = setTimeout(() => setCopied(false), COPIED_CONFIRMATION_MS)
  }

  const onClick = (e: MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    void doCopy()
  }

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key !== 'Enter' && e.key !== ' ') return
    e.preventDefault()
    e.stopPropagation()
    void doCopy()
  }

  const common = {
    className: `ev2-copy${copied ? ' ev2-copy--copied' : ''}`,
    'aria-label': `Copy ${id}`,
    'data-copy-id': id,
    onClick,
  }
  const icon = copied ? (
    <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false">
      <path d="M3 8.5l3.2 3.2L13 4.8" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ) : (
    <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false">
      <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" fill="none" stroke="currentColor" strokeWidth="1.4" />
      <path d="M10.5 3.5v-.5A1.5 1.5 0 0 0 9 1.5H3.5A1.5 1.5 0 0 0 2 3v5.5A1.5 1.5 0 0 0 3.5 10H4" fill="none" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  )
  const tip = copied ? (
    <span className="ev2-copy__tip" role="status">
      Copied
    </span>
  ) : null

  if (nested) {
    return (
      <span {...common} role="button" tabIndex={0} onKeyDown={onKeyDown}>
        {icon}
        {tip}
      </span>
    )
  }
  return (
    <button type="button" {...common}>
      {icon}
      {tip}
    </button>
  )
}
