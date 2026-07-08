import type { ReactNode } from 'react'
import { RecordId } from './RecordId'
import { StatusChip } from './StatusChip'
import { MarkdownContent } from './MarkdownContent'

/**
 * Shared card chrome for every primitive renderer. Void-emergent surface,
 * teal-alpha border, 8px radius (var(--radius-lg)), design-system type. Primitive
 * components fill `header` accessory, `title`, and `children` body.
 */
export function PrimitiveCard({
  recordId,
  kindLabel,
  title,
  status,
  priority,
  recordType,
  children,
}: {
  recordId: string
  kindLabel: string
  title: string
  status?: string
  priority?: string
  recordType?: string
  children: ReactNode
}) {
  return (
    <article
      style={{
        background: 'var(--bg-surface)',
        border: 'var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        padding: 'var(--space-8)',
        boxShadow: 'var(--shadow-md)',
        maxWidth: '68ch',
      }}
    >
      <header
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-3)',
          marginBottom: 'var(--space-4)',
          flexWrap: 'wrap',
        }}
      >
        <span
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 'var(--text-xs)',
            fontWeight: 'var(--fw-bold)',
            textTransform: 'uppercase',
            letterSpacing: '0.09em',
            color: 'var(--accent)',
          }}
        >
          {kindLabel}
        </span>
        <RecordId id={recordId} />
        {status ? <StatusChip status={status} priority={priority} recordType={recordType} /> : null}
      </header>

      <h3
        style={{
          fontFamily: 'var(--font-heading)',
          fontWeight: 'var(--fw-medium)',
          fontSize: 'var(--text-2xl)',
          lineHeight: 'var(--lh-snug)',
          color: 'var(--fg-display)',
          margin: '0 0 var(--space-5)',
        }}
      >
        {title}
      </h3>

      {children}
    </article>
  )
}

/** Label/value metadata row using dust labels + starlight values. */
export function MetaRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '10rem 1fr',
        gap: 'var(--space-4)',
        padding: 'var(--space-2) 0',
        borderTop: 'var(--border-divider)',
      }}
    >
      <span
        style={{
          fontFamily: 'var(--font-body)',
          fontSize: 'var(--text-xs)',
          fontWeight: 'var(--fw-medium)',
          textTransform: 'uppercase',
          letterSpacing: 'var(--tracking-label)',
          color: 'var(--fg-muted)',
        }}
      >
        {label}
      </span>
      <span style={{ color: 'var(--fg)', fontSize: 'var(--text-sm)' }}>{children}</span>
    </div>
  )
}

/** Body prose -- record description/observation text, rendered through the
 *  shared MarkdownContent component (ENC-TSK-M32) rather than a raw <p>, so
 *  descriptions get real markdown, inline ENC-*\/DOC-* ID auto-linking, and
 *  long-token wrapping. `projectId` resolves bare tracker-ID mentions found
 *  inline to a same-project detail route. */
export function Prose({ children, projectId }: { children: ReactNode; projectId?: string }) {
  const text = typeof children === 'string' ? children : ''
  return <MarkdownContent text={text} projectId={projectId} />
}

/** Mono metric value — tabular numerics, teal (Law 2 — fracture as detail). */
export function Metric({ children }: { children: ReactNode }) {
  return (
    <span
      style={{
        fontFamily: 'var(--font-mono)',
        fontVariantNumeric: 'tabular-nums',
        color: 'var(--accent)',
      }}
    >
      {children}
    </span>
  )
}
