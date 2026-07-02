/**
 * Status chip. Colors come exclusively from the design-system status tokens —
 * no hard-coded hex. Unknown statuses fall back to the muted/dust foreground.
 */

const STATUS_TOKEN: Record<string, string> = {
  open: 'var(--status-open)',
  'in-progress': 'var(--status-in-progress)',
  blocked: 'var(--status-blocked)',
  closed: 'var(--status-closed)',
  draft: 'var(--status-draft)',
  drafted: 'var(--status-draft)',
  started: 'var(--status-in-progress)',
  complete: 'var(--status-open)',
  completed: 'var(--status-open)',
  incomplete: 'var(--status-blocked)',
  planned: 'var(--status-draft)',
  production: 'var(--status-open)',
  deprecated: 'var(--status-closed)',
  active: 'var(--status-open)',
  archived: 'var(--status-closed)',
}

export function StatusChip({ status }: { status: string }) {
  const color = STATUS_TOKEN[status.toLowerCase()] ?? 'var(--fg-muted)'
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--space-2)',
        fontFamily: 'var(--font-heading)',
        fontSize: 'var(--text-xs)',
        fontWeight: 'var(--fw-medium)',
        textTransform: 'uppercase',
        letterSpacing: 'var(--tracking-label)',
        color,
        border: `1px solid ${color}`,
        borderRadius: 'var(--radius-sm)',
        padding: '2px var(--space-2)',
        background: 'transparent',
      }}
    >
      <span
        aria-hidden
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: color,
          boxShadow: '0 0 6px currentColor',
        }}
      />
      {status}
    </span>
  )
}
