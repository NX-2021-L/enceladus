/**
 * Status chip. Cloudscape StatusIndicator semantics (dot + label), re-branded
 * onto Enceladus DS tokens exclusively — no hard-coded hex. Unknown statuses
 * fall back to the muted/dust foreground.
 *
 * Governed escalation (FND-05):
 *  - priority P0, or status "blocked"  -> crimson + glow
 *  - lesson records (recordType="lesson") -> lavender, regardless of status
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
  p0: 'var(--status-p0)',
  lesson: 'var(--status-lesson)',
}

const GLOW_TOKEN: Record<string, string> = {
  p0: 'var(--glow-crimson)',
  blocked: 'var(--glow-crimson)',
  lesson: 'var(--glow-lavender)',
}

export function StatusChip({
  status,
  priority,
  recordType,
}: {
  status: string
  /** Optional governed priority (e.g. "P0"). P0 escalates to crimson+glow. */
  priority?: string
  /** Optional governed record kind. "lesson" escalates to lavender. */
  recordType?: string
}) {
  const isP0 = priority?.toLowerCase() === 'p0'
  const isLesson = recordType?.toLowerCase() === 'lesson'
  const key = isLesson ? 'lesson' : isP0 ? 'p0' : status.toLowerCase()

  const color = STATUS_TOKEN[key] ?? STATUS_TOKEN[status.toLowerCase()] ?? 'var(--fg-muted)'
  const glow = GLOW_TOKEN[key]

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
        boxShadow: glow ?? 'none',
      }}
    >
      <span
        aria-hidden
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: color,
          boxShadow: glow ?? '0 0 6px currentColor',
        }}
      />
      {status}
    </span>
  )
}
