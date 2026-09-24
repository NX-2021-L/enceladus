import { useState } from 'react'
import type { ContextNodeMeta } from '../types/records'

function scoreColor(score: number): string {
  if (score >= 0.7) return 'var(--status-success-fg, #6ee7b7)'
  if (score >= 0.4) return 'var(--status-warning-fg, #fcd34d)'
  return 'var(--status-danger-fg, #fca5a5)'
}

function ScoreBadge({ label, value }: { label: string; value: number }) {
  return (
    <span
      title={`${label}: ${value.toFixed(3)}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--space-1)',
        padding: '2px var(--space-2)',
        borderRadius: 'var(--radius-sm)',
        fontSize: 'var(--text-xs)',
        fontFamily: 'var(--font-body)',
        background: 'color-mix(in srgb, var(--bg-elevated) 80%, transparent)',
        color: scoreColor(value),
      }}
    >
      <span style={{ opacity: 0.7 }}>{label}</span>
      {value.toFixed(2)}
    </span>
  )
}

export function ContextNodeBadges({ contextNode }: { contextNode?: ContextNodeMeta }) {
  const [expanded, setExpanded] = useState(false)
  if (!contextNode) return null

  const { freshness_score, structural_importance, information_density, access_frequency } =
    contextNode

  if (freshness_score === 0 && structural_importance === 0 && information_density === 0) {
    return null
  }

  return (
    <section
      style={{
        marginTop: 'var(--space-5)',
        padding: 'var(--space-4)',
        borderRadius: 'var(--radius-md)',
        border: 'var(--border-subtle)',
        background: 'var(--bg-elevated)',
      }}
    >
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-2)',
          width: '100%',
          background: 'none',
          border: 'none',
          padding: 0,
          cursor: 'pointer',
          color: 'var(--fg-muted)',
          fontFamily: 'var(--font-body)',
          fontSize: 'var(--text-xs)',
          textTransform: 'uppercase',
          letterSpacing: 'var(--tracking-label)',
        }}
      >
        Context scores
        <span aria-hidden>{expanded ? '▾' : '▸'}</span>
      </button>
      {expanded ? (
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 'var(--space-2)',
            marginTop: 'var(--space-3)',
          }}
        >
          <ScoreBadge label="Fresh" value={freshness_score} />
          <ScoreBadge label="Struct" value={structural_importance} />
          <ScoreBadge label="Dense" value={information_density} />
          {access_frequency > 0 ? (
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--fg-muted)' }}>
              Accessed {access_frequency}×
            </span>
          ) : null}
        </div>
      ) : null}
    </section>
  )
}
