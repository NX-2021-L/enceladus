import { useState } from 'react'
import { ScoreMeter } from './LevelMeter'
import type { ContextNodeMeta } from '../types/records'

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
        borderWidth: 1, borderStyle: 'solid', borderColor: 'var(--border)',
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
          color: 'var(--text-dim)',
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
          <ScoreMeter label="Fresh" score={freshness_score} />
          <ScoreMeter label="Struct" score={structural_importance} />
          <ScoreMeter label="Dense" score={information_density} />
          {access_frequency > 0 ? (
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-dim)' }}>
              Accessed {access_frequency}×
            </span>
          ) : null}
        </div>
      ) : null}
    </section>
  )
}
