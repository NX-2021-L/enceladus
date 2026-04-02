/**
 * ContextNodeBadges — collapsible score badges for context node metadata.
 * Shows freshness, structural importance, and information density scores.
 * (ENC-ISS-138 / ENC-FTR-050 / ENC-TSK-A57)
 */

import { useState } from 'react'
import type { ContextNodeMeta } from '../../types/feeds'

function scoreColor(score: number): string {
  if (score >= 0.7) return 'bg-emerald-500/20 text-emerald-400'
  if (score >= 0.4) return 'bg-amber-500/20 text-amber-400'
  return 'bg-red-500/20 text-red-400'
}

function ScoreBadge({ label, value }: { label: string; value: number }) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium ${scoreColor(value)}`}
      title={`${label}: ${value.toFixed(3)}`}
    >
      <span className="text-[9px] opacity-70">{label}</span>
      {value.toFixed(2)}
    </span>
  )
}

interface ContextNodeBadgesProps {
  contextNode: ContextNodeMeta
  /** Compact mode for feed cards (single row, fewer details) */
  compact?: boolean
}

export function ContextNodeBadges({ contextNode, compact = false }: ContextNodeBadgesProps) {
  const [expanded, setExpanded] = useState(false)

  const { freshness_score, structural_importance, information_density, access_frequency } = contextNode

  // Don't render if all scores are zero (no context node data)
  if (freshness_score === 0 && structural_importance === 0 && information_density === 0) {
    return null
  }

  if (compact) {
    // Compact: single composite indicator
    const composite = (freshness_score + structural_importance + information_density) / 3
    return (
      <span
        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium ${scoreColor(composite)}`}
        title={`Context: F=${freshness_score.toFixed(2)} S=${structural_importance.toFixed(2)} D=${information_density.toFixed(2)}`}
      >
        <svg className="w-2.5 h-2.5" fill="currentColor" viewBox="0 0 20 20">
          <path d="M10 2a8 8 0 100 16 8 8 0 000-16zM8 12a2 2 0 114 0H8z" />
        </svg>
        {composite.toFixed(2)}
      </span>
    )
  }

  return (
    <div className="bg-slate-800 rounded-lg p-3">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-2 w-full text-left"
      >
        <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider">
          Context Scores
        </h3>
        <svg
          className={`w-3 h-3 text-slate-500 transition-transform ${expanded ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {expanded && (
        <div className="flex flex-wrap items-center gap-1.5 mt-2">
          <ScoreBadge label="Fresh" value={freshness_score} />
          <ScoreBadge label="Struct" value={structural_importance} />
          <ScoreBadge label="Dense" value={information_density} />
          {access_frequency > 0 && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-slate-600/50 text-slate-400">
              Accessed: {access_frequency}x
            </span>
          )}
        </div>
      )}
    </div>
  )
}
