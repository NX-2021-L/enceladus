import type { PillarScores } from '../../types/feeds'

interface PillarScoreChartProps {
  pillarScores: PillarScores
  pillarComposite: number
  resonanceScore: number
}

const PILLARS: { key: keyof PillarScores; label: string; color: string }[] = [
  { key: 'efficiency', label: 'Efficiency', color: 'bg-cyan-400' },
  { key: 'human_protection', label: 'Human Protection', color: 'bg-emerald-400' },
  { key: 'intention', label: 'Intention', color: 'bg-amber-400' },
  { key: 'alignment', label: 'Alignment', color: 'bg-violet-400' },
]

export function PillarScoreChart({ pillarScores, pillarComposite, resonanceScore }: PillarScoreChartProps) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-4 mb-2">
        <div className="text-center">
          <div className="text-2xl font-bold text-purple-300">{pillarComposite.toFixed(3)}</div>
          <div className="text-xs text-slate-500">Composite</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-cyan-300">{resonanceScore.toFixed(3)}</div>
          <div className="text-xs text-slate-500">Resonance</div>
        </div>
      </div>
      <div className="space-y-2">
        {PILLARS.map(({ key, label, color }) => {
          const value = pillarScores[key] ?? 0
          return (
            <div key={key} className="flex items-center gap-2">
              <span className="text-xs text-slate-400 w-32 flex-shrink-0">{label}</span>
              <div className="flex-1 h-3 bg-slate-700 rounded-full overflow-hidden">
                <div
                  className={`h-full ${color} rounded-full transition-all`}
                  style={{ width: `${Math.min(value * 100, 100)}%` }}
                />
              </div>
              <span className="text-xs font-mono text-slate-400 w-8 text-right">
                {value.toFixed(2)}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
