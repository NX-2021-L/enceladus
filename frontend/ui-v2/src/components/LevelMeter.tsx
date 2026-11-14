/**
 * LevelMeter (ENC-TSK-S62-0B; Design System v1.1 spec DOC-8253497AC9FC sections 4.5 and 6.5).
 * A mono number with segments on a neutral ramp. Context scores use three segments
 * (0.7 and above high, 0.4 and above mid, below low); document maturity uses four.
 */
import './levelMeter.css'

export type LevelBand = 'high' | 'mid' | 'low'

export function scoreBand(score: number): LevelBand {
  if (score >= 0.7) return 'high'
  if (score >= 0.4) return 'mid'
  return 'low'
}

const MATURITY = ['raw', 'compliant', 'contextualized', 'mature'] as const

export function LevelMeter({
  label,
  value,
  segments = 3,
  on,
  band,
  title,
}: {
  label?: string
  /** Shown as the number (scores) or the stage name (maturity). */
  value: string
  segments?: number
  /** Filled segment count. */
  on: number
  band: LevelBand
  title?: string
}) {
  return (
    <span className="enc-level" data-level={band} title={title}>
      {label ? <span className="enc-level__label">{label}</span> : null}
      <span aria-hidden>
        {Array.from({ length: segments }, (_, i) => (
          <i key={i} data-on={i < on ? '' : undefined} />
        ))}
      </span>
      {value}
    </span>
  )
}

/** A 0..1 score as a three-segment meter. */
export function ScoreMeter({ label, score }: { label?: string; score: number }) {
  const band = scoreBand(score)
  return (
    <LevelMeter
      label={label}
      value={score.toFixed(2)}
      on={band === 'high' ? 3 : band === 'mid' ? 2 : 1}
      band={band}
      title={label ? `${label}: ${score.toFixed(3)}` : score.toFixed(3)}
    />
  )
}

/** Document maturity (raw, compliant, contextualized, mature) as a four-segment meter. */
export function MaturityMeter({ state }: { state?: string | null }) {
  const i = MATURITY.indexOf((state ?? '').trim().toLowerCase() as (typeof MATURITY)[number])
  if (i < 0) return null
  const band: LevelBand = i >= 2 ? 'high' : i === 1 ? 'mid' : 'low'
  return <LevelMeter value={MATURITY[i]} segments={4} on={i + 1} band={band} title={`Document maturity: ${MATURITY[i]}`} />
}
