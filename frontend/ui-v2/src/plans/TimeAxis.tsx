/**
 * ENC-TSK-S98-0B (ENC-PLN-108 W3.2): the plan's time axis and the layer behind its rows (grid lines, folded gaps, now).
 * Markup follows the approved canvas (Main.dc.html): `.pl-over` is the decorative layer, `.pl-axis` the header row.
 */
import type { CSSProperties } from 'react'
import type { AxisView } from './planView'

export const pct = (n: number): string => `${n.toFixed(2)}%`

export function TimeAxis({ axis }: { axis: AxisView }) {
  return (
    <>
      <div className="pl-over" aria-hidden="true">
        {axis.gridsPct.map((x, i) => (
          <span key={`g${i}`} className="pl-grid" style={{ left: pct(x) }} />
        ))}
        {axis.gaps.map((g, i) => (
          <span key={`f${i}`} className="pl-gap" style={{ left: pct(g.leftPct), width: pct(g.widthPct) }} />
        ))}
        {axis.hasNow ? <span className="pl-now" /> : null}
      </div>
      <div className="pl-row pl-axis">
        <div className="pl-lab">Wave / task</div>
        <div className="pl-track" aria-hidden="true">
          {axis.days.map((d, i) => (
            <span key={`d${i}`} className="pl-day" style={d.leftPct === null ? { right: 0 } : { left: pct(d.leftPct) }}>
              {d.label}
            </span>
          ))}
          {axis.ticks.map((t, i) => {
            const style: CSSProperties = t.fold ? { left: pct(t.leftPct), color: 'var(--text-dim-raised)' } : { left: pct(t.leftPct) }
            return (
              <span key={`t${i}`} className="pl-tick" data-fold={t.fold ? 'true' : undefined} style={style}>
                {t.label}
              </span>
            )
          })}
        </div>
        <div className="pl-dur">
          <span>wait</span>
          <span>work</span>
        </div>
      </div>
    </>
  )
}
