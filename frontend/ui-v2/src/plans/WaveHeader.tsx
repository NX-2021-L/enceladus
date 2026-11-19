/**
 * ENC-TSK-S98-0B (ENC-PLN-108 W3.2): one wave header row (Main.dc.html, States.dc.html).
 *
 * The toggle is a real <button> with aria-expanded. Its `::after` (plans.css) is stretched over the whole row at z-index 1,
 * and the wave parent's record link sits at z-index 2 (`.pl a.enc-id`), so the row toggles from anywhere EXCEPT the link:
 * following the parent never opens or closes the wave. The link is a sibling of the button, never inside it.
 */
import { RecordLink } from '../components/RecordLink'
import { StatusPill } from '../components/StatusPill'
import { pct } from './TimeAxis'
import type { WaveView } from './planView'

export function WaveHeader({ wave, open, bodyId, onToggle }: { wave: WaveView; open: boolean; bodyId: string; onToggle: () => void }) {
  return (
    <div className="pl-row pl-wave" data-state={wave.state}>
      <div className="pl-lab">
        <button type="button" className="pl-toggle" aria-expanded={open} aria-controls={bodyId} aria-label={wave.ariaLabel(open)} onClick={onToggle}>
          <svg className="pl-chev" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="m9 18 6-6-6-6" />
          </svg>
          <span className="pl-wtag">{wave.tag}</span>
        </button>
        {wave.parentId ? <RecordLink id={wave.parentId} recordType="task" className="enc-id" /> : null}
        <span className="pl-ttl">{wave.title}</span>
        <StatusPill status={wave.tally} role={wave.state} />
      </div>
      <div className="pl-track">
        {wave.band ? <span className="pl-band" data-open={wave.band.open ? 'true' : undefined} style={{ left: pct(wave.band.leftPct), width: pct(wave.band.widthPct) }} /> : null}
      </div>
      <div className="pl-dur">
        <span />
        <span>{wave.windowText}</span>
      </div>
    </div>
  )
}
