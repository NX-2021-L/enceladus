/**
 * ENC-TSK-S98-0B (ENC-PLN-108 W3.2): one plan card (Main.dc.html). The card is the container the lane breakpoints are
 * measured on (`container-type: inline-size`): rows stack below 560px of CARD width, two columns from 560px and the
 * duration column from 880px, whatever the viewport is.
 *
 * Collapse rules: `shown()` of the lens decides each wave. A hot wave of a started or incomplete plan is open by default,
 * a manual toggle holds until the wave's state or hotness next changes (D-3), and a drafted plan collapses everything (R7).
 * A collapsed body stays in the document, as the canvas draws it, so W4 can animate its height; it is `inert` so its links
 * leave the tab order and the accessibility tree while it is closed.
 */
import { Fragment, useRef } from 'react'
import { RecordLink } from '../components/RecordLink'
import { StatusPill } from '../components/StatusPill'
import { Tag } from '../components/Pill'
import { makeOverride, shown, type WaveOverride } from './lens/waveState'
import type { PlanView } from './planView'
import { useFlipRows } from './motion'
import { TaskLane } from './TaskLane'
import { TimeAxis } from './TimeAxis'
import { WaveHeader } from './WaveHeader'
import type { WaveOverrideMap } from './waveOverrides'

const plural = (n: number, one: string, many: string): string => (n === 1 ? one : many)
const bodyIdOf = (key: string): string => `pl-body-${key.replace(/[^A-Za-z0-9_-]/g, '-')}`

export interface PlanCardProps {
  plan: PlanView
  overrides: WaveOverrideMap
  onToggle: (waveKey: string, override: WaveOverride) => void
  /**
   * ENC-TSK-S99-0A (W4.1, ruling D-10): wave keys a completion hold is keeping open. A wave's last task closing
   * makes it `done`, which would otherwise collapse it in the same frame its header turns to the done role -- so
   * the finish io asked to see would never be visible. The header still renders the done role throughout; the hold
   * only delays the collapse.
   */
  heldOpen?: ReadonlySet<string>
}

/**
 * The rows of one wave. It is its own component so FLIP can hold a ref and the previous row positions per wave --
 * a hook cannot run inside the waves map (ENC-TSK-S99-0A).
 */
function WaveBody({ bodyId, open, tasks }: { bodyId: string; open: boolean; tasks: PlanView['waves'][number]['tasks'] }) {
  const rows = useRef<HTMLDivElement | null>(null)
  useFlipRows(rows, tasks.map((t) => t.id))
  return (
    <div className="pl-body" id={bodyId} data-open={open ? 'true' : 'false'} inert={!open}>
      <div ref={rows}>
        {tasks.map((task) => (
          <TaskLane key={task.id} task={task} />
        ))}
      </div>
    </div>
  )
}

export function PlanCard({ plan, overrides, onToggle, heldOpen }: PlanCardProps) {
  const { stats } = plan
  return (
    <section className="pl-card" id={plan.id} aria-label={plan.id}>
      <div className="pl-card__top">
        <RecordLink id={plan.id} recordType="plan" className="enc-id" copyable />
        {plan.project ? <Tag code>{plan.project}</Tag> : null}
        {plan.createdAt ? <time dateTime={plan.createdAt}>created {plan.createdText}</time> : null}
      </div>
      <h2 className="pl-card__title">{plan.title}</h2>
      <div className="pl-card__chips">
        <StatusPill status={plan.status} kind="plan" />
        <p className="pl-sum">
          <b>{stats.nTasks}</b> tree {plural(stats.nTasks, 'task', 'tasks')} in <b>{stats.nWaves}</b> {plural(stats.nWaves, 'wave', 'waves')}, <b>{stats.nClosed}</b> closed
          {stats.hasStats ? (
            <span>
              {' '}
              · span <b>{stats.span}</b> · median wait <b>{stats.medianWait}</b>, work <b>{stats.medianWork}</b>
            </span>
          ) : null}
        </p>
        {plan.chips.map((id) => (
          <Tag key={id} code>
            {id}
          </Tag>
        ))}
        {plan.missing > 0 ? (
          <p className="pl-absent">
            {plan.missing} {plural(plan.missing, 'objective is', 'objectives are')} outside the corpus
          </p>
        ) : null}
      </div>
      <div className="pl-lanes">
        <TimeAxis axis={plan.axis} />
        {plan.waves.map((wave) => {
          const open = shown(wave.facts, plan.status, overrides[wave.key]) || (heldOpen?.has(wave.key) ?? false)
          const bodyId = bodyIdOf(wave.key)
          return (
            <Fragment key={wave.key}>
              <WaveHeader wave={wave} open={open} bodyId={bodyId} onToggle={() => onToggle(wave.key, makeOverride(wave.facts, !open))} />
              <WaveBody bodyId={bodyId} open={open} tasks={wave.tasks} />
            </Fragment>
          )
        })}
      </div>
    </section>
  )
}
