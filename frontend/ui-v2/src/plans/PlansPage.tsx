/**
 * ENC-TSK-S98-0B (ENC-PLN-108 W3.2): the Plans page content, DOC-5E1E205FA664 sections 5.7 and 5.12, structure from the
 * approved canvas (Main.dc.html). Presentation only: it takes a corpus and a clock and fetches nothing. The route, the menu
 * entry and the corpus hook are W3.3; the animation layer is W4.
 *
 * Shipped components only: PageHeader, RecordLink, StatusPill, Tag, Select, Button, SkeletonCard and Alert.
 */
import { useEffect, useState } from 'react'
import { Alert, Button, Select } from '../design-system'
import { PageHeader } from '../components/PageHeader'
import { SkeletonCard } from '../components/SkeletonCard'
import { formatClockSecondsZone, toMs } from './format'
import type { TimeInput } from './lens/layoutTime'
import { PLAN_PAGE_SIZE, nextPlanCount, selectPlans } from './lens/selectPlans'
import { PlanCard } from './PlanCard'
import type { PlansRow } from './planView'
import { planViewsOf } from './planViews'
import { getDeviceWaveOverrideStore, useWaveOverrides, type WaveOverrideStore } from './waveOverrides'
import { usePlanMotion } from './motion'
import './plans.css'

export interface PlansPageProps {
  /** Every row the page may draw: plans, and the tasks and objectives their waves are made of. */
  corpus: readonly PlansRow[]
  /** The clock. Passed in so rendering reads none: an open bar runs to this instant. */
  now: TimeInput
  /** Corpus `lastSeededAt`; the freshness text is omitted when absent. */
  asOf?: TimeInput | null
  /** The corpus is older than it should be: the freshness dot takes the caution colour. */
  stale?: boolean
  loading?: boolean
  error?: string | null
  onRefresh?: () => void
  /** Where manual toggles are remembered; the device's own store when omitted. */
  overrideStore?: WaveOverrideStore
  /**
   * ENC-TSK-S98-0C (W3.3): the project filter, controlled. When omitted the page keeps its own state, which is what
   * the W3.2 tests and fixtures use; the /plans route passes it so the selection is mirrored in `?project=`.
   */
  project?: string
  onProjectChange?: (project: string) => void
}

const ALL_PROJECTS = { label: 'All projects', value: '' }

export function PlansPage({ corpus, now, asOf = null, stale = false, loading = false, error = null, onRefresh, overrideStore, project: projectProp, onProjectChange }: PlansPageProps) {
  const store = overrideStore ?? getDeviceWaveOverrideStore()
  const overrides = useWaveOverrides(store)
  const [ownProject, setOwnProject] = useState('')
  const [count, setCount] = useState(PLAN_PAGE_SIZE)
  // Controlled when the route supplies it, uncontrolled otherwise.
  const project = projectProp ?? ownProject
  const setProject = (next: string) => {
    if (projectProp === undefined) setOwnProject(next)
    onProjectChange?.(next)
  }

  // No hand-written memoisation: the React Compiler memoises these (AC-16).
  const projects = [...new Set(corpus.filter((r) => r.record_type.toLowerCase() === 'plan' && r.project_id).map((r) => r.project_id as string))].sort()
  const options = [ALL_PROJECTS, ...projects.map((p) => ({ label: p, value: p }))]
  const selected = options.find((o) => o.value === project) ?? ALL_PROJECTS

  const selection = selectPlans(corpus, { project, count })
  // ENC-TSK-S99-0B (W4.2): only the plans whose own rows changed are rebuilt. The corpus array gets a new identity
  // on every heal, so this has to be keyed on content -- see planViews.ts for why the row `version` is not enough.
  const views = planViewsOf(selection.plans, corpus, now)

  // ENC-TSK-S99-0A (W4.1): the change set drives the motion. Only the completion hold (D-10) needs holding here;
  // every other transition falls out of the lens state plus the transitions already in plans.css.
  const motion = usePlanMotion({ plans: selection.plans, rows: corpus })

  // A manual toggle is discarded once its wave's state or hotness has changed (D-3). The store holds the rule; this is the
  // only place that tells it what the waves are now.
  //
  // Keyed on the serialised wave states rather than on `views`, because `views` is a fresh array on every render even
  // when every card in it was a cache hit (W4.2) -- and reconcile writes to device storage, which an idle page must
  // not do once a minute for nothing (criterion 12).
  const liveWaves = JSON.stringify(
    Object.fromEntries(views.flatMap((v) => v.waves.map((w) => [w.key, { state: w.state, hot: w.hot }] as const))),
  )
  useEffect(() => {
    store.reconcile(JSON.parse(liveWaves) as Record<string, { state: 'todo' | 'active' | 'done'; hot: boolean }>)
  }, [store, liveWaves])

  const asOfMs = toMs(asOf)

  return (
    <div className="pl">
      <div className="pl-head">
        <div className="pl-head__title">
          <PageHeader title="Plans" count={selection.total} />
        </div>
        <div className="pl-tools">
          {asOfMs !== null ? (
            <span className="pl-fresh" data-stale={stale ? 'true' : undefined} title="Corpus lastSeededAt: moves on every heal">
              current as of {formatClockSecondsZone(asOfMs)}
            </span>
          ) : null}
          <button type="button" className="pl-iconbtn" aria-label="Refresh the corpus" onClick={onRefresh}>
            <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
              <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
              <path d="M21 3v5h-5" />
              <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
              <path d="M8 16H3v5" />
            </svg>
          </button>
          <div className="pl-filter">
            <Select
              selectedOption={selected}
              options={options}
              placeholder="Project"
              onChange={({ detail }: { detail: { selectedOption: { value: string } } }) => {
                setProject(detail.selectedOption.value)
                setCount(PLAN_PAGE_SIZE)
              }}
            />
          </div>
        </div>
      </div>

      <ul className="pl-legend" aria-label="How to read a lane">
        <li>
          <span className="pl-key">
            <span className="pl-c" style={{ left: '50%' }} />
          </span>
          Created
        </li>
        <li>
          <span className="pl-key">
            <span className="pl-wait" style={{ left: 0, width: '100%' }} />
          </span>
          Waiting for checkout
        </li>
        <li>
          <span className="pl-key">
            <span className="pl-work" data-role="done" style={{ left: 0, width: '100%' }} />
          </span>
          Checked out to closed
        </li>
        <li>
          <span className="pl-key">
            <span className="pl-work" data-role="active" data-open="true" style={{ left: 0, width: '100%' }} />
          </span>
          Checked out, still open
        </li>
        <li>
          <span className="pl-key">
            <span className="pl-z" style={{ left: '50%' }} />
          </span>
          Closed
        </li>
        <li>
          <span className="pl-key">
            <span className="pl-band" style={{ left: 0, width: '100%' }} />
          </span>
          Wave window
        </li>
        <li>
          <span className="pl-key">
            <span className="pl-gap" style={{ left: 0, width: '100%', top: 0, bottom: 0 }} />
          </span>
          Folded idle gap
        </li>
      </ul>

      {error ? (
        <Alert type="error" header="Plans could not be loaded">
          {error}
        </Alert>
      ) : loading ? (
        <SkeletonCard label="Loading plans" />
      ) : (
        <div className="pl-list">
          {views.length === 0 ? <p className="pl-empty">No plans in this project.</p> : null}
          {views.map((v) => (
            <PlanCard key={v.id} plan={v} overrides={overrides} onToggle={store.set} heldOpen={motion.heldOpen} />
          ))}
        </div>
      )}

      {selection.hasMore && !error && !loading ? (
        <div className="pl-foot">
          <Button variant="normal" onClick={() => setCount(nextPlanCount(count))}>
            Show {Math.min(PLAN_PAGE_SIZE, selection.remaining)} older plans
          </Button>
        </div>
      ) : null}
    </div>
  )
}
