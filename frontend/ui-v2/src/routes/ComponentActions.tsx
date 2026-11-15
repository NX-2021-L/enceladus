/** Lifecycle track, edges, actions and registration form (ENC-TSK-S84 slice 2). Gated on component.advance. */
import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Modal } from '../design-system'
import { useCanExecute } from '../auth/useCan'
import {
  COMPONENT_ID_PATTERN, MIN_REVERT_REASON, registerComponent, runLifecycleAction,
  type ComponentEdge, type ComponentFloor, type LifecycleAction, type RegistryComponent,
} from '../api/components'
import { LIFECYCLE_TRACK, OFF_TRACK, actionPlan, isGoverned } from './componentRegistry'

/** Same gate as the queue: no component.approve ActionId exists in the manifest vocabulary. */
const GATE = 'component.advance'

export function LifecycleTrack({ status }: { status: string | undefined }) {
  const idx = (LIFECYCLE_TRACK as readonly string[]).indexOf(status ?? '')
  const off = (OFF_TRACK as readonly string[]).includes(status ?? '')
  return (
    <div className="ev2-track" aria-label="Lifecycle">
      <ol className="ev2-track__steps">
        {LIFECYCLE_TRACK.map((s, i) => (
          <li
            key={s} className="ev2-track__step" data-state={i < idx ? 'done' : i === idx ? 'current' : 'todo'}
            aria-current={i === idx ? 'step' : undefined}
          >{s}</li>
        ))}
      </ol>
      <div className="ev2-track__off">
        {OFF_TRACK.map((s) => (
          <span key={s} className="ev2-track__offstate" data-state={status === s ? 'current' : 'todo'} aria-current={status === s ? 'step' : undefined}>{s}</span>
        ))}
        {!isGoverned(status) && status && <span className="ev2-reg__stored">{status} (not a governed status)</span>}
        {!off && idx < 0 && !status && <span className="ev2-reg__none">no lifecycle</span>}
      </div>
    </div>
  )
}

export function EdgeList({ edges }: { edges: ComponentEdge[] | undefined }) {
  if (!edges || edges.length === 0) return null
  return (
    <section className="ev2-reg__section">
      <h2 className="ev2-reg__h2">Edges</h2>
      <ul className="ev2-edges">
        {edges.map((e, i) => {
          const type = e.edge_type ?? e.relationship_type ?? 'edge'
          return (
            <li key={`${type}-${e.target_id ?? e.target ?? i}`} className="ev2-edges__row">
              <span className="ev2-edges__type">{type}</span> <code>{e.target_id ?? e.target ?? 'unknown'}</code>
              {e.locked !== undefined && <span className="ev2-edges__lock" data-locked={e.locked ? 'true' : 'false'}>{e.locked ? 'locked' : 'unlocked'}{e.lock_reason ? `: ${e.lock_reason}` : ''}</span>}
            </li>
          )
        })}
      </ul>
    </section>
  )
}

export function ComponentActions({ c }: { c: RegistryComponent }) {
  const can = useCanExecute(GATE)
  const qc = useQueryClient()
  const plan = actionPlan(c.lifecycle_status)
  const [open, setOpen] = useState<LifecycleAction | null>(null)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [done, setDone] = useState<string | null>(null)
  if (!can) return null

  async function run(action: LifecycleAction, arg?: string) {
    setBusy(true); setErr(null); setDone(null)
    try {
      await runLifecycleAction(c.component_id, action, arg)
      setDone(`${action} applied`)
      setOpen(null); setReason('')
      await qc.invalidateQueries({ queryKey: ['component-registry'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Request failed')
    } finally { setBusy(false) }
  }
  const needsReason = open === 'revert'
  const reasonOk = !needsReason || reason.trim().length >= MIN_REVERT_REASON
  const anyAction = plan.advance || plan.revert || plan.deprecate || plan.restore
  if (!anyAction) return null
  return (
    <section className="ev2-reg__section" aria-label="Actions">
      <h2 className="ev2-reg__h2">Actions</h2>
      {err && <Alert type="error" header="Not applied">{err}</Alert>}
      {done && <Alert type="success" header={done} />}
      <div className="ev2-queue__bar">
        {plan.advance && <Button variant="primary" disabled={busy} onClick={() => void run('advance', plan.advance)}>Advance to {plan.advance}</Button>}
        {plan.revert && <Button variant="normal" disabled={busy} onClick={() => { setReason(''); setOpen('revert') }}>Revert</Button>}
        {plan.deprecate && <Button variant="normal" disabled={busy} onClick={() => { setReason(''); setOpen('deprecate') }}>Deprecate</Button>}
        {plan.restore && <Button variant="normal" disabled={busy} onClick={() => void run('restore')}>Restore</Button>}
      </div>
      <Modal
        visible={open !== null}
        header={open === 'revert' ? `Revert ${c.component_id}` : `Deprecate ${c.component_id}`}
        onDismiss={() => setOpen(null)}
        footer={(
          <div className="ev2-queue__bar">
            <Button variant="normal" onClick={() => setOpen(null)}>Cancel</Button>
            <Button variant="primary" disabled={busy || !reasonOk} onClick={() => open && void run(open, reason)}>{open === 'revert' ? 'Revert' : 'Deprecate'}</Button>
          </div>
        )}
      >
        <label>Reason{open === 'deprecate' ? ' (optional)' : ''}
          <textarea className="ev2-queue__input" rows={3} aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
        {needsReason && !reasonOk && <span className="ev2-queue__err">At least {MIN_REVERT_REASON} characters.</span>}
      </Modal>
    </section>
  )
}

const FLOORS: ComponentFloor[] = ['code', 'external_deploy', 'documentation']
const CATEGORIES = ['lambda', 'frontend', 'infrastructure', 'library', 'workflow', 'external']

export function RegisterComponent() {
  const can = useCanExecute(GATE)
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [f, setF] = useState({ component_name: '', project_id: '', category: 'lambda', required_transition_type: 'code' as ComponentFloor, description: '', component_id: '' })
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  if (!can) return null
  const idOk = !f.component_id || COMPONENT_ID_PATTERN.test(f.component_id)
  const valid = f.component_name.trim() && f.project_id.trim() && f.description.trim() && idOk
  const set = (k: string, v: string) => setF((cur) => ({ ...cur, [k]: v }))
  async function submit() {
    setBusy(true); setErr(null)
    try {
      await registerComponent({ ...f, component_name: f.component_name.trim(), project_id: f.project_id.trim() })
      setOpen(false)
      setF({ ...f, component_name: '', description: '', component_id: '' })
      await qc.invalidateQueries({ queryKey: ['component-registry'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Request failed')
    } finally { setBusy(false) }
  }
  return (
    <>
      <Button variant="normal" onClick={() => setOpen(true)}>Register component</Button>
      <Modal
        visible={open} header="Register component" onDismiss={() => setOpen(false)}
        footer={(
          <div className="ev2-queue__bar">
            <Button variant="normal" onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="primary" disabled={busy || !valid} onClick={() => void submit()}>Register</Button>
          </div>
        )}
      >
        {err && <Alert type="error" header="Not registered">{err}</Alert>}
        <label>Name<input className="ev2-queue__input" aria-label="Component name" value={f.component_name} onChange={(e) => set('component_name', e.target.value)} /></label>
        <label>Project<input className="ev2-queue__input" aria-label="Project" value={f.project_id} onChange={(e) => set('project_id', e.target.value)} /></label>
        <label>Category
          <select className="ev2-queue__input" aria-label="Category" value={f.category} onChange={(e) => set('category', e.target.value)}>{CATEGORIES.map((c) => <option key={c}>{c}</option>)}</select>
        </label>
        <label>Floor
          <select className="ev2-queue__input" aria-label="Floor" value={f.required_transition_type} onChange={(e) => set('required_transition_type', e.target.value)}>{FLOORS.map((c) => <option key={c}>{c}</option>)}</select>
        </label>
        <label>Description<textarea className="ev2-queue__input" rows={3} aria-label="Description" value={f.description} onChange={(e) => set('description', e.target.value)} /></label>
        <label>Component ID (optional)<input className="ev2-queue__input" aria-label="Component ID" value={f.component_id} onChange={(e) => set('component_id', e.target.value)} /></label>
        {!idOk && <span className="ev2-queue__err">Must match comp-[a-z0-9][a-z0-9-]*</span>}
      </Modal>
    </>
  )
}
