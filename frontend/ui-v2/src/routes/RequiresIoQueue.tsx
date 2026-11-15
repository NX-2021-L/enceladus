/**
 * "Requires io" queue on the registry page (ENC-TSK-S84 slice 1). Pending proposals only: a row never shows
 * a component ID as existing. The suggested ID is labelled; the minted ID appears only in the results.
 */
import { useState } from 'react'
import { Button, Flashbar, Modal, Select } from '../design-system'
import { Table } from '../components/StackedTable'
import { Tag } from '../components/Pill'
import { useCanExecute } from '../auth/useCan'
import { useApprovalQueue } from '../approvals/useApprovalQueue'
import type { Verdict } from '../approvals/types'
import {
  COMPONENT_ID_PATTERN, MIN_REJECT_REASON, componentProposalAdapter,
  type ComponentFloor, type ComponentProposal, type ProposalPayload,
} from '../api/components'
import { floorClass } from './componentRegistry'

const FLOORS: ComponentFloor[] = ['code', 'external_deploy', 'documentation']
/** No component.approve ActionId exists in the manifest vocabulary; component.advance is the nearest decider gate. */
const DECIDE_GATE = 'component.advance'

interface Draft { id: string; floor: ComponentFloor; reason: string }
type Drafts = Record<string, Draft>

function draftFor(p: ComponentProposal): Draft {
  const f = floorClass(p.requested_minimum_transition_type ?? '')
  return { id: p.suggested_component_id ?? '', floor: (FLOORS as string[]).includes(f) ? (f as ComponentFloor) : 'code', reason: '' }
}

export function draftValid(verdict: Verdict, d: Draft): boolean {
  return verdict === 'approve' ? COMPONENT_ID_PATTERN.test(d.id) : d.reason.trim().length >= MIN_REJECT_REASON
}

export function RequiresIoQueue() {
  const canDecide = useCanExecute(DECIDE_GATE)
  const q = useApprovalQueue(componentProposalAdapter)
  const [verdict, setVerdict] = useState<Verdict | null>(null)
  const [drafts, setDrafts] = useState<Drafts>({})

  function open(v: Verdict) {
    setDrafts(Object.fromEntries(q.selectedItems.map((p) => [p.component_id, draftFor(p)])))
    setVerdict(v)
  }
  const patch = (k: string, d: Partial<Draft>) => setDrafts((cur) => ({ ...cur, [k]: { ...cur[k]!, ...d } }))
  const allValid = verdict !== null && q.selectedItems.length > 0 && q.selectedItems.every((p) => draftValid(verdict, drafts[p.component_id] ?? draftFor(p)))

  async function confirm() {
    if (!verdict) return
    const v = verdict
    setVerdict(null)
    await q.decideSelected(v, (p): ProposalPayload => {
      const d = drafts[p.component_id] ?? draftFor(p)
      return v === 'approve'
        ? { verdict: 'approve', component_id: d.id, required_transition_type: d.floor }
        : { verdict: 'reject', rejection_reason: d.reason.trim() }
    })
  }

  const flash = q.results.map((r) => ({
    id: `${r.key}-${r.verdict}`,
    type: r.state === 'ok' ? 'success' : r.state === 'conflict' ? 'warning' : 'error',
    dismissible: true,
    header: r.state === 'ok'
      ? (r.verdict === 'approve' ? `Approved ${r.key}` : `Rejected ${r.key}`)
      : `${r.verdict === 'approve' ? 'Approve' : 'Reject'} not applied: ${r.key}`,
    content: r.state === 'ok'
      ? (r.verdict === 'approve' ? `Minted component ID ${r.outcome?.component_id ?? '(see registry)'}` : 'Proposal rejected; no component was created.')
      : `${r.status ?? ''} ${r.message ?? ''}`.trim() + (r.state === 'conflict' ? '. The row stays in the queue.' : ''),
  }))

  const columns = [
    { id: 'name', header: 'Proposed name', cell: (p: ComponentProposal) => (
      <span>{p.component_name}<br /><span className="ev2-queue__sug">Suggested ID: <code>{p.suggested_component_id ?? 'none'}</code> (suggestion, not yet minted)</span></span>
    ) },
    { id: 'project', header: 'Project', cell: (p: ComponentProposal) => <Tag code>{p.project_id}</Tag> },
    { id: 'category', header: 'Category', cell: (p: ComponentProposal) => <Tag>{p.category}</Tag> },
    { id: 'floor', header: 'Requested floor', cell: (p: ComponentProposal) => <Tag>{floorClass(p.requested_minimum_transition_type ?? '') || 'none'}</Tag> },
    { id: 'paths', header: 'Source paths', cell: (p: ComponentProposal) => (
      <span className="ev2-queue__paths">{Object.values(p.source_paths ?? {}).join(', ') || 'none'}</span>
    ) },
    { id: 'session', header: 'Proposed by', cell: (p: ComponentProposal) => p.proposing_agent_session_id ?? 'none' },
    { id: 'when', header: 'Proposed', cell: (p: ComponentProposal) => (p.proposed_at ?? '').replace('T', ' ').slice(0, 16) || 'none' },
  ]

  if (!q.loading && !q.loadError && q.items.length === 0 && q.results.length === 0) return null
  const n = q.selectedItems.length
  return (
    <section className="ev2-queue" aria-label="Requires io">
      <h2 className="ev2-reg__h2">Requires io {q.items.length > 0 && <span className="ev2-reg__segcount">{q.items.length}</span>}</h2>
      {flash.length > 0 && <Flashbar items={flash} />}
      {q.loadError && <div className="ev2-queue__err">Could not load proposals: {q.loadError}</div>}
      <div className="ev2-queue__bar">
        <Button variant="primary" disabled={!canDecide || n === 0 || q.progress.running} onClick={() => open('approve')}>Approve{n > 0 ? ` (${n})` : ''}</Button>
        <Button variant="normal" disabled={!canDecide || n === 0 || q.progress.running} onClick={() => open('reject')}>Reject{n > 0 ? ` (${n})` : ''}</Button>
        {q.progress.running && <span>Deciding {q.progress.done} of {q.progress.total}…</span>}
        {!canDecide && <span className="ev2-queue__sug">Deciding needs execute permission.</span>}
      </div>
      <Table
        columnDefinitions={columns}
        items={q.loading ? [] : q.items}
        trackBy="component_id"
        selectionType="multi"
        selectedItems={q.selectedItems}
        onSelectionChange={({ detail }: { detail: { selectedItems: ComponentProposal[] } }) => q.setSelection(detail.selectedItems.map((i) => i.component_id))}
        empty={q.loading ? 'Loading proposals…' : 'No pending proposals.'}
      />
      <Modal
        visible={verdict !== null}
        header={verdict === 'approve' ? `Approve ${n} proposal${n === 1 ? '' : 's'}` : `Reject ${n} proposal${n === 1 ? '' : 's'}`}
        size="large"
        onDismiss={() => setVerdict(null)}
        footer={(
          <div className="ev2-queue__bar">
            <Button variant="normal" onClick={() => setVerdict(null)}>Cancel</Button>
            <Button variant="primary" disabled={!allValid} onClick={() => void confirm()}>
              {verdict === 'approve' ? 'Approve each' : 'Reject each'}
            </Button>
          </div>
        )}
      >
        <p>Each proposal is decided on its own, with its own request.</p>
        {q.selectedItems.map((p) => {
          const d = drafts[p.component_id] ?? draftFor(p)
          return (
            <div key={p.component_id} className="ev2-queue__item">
              <strong>{p.component_name}</strong>
              {verdict === 'approve' ? (
                <>
                  <label>Component ID<input className="ev2-queue__input" aria-label={`Component ID for ${p.component_name}`} value={d.id} onChange={(e) => patch(p.component_id, { id: e.target.value })} /></label>
                  {!COMPONENT_ID_PATTERN.test(d.id) && <span className="ev2-queue__err">Must match comp-[a-z0-9][a-z0-9-]*</span>}
                  <label>Floor
                    <Select
                      selectedOption={{ label: d.floor, value: d.floor }}
                      options={FLOORS.map((f) => ({ label: f, value: f }))}
                      onChange={({ detail }: { detail: { selectedOption: { value: string } } }) => patch(p.component_id, { floor: detail.selectedOption.value as ComponentFloor })}
                    />
                  </label>
                </>
              ) : (
                <>
                  <label>Reason<textarea className="ev2-queue__input" rows={2} aria-label={`Reason for ${p.component_name}`} value={d.reason} onChange={(e) => patch(p.component_id, { reason: e.target.value })} /></label>
                  {d.reason.trim().length < MIN_REJECT_REASON && <span className="ev2-queue__err">At least {MIN_REJECT_REASON} characters.</span>}
                </>
              )}
            </div>
          )
        })}
      </Modal>
    </section>
  )
}
