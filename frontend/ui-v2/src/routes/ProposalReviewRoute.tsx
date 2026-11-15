/** /component-registry/proposals/$ref: review one proposal (push-notification deep link). ENC-TSK-S84 slice 2. */
import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from '@tanstack/react-router'
import { Alert, Button, Modal } from '../design-system'
import { PageHeader } from '../components/PageHeader'
import { Tag } from '../components/Pill'
import { useCanExecute } from '../auth/useCan'
import { useApprovalQueue } from '../approvals/useApprovalQueue'
import type { Verdict } from '../approvals/types'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import {
  COMPONENT_ID_PATTERN, MIN_REJECT_REASON, componentProposalAdapter, getProposal,
  type ComponentFloor, type ComponentProposal, type ProposalPayload,
} from '../api/components'
import { floorClass } from './componentRegistry'
import './componentRegistry.css'

const FLOORS: ComponentFloor[] = ['code', 'external_deploy', 'documentation']

export function ProposalReviewRoute() {
  const { ref = '' } = useParams({ strict: false }) as { ref?: string }
  useDocumentTitle('Proposal review')
  const canDecide = useCanExecute('component.advance')
  const adapter = useMemo(() => ({ ...componentProposalAdapter, list: async () => [await getProposal(ref)] }), [ref])
  const q = useApprovalQueue(adapter)
  const [verdict, setVerdict] = useState<Verdict | null>(null)
  const [id, setId] = useState('')
  const [floor, setFloor] = useState<ComponentFloor>('code')
  const [reason, setReason] = useState('')
  const p: ComponentProposal | undefined = q.items[0]

  useEffect(() => { if (p) q.setSelection([p.component_id]) }, [p?.component_id, p?.version]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!p) return
    setId(p.suggested_component_id ?? '')
    const f = floorClass(p.requested_minimum_transition_type ?? '')
    setFloor((FLOORS as string[]).includes(f ?? '') ? (f as ComponentFloor) : 'code')
  }, [p?.component_id, p?.version]) // eslint-disable-line react-hooks/exhaustive-deps

  const last = q.results[q.results.length - 1]
  const decided = last?.state === 'ok'
  const valid = verdict === 'approve' ? COMPONENT_ID_PATTERN.test(id) : reason.trim().length >= MIN_REJECT_REASON

  async function confirm() {
    if (!verdict) return
    const v = verdict
    setVerdict(null)
    await q.decideSelected(v, (): ProposalPayload => (v === 'approve'
      ? { verdict: 'approve', component_id: id, required_transition_type: floor }
      : { verdict: 'reject', rejection_reason: reason.trim() }))
  }

  return (
    <div className="ev2-page">
      <PageHeader title={p?.component_name ?? 'Proposal review'} description={ref} />
      {q.loadError && <Alert type="error" header="Could not load the proposal">{q.loadError}</Alert>}
      {last && last.state === 'ok' && (
        <Alert type="success" header={last.verdict === 'approve' ? `Approved. Minted component ID ${last.outcome?.component_id ?? '(see registry)'}` : 'Rejected. No component was created.'} />
      )}
      {last && last.state !== 'ok' && (
        <Alert type={last.state === 'conflict' ? 'warning' : 'error'} header="Not applied">
          {`${last.status ?? ''} ${last.message ?? ''}`.trim()}{last.state === 'conflict' ? '. The proposal below is refreshed.' : ''}
        </Alert>
      )}
      {p && p.proposal_status && p.proposal_status !== 'pending' && !decided && (
        <Alert type="info" header={`This proposal is already ${p.proposal_status}`} />
      )}
      {p && (
        <div className="ev2-queue__bar" role="group" aria-label="Decide">
          <Button variant="primary" disabled={!canDecide || decided || q.progress.running || (!!p.proposal_status && p.proposal_status !== 'pending')} onClick={() => setVerdict('approve')}>Approve</Button>
          <Button variant="normal" disabled={!canDecide || decided || q.progress.running || (!!p.proposal_status && p.proposal_status !== 'pending')} onClick={() => { setReason(''); setVerdict('reject') }}>Reject</Button>
          {!canDecide && <span className="ev2-queue__sug">Deciding needs execute permission.</span>}
        </div>
      )}
      {p && (
        <section className="ev2-reg__section">
          <p>Suggested ID: <code>{p.suggested_component_id ?? 'none'}</code> (suggestion, not yet minted)</p>
          <p><Tag code>{p.project_id}</Tag> <Tag>{p.category}</Tag> <Tag>{floorClass(p.requested_minimum_transition_type ?? '') || 'no floor'}</Tag></p>
          <p className="ev2-queue__paths">Source paths: {Object.values(p.source_paths ?? {}).join(', ') || 'none'}</p>
          <p>Proposed by {p.proposing_agent_session_id ?? 'unknown'} at {(p.proposed_at ?? '').replace('T', ' ').slice(0, 16) || 'unknown'}</p>
        </section>
      )}
      <Link to="/component-registry" className="ev2-reg__back">Back to the registry</Link>
      <Modal
        visible={verdict !== null}
        header={verdict === 'approve' ? 'Approve proposal' : 'Reject proposal'}
        onDismiss={() => setVerdict(null)}
        footer={(
          <div className="ev2-queue__bar">
            <Button variant="normal" onClick={() => setVerdict(null)}>Cancel</Button>
            <Button variant="primary" disabled={!valid} onClick={() => void confirm()}>{verdict === 'approve' ? 'Approve' : 'Reject'}</Button>
          </div>
        )}
      >
        {verdict === 'approve' ? (
          <>
            <label>Component ID<input className="ev2-queue__input" aria-label="Component ID" value={id} onChange={(e) => setId(e.target.value)} /></label>
            {!COMPONENT_ID_PATTERN.test(id) && <span className="ev2-queue__err">Must match comp-[a-z0-9][a-z0-9-]*</span>}
            <label>Floor
              <select className="ev2-queue__input" aria-label="Floor" value={floor} onChange={(e) => setFloor(e.target.value as ComponentFloor)}>{FLOORS.map((f) => <option key={f}>{f}</option>)}</select>
            </label>
          </>
        ) : (
          <>
            <label>Reason<textarea className="ev2-queue__input" rows={3} aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} /></label>
            {reason.trim().length < MIN_REJECT_REASON && <span className="ev2-queue__err">At least {MIN_REJECT_REASON} characters.</span>}
          </>
        )}
      </Modal>
    </div>
  )
}
