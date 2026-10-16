/**
 * Escalations cockpit (DVP-TSK-A20, io request 2026-10-12): the pre-970 look and feel
 * (PageHeader, pending/terminal tabs, StackedTable rows, modal decide flow) rendered on the
 * consolidated hub data. One all-projects feed, every gate kind; verdicts go through the
 * @io-kit/gates decide path (escalationCockpit.ts). Compact mode is the home requires-io slot.
 * State ownership: records live in TanStack Query; useState holds only view state (the open
 * row key, bucket, draft note, chosen candidate).
 */
import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { allowedVerdicts, approve, cardFromConflict, deny, type Verdict } from '@io-kit/gates'
import { DiffView, ProposedCallPreview } from '@io-kit/gates/react'
import { Alert, Button, Container, FormField, Header, KeyValuePairs, Modal } from '../design-system'
import { Table } from '../components/StackedTable'
import { Tabs } from '../components/StripTabs'
import { Badge } from '../components/Badge'
import { StatusChip } from '../components/StatusChip'
import { RecordLink } from '../components/RecordLink'
import { useCanExecute } from '../auth/useCan'
import { useEscalationRealtimeNonce } from './GateInboxPanel'
import { decideCard, describeError, describeReceipt, fetchCockpitFeed, type CockpitNotice } from './escalationCockpit'
import { countByBucket, filterRows, toEscalationRows, type EscalationBucket, type EscalationRow } from './escalationRows'
import { EscalationPushNudge } from '../notifications/EscalationPushNudge'
import { notifyApi } from '../notifications/notifyApi'
import './escalations.css'

const POLL_INTERVAL_MS = 30_000
const COMPACT_LIMIT = 8
const FEED_KEY = 'escalation-cockpit'

export function EscalationsCockpit({ compact = false, onPendingCount, focusId }: { compact?: boolean; onPendingCount?: (n: number) => void; focusId?: string }) {
  const queryClient = useQueryClient()
  const [bucket, setBucket] = useState<EscalationBucket>('pending')
  const [openKey, setOpenKey] = useState<string | null>(null)
  const [note, setNote] = useState('')
  const [candidateId, setCandidateId] = useState<string | undefined>(undefined)
  const [deciding, setDeciding] = useState(false)
  const [notice, setNotice] = useState<CockpitNotice | null>(null)
  const canDecide = useCanExecute('escalation.request')

  const feedQuery = useQuery({
    queryKey: [FEED_KEY, compact],
    queryFn: () => fetchCockpitFeed(compact),
    refetchInterval: POLL_INTERVAL_MS,
  })
  const realtimeNonce = useEscalationRealtimeNonce()
  useEffect(() => {
    if (realtimeNonce > 0) void queryClient.invalidateQueries({ queryKey: [FEED_KEY] })
  }, [realtimeNonce, queryClient])

  const rows = toEscalationRows(feedQuery.data?.cards ?? [])
  const counts = countByBucket(rows)
  const pendingCount = counts.pending
  useEffect(() => { onPendingCount?.(pendingCount) }, [pendingCount, onPendingCount])
  const visibleRows = compact ? filterRows(rows, 'pending').slice(0, COMPACT_LIMIT) : filterRows(rows, bucket)
  const focusRow = focusId ? (rows.find((r) => r.id === focusId) ?? null) : null
  const openRow = openKey ? (rows.find((r) => r.key === openKey) ?? null) : null

  function closeModal() {
    setOpenKey(null)
    setNote('')
    setCandidateId(undefined)
  }

  async function submit(row: EscalationRow, verdict: Verdict) {
    setDeciding(true)
    try {
      const receipt = await decideCard(row.card, verdict)
      setNotice(describeReceipt(row.card, verdict, receipt))
      closeModal()
    } catch (e) {
      setNotice(describeError(e, cardFromConflict(e) !== undefined))
    } finally {
      setDeciding(false)
      // A 412/409 or a success both mean the queue moved: refresh so no stale control is offered.
      void queryClient.invalidateQueries({ queryKey: [FEED_KEY] })
    }
  }

  const columnDefinitions = [
    {
      id: 'id', header: 'Escalation', sortingField: 'id',
      cell: (row: EscalationRow) => (
        <button className="ev2-esc__idlink" onClick={() => setOpenKey(row.key)}>{row.id}</button>
      ),
    },
    { id: 'project', header: 'Project', cell: (row: EscalationRow) => <Badge color="teal">{row.projectId}</Badge> },
    { id: 'kind', header: 'Kind', cell: (row: EscalationRow) => <Badge color="amber">{row.kind.replace('_', ' ')}</Badge> },
    { id: 'status', header: 'Status', cell: (row: EscalationRow) => <StatusChip status={row.status} /> },
    {
      id: 'target', header: 'Target record',
      cell: (row: EscalationRow) => (
        <span className="ev2-esc__mono">
          <RecordLink id={row.targetRecordId} />
          {row.driftDetected && <span className="ev2-esc__drift" title="Target record changed since this was filed">drift</span>}
        </span>
      ),
    },
    { id: 'mutation', header: 'Requested mutation', cell: (row: EscalationRow) => <span className="ev2-esc__mono">{row.title}</span> },
    { id: 'session', header: 'Requested by', cell: (row: EscalationRow) => <span className="ev2-esc__mono">{row.requestedBy}</span> },
    { id: 'expires', header: 'Expires', cell: (row: EscalationRow) => <span className="ev2-esc__expiry">{row.expiresLabel}</span> },
    { id: 'age', header: 'Age', sortingField: 'createdAt', cell: (row: EscalationRow) => row.ageLabel },
  ]

  const table = (items: EscalationRow[], emptyText: string) => (
    <Table
      columnDefinitions={columnDefinitions}
      items={feedQuery.isPending ? [] : items}
      trackBy="key"
      empty={feedQuery.isPending ? 'Loading escalations…' : emptyText}
    />
  )

  const tabs = (
    [
      { id: 'pending', label: 'Pending', count: counts.pending },
      { id: 'approved', label: 'Approved', count: counts.approved },
      { id: 'denied', label: 'Denied', count: counts.denied },
      { id: 'all', label: 'All', count: counts.all },
    ] as const
  ).map((tab) => ({
    ...tab,
    content: table(visibleRows, bucket === 'pending' ? 'Nothing awaiting your decision.' : 'No escalations in this bucket.'),
  }))

  const verdicts = openRow ? allowedVerdicts(openRow.card) : []
  const canAct = Boolean(openRow?.decidable && canDecide)
  const needsCandidate = Boolean(openRow?.card.candidates) && candidateId === undefined

  const focusVerdicts = focusRow ? allowedVerdicts(focusRow.card) : []
  const focusCanAct = Boolean(focusRow?.decidable && canDecide)

  return (
    <>
      {!compact && <EscalationPushNudge api={notifyApi} className="ev2-esc__notice" />}
      {focusId && !feedQuery.isPending && !focusRow && (
        <div className="ev2-esc__notice">
          <Alert type="warning" header={`${focusId} was not found`}>It is not in the pending queue or the recent decisions; it may have expired or belong to a project you cannot see.</Alert>
        </div>
      )}
      {focusRow && (
        <div className="ev2-esc__focus" data-testid="escalation-focus">
          <div className="ev2-esc__focus-head">
            <span className="ev2-esc__mono">{focusRow.id}</span> <Badge color="teal">{focusRow.projectId}</Badge> <Badge color="amber">{focusRow.kind.replace('_', ' ')}</Badge> <span className="ev2-esc__mono">risk {focusRow.risk}</span> <StatusChip status={focusRow.status} />
          </div>
          <div className="ev2-esc__prose">{focusRow.title}</div>
          {focusCanAct ? (
            <>
              {focusRow.card.family === 'decision' && (
                <textarea
                  className="ev2-esc__textarea" rows={1} value={note} disabled={deciding}
                  placeholder="Guidance note (required to deny)" aria-label="Guidance note"
                  onChange={(event) => setNote(event.target.value)}
                />
              )}
              <div className="ev2-esc__actions">
                {focusVerdicts.includes('deny') && (
                  <Button variant="normal" disabled={deciding || note.trim() === ''} onClick={() => void submit(focusRow, deny(note))}>Deny</Button>
                )}
                {focusVerdicts.includes('approve') && (
                  <Button variant="primary" disabled={deciding || Boolean(focusRow.card.candidates) || focusRow.driftDetected} onClick={() => void submit(focusRow, approve(undefined))}>Approve</Button>
                )}
                {!focusVerdicts.includes('approve') && focusVerdicts.includes('ack') && (
                  <Button variant="primary" disabled={deciding} onClick={() => void submit(focusRow, { type: 'ack' })}>Acknowledge</Button>
                )}
                <Button variant="link" onClick={() => setOpenKey(focusRow.key)}>Details</Button>
              </div>
            </>
          ) : (
            <div className="ev2-esc__actions ev2-esc__actions--closed">This escalation is {focusRow.status}: decisions are only available while it is pending. <Button variant="link" onClick={() => setOpenKey(focusRow.key)}>Details</Button></div>
          )}
        </div>
      )}
      {notice && (
        <div className="ev2-esc__notice">
          <Alert type={notice.type} header={notice.header} dismissible onDismiss={() => setNotice(null)}>
            <div>{notice.detail}</div>
            {notice.receipt && <pre className="ev2-esc__payload ev2-esc__receipt" data-testid="decide-receipt">{notice.receipt}</pre>}
          </Alert>
        </div>
      )}

      {feedQuery.isError && (
        <div className="ev2-esc__notice">
          <Alert type="error" header="Could not load the escalation queue">
            {feedQuery.error instanceof Error ? feedQuery.error.message : 'Unknown error'}
          </Alert>
        </div>
      )}

      {feedQuery.data?.terminalError && (
        <div className="ev2-esc__notice">
          <Alert type="warning" header="Recent decisions did not load">
            {feedQuery.data.terminalError}. The pending queue below is still current.
          </Alert>
        </div>
      )}

      {compact ? (
        table(visibleRows, 'Nothing awaiting your decision.')
      ) : (
        <Tabs
          tabs={tabs}
          activeTabId={bucket}
          onChange={(event: { detail: { activeTabId: string } }) => setBucket(event.detail.activeTabId as EscalationBucket)}
        />
      )}

      <Modal
        visible={openRow !== null}
        header="Escalation"
        recordId={openRow?.id}
        size="large"
        onDismiss={closeModal}
        footer={
          openRow && canAct ? (
            <div className="ev2-esc__actions">
              {verdicts.includes('deny') && (
                <Button variant="normal" disabled={deciding || note.trim() === ''} onClick={() => void submit(openRow, deny(note))}>
                  {note.trim() ? 'Deny with guidance' : 'Deny'}
                </Button>
              )}
              {verdicts.includes('approve') && (
                <Button variant="primary" disabled={deciding || needsCandidate || openRow.driftDetected} onClick={() => void submit(openRow, approve(candidateId))}>
                  Approve &amp; apply
                </Button>
              )}
              {!verdicts.includes('approve') && verdicts.includes('ack') && (
                <Button variant="primary" disabled={deciding} onClick={() => void submit(openRow, { type: 'ack' })}>Acknowledge</Button>
              )}
            </div>
          ) : (
            <div className="ev2-esc__actions ev2-esc__actions--closed">
              This escalation is {openRow?.status ?? 'terminal'}: decisions are only available while it is pending.
            </div>
          )
        }
      >
        {openRow && <EscalationDetail row={openRow} candidateId={candidateId} onCandidate={setCandidateId} disabled={deciding} />}
        {openRow && canAct && openRow.card.family === 'decision' && (
          <div className="ev2-esc__deny">
            <FormField label="Guidance note" description="Required to deny. It is recorded on the receipt and returned to the requesting session so it can correct course.">
              <textarea
                className="ev2-esc__textarea" rows={3} value={note} disabled={deciding}
                placeholder="Why this is denied, and what to do instead…" aria-label="Guidance note"
                onChange={(event) => setNote(event.target.value)}
              />
            </FormField>
          </div>
        )}
      </Modal>
    </>
  )
}

function EscalationDetail({ row, candidateId, onCandidate, disabled }: {
  row: EscalationRow
  candidateId: string | undefined
  onCandidate: (id: string) => void
  disabled: boolean
}) {
  const card = row.card
  const calls = card.proposedCalls ?? []
  const prompt = card.why?.summary ?? card.justification
  return (
    <div className="ev2-esc__detail">
      <KeyValuePairs
        columns={3}
        items={[
          { label: 'Status', value: <StatusChip status={row.status} /> },
          { label: 'Kind', value: row.kind, mono: true },
          { label: 'Risk', value: row.risk, mono: true },
          { label: 'Project', value: row.projectId, mono: true },
          { label: 'Target record', value: <RecordLink id={row.targetRecordId} />, mono: true },
          { label: 'Requested by', value: row.requestedBy, mono: true },
          { label: 'Expires', value: card.expiresAt ? `${card.expiresAt} (${card.onExpire})` : '—', mono: true },
          { label: 'Created', value: row.createdAt ?? '—', mono: true },
          { label: 'Decided by', value: card.decision?.decider ?? '—', mono: true },
        ]}
      />
      {prompt && (
        <Container header={<Header variant="h3">Justification</Header>}>
          <p className="ev2-esc__prose">{prompt}</p>
        </Container>
      )}
      {card.decision?.note && (
        <Container header={<Header variant="h3">Guidance returned</Header>}>
          <p className="ev2-esc__prose">{card.decision.note}</p>
        </Container>
      )}
      {row.driftDetected && (
        <Alert type="warning" header="Target record changed after this was filed">
          The card was rendered against an older version of the record; approval is disabled until the queue refreshes.
        </Alert>
      )}
      {calls.map((c) => (
        <Container key={c.callHash} header={<Header variant="h3">Proposed call</Header>}>
          <ProposedCallPreview call={c} diff={card.diff} />
        </Container>
      ))}
      {calls.length === 0 && card.diff && (
        <Container header={<Header variant="h3">Computed diff</Header>}>
          <DiffView diff={card.diff} />
        </Container>
      )}
      {card.candidates && (
        <Container header={<Header variant="h3">Candidates (choose one to approve)</Header>}>
          <fieldset disabled={disabled || !row.decidable}>
            {card.candidates.map((c) => (
              <label key={c.id} className="ev2-esc__candidate">
                <input type="radio" name={`candidate-${row.key}`} value={c.id} checked={candidateId === c.id} onChange={() => onCandidate(c.id)} />{' '}
                {c.label}{c.rule ? ` (${c.rule})` : ''}
                {c.call ? <ProposedCallPreview call={c.call} diff={card.diff} /> : null}
              </label>
            ))}
          </fieldset>
        </Container>
      )}
      {card.evidence.length > 0 && (
        <Container header={<Header variant="h3">Evidence</Header>}>
          <ul>
            {card.evidence.map((e, i) => (
              <li key={`${e.ref}-${i}`}><span>{e.label}</span> <code>{e.ref}</code>{e.excerpt ? <div className="ev2-esc__prose">{e.excerpt}</div> : null}</li>
            ))}
          </ul>
        </Container>
      )}
    </div>
  )
}
