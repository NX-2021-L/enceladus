/**
 * Escalations — io's approval cockpit (ENC-TSK-O40 / ENC-FTR-121 Ph3).
 *
 * List + detail + the two non-delegable decisions. This is the surface that
 * closes the io-approval loop inside PWA 2.0: before it, ENC-FTR-121 shipped a
 * complete backend and a v3-only UI, so the v4 cockpit could see escalations
 * (CoordinationRoute's read-only tab) but never decide one.
 *
 * WHY THE DECISION CONTROLS ARE SHAPED THE WAY THEY ARE. Approve/deny have no
 * MCP action and no agent path by deliberate design (DOC-5B888FCA43B8 §6,
 * ENC-ISS-501). The backend fail-closes through three gates — Cognito session,
 * interactive-human ID token, and a Console-managed decider allowlist. This
 * component therefore:
 *   - renders decision controls ONLY for a decidable ('requested') escalation
 *     reached through the app's own human Cognito session (AuthGate has already
 *     proven one exists before any route mounts);
 *   - never routes a decision through an agent/internal-key path — there is no
 *     such code path in src/api/escalations.ts to route through;
 *   - surfaces a 403 from any gate verbatim, with the reason, instead of
 *     retrying or degrading. A refused decision is a correct outcome to show,
 *     not an error to swallow.
 *
 * State ownership (B67 AC-13/AC-14): all record data lives in TanStack Query.
 * The only useState here is view state — which bucket is selected, which row is
 * open, and the draft guidance note. No escalation is ever copied into
 * component state, so the queue cannot go stale behind an open modal.
 */
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Box,
  Button,
  Container,
  FormField,
  Header,
  KeyValuePairs,
  Modal,
  Table,
  Tabs,
} from '../design-system'
import { StatusChip } from '../components/StatusChip'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import {
  approveEscalation,
  denyEscalation,
  escalationKeys,
  fetchEscalationsFeed,
  type EscalationDecisionResult,
  type EscalationItem,
} from '../api/escalations'
import {
  countByBucket,
  describeDecisionError,
  describeDecisionResult,
  filterRows,
  toEscalationRows,
  type EscalationBucket,
  type EscalationRow,
} from './escalationRows'
import './escalations.css'

// ENC-ISS-527 / ENC-TSK-M60: the cockpit is pinned to enceladus — never
// derived from projects[0], which resolves to 'agentharmony' on gamma and
// silently renders an empty queue. Same pin as CoordinationRoute/Governance.
const ESCALATIONS_PROJECT_ID = 'enceladus'

/** Poll cadence. ENC-TSK-J71's escalation.watch is the agent-side cursor feed;
 *  the cockpit uses the documented fallback (poll escalation.list) because a
 *  human queue does not need sub-30s latency and polling cannot wedge. */
const POLL_INTERVAL_MS = 30_000

export function EscalationsRoute() {
  useDocumentTitle('Escalations')
  const queryClient = useQueryClient()

  const [bucket, setBucket] = useState<EscalationBucket>('pending')
  const [openId, setOpenId] = useState<string | null>(null)
  const [guidanceNote, setGuidanceNote] = useState('')
  const [notice, setNotice] = useState<{
    type: 'success' | 'warning' | 'error'
    header: string
    detail: string
    hint?: string
  } | null>(null)

  const feedQuery = useQuery({
    queryKey: escalationKeys.feed(ESCALATIONS_PROJECT_ID),
    queryFn: ({ signal }) => fetchEscalationsFeed(ESCALATIONS_PROJECT_ID, { signal }),
    refetchInterval: POLL_INTERVAL_MS,
  })

  // AC-16: React Compiler owns memoization — no hand-written useMemo.
  const rows = toEscalationRows(feedQuery.data)
  const counts = countByBucket(rows)
  const visibleRows = filterRows(rows, bucket)
  // The open row is READ FROM QUERY DATA every render, never copied into state:
  // a decision elsewhere (or the 30s poll) updates the modal in place, and an
  // escalation that leaves the feed closes it rather than showing a ghost.
  const openRow = openId ? (rows.find((row) => row.id === openId) ?? null) : null

  function closeModal() {
    setOpenId(null)
    setGuidanceNote('')
  }

  function settleDecision(result: EscalationDecisionResult) {
    setNotice(describeDecisionResult(result))
    void queryClient.invalidateQueries({ queryKey: escalationKeys.feed(ESCALATIONS_PROJECT_ID) })
    closeModal()
  }

  function settleError(error: unknown) {
    setNotice(describeDecisionError(error))
    // A 409 means someone/something already decided it — refresh so the queue
    // stops offering a control the server will keep refusing.
    void queryClient.invalidateQueries({ queryKey: escalationKeys.feed(ESCALATIONS_PROJECT_ID) })
  }

  const approveMutation = useMutation({
    mutationFn: (escalationId: string) =>
      approveEscalation(ESCALATIONS_PROJECT_ID, escalationId),
    onSuccess: settleDecision,
    onError: settleError,
  })

  const denyMutation = useMutation({
    mutationFn: (vars: { escalationId: string; note: string }) =>
      denyEscalation(ESCALATIONS_PROJECT_ID, vars.escalationId, vars.note),
    onSuccess: settleDecision,
    onError: settleError,
  })

  const deciding = approveMutation.isPending || denyMutation.isPending

  const columnDefinitions = [
    {
      id: 'id',
      header: 'Escalation',
      sortingField: 'id',
      cell: (row: EscalationRow) => (
        <button className="ev2-esc__idlink" onClick={() => setOpenId(row.id)}>
          {row.id}
        </button>
      ),
    },
    {
      id: 'status',
      header: 'Status',
      cell: (row: EscalationRow) => <StatusChip status={row.status} />,
    },
    {
      id: 'target',
      header: 'Target record',
      cell: (row: EscalationRow) => (
        <span className="ev2-esc__mono">
          {row.targetRecordId}
          {row.driftDetected && (
            <span className="ev2-esc__drift" title="Target record changed since this was filed">
              drift
            </span>
          )}
        </span>
      ),
    },
    {
      id: 'mutation',
      header: 'Requested mutation',
      cell: (row: EscalationRow) => <span className="ev2-esc__mono">{row.mutationSummary}</span>,
    },
    {
      id: 'session',
      header: 'Requested by',
      cell: (row: EscalationRow) => <span className="ev2-esc__mono">{row.requestedBySession}</span>,
    },
    {
      id: 'age',
      header: 'Age',
      sortingField: 'createdAt',
      cell: (row: EscalationRow) => row.ageLabel,
    },
  ]

  const tabs = (
    [
      { id: 'pending', label: 'Pending', count: counts.pending },
      { id: 'approved', label: 'Approved', count: counts.approved },
      { id: 'denied', label: 'Denied', count: counts.denied },
      { id: 'all', label: 'All', count: counts.all },
    ] as const
  ).map((tab) => ({
    id: tab.id,
    label: tab.label,
    count: tab.count,
    content: (
      <Table
        columnDefinitions={columnDefinitions}
        items={feedQuery.isPending ? [] : visibleRows}
        trackBy="id"
        empty={
          feedQuery.isPending
            ? 'Loading escalations…'
            : bucket === 'pending'
              ? 'Nothing awaiting your decision.'
              : 'No escalations in this bucket.'
        }
      />
    ),
  }))

  return (
    <Box>
      <Header
        variant="h1"
        counter={`(${counts.pending} pending)`}
        description="Governed mutations an agent could not perform itself, routed here for your explicit human approval. Approving applies the mutation; denying can return a guidance note to the requesting session."
      >
        Escalations
      </Header>

      {notice && (
        <div className="ev2-esc__notice">
          <Alert type={notice.type} header={notice.header} dismissible onDismiss={() => setNotice(null)}>
            <div>{notice.detail}</div>
            {notice.hint && <div className="ev2-esc__hint">{notice.hint}</div>}
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

      <Tabs
        tabs={tabs}
        activeTabId={bucket}
        onChange={(event: { detail: { activeTabId: string } }) =>
          setBucket(event.detail.activeTabId as EscalationBucket)
        }
      />

      <Modal
        visible={openRow !== null}
        header="Escalation"
        recordId={openRow?.id}
        size="large"
        onDismiss={closeModal}
        footer={
          openRow?.decidable ? (
            <div className="ev2-esc__actions">
              <Button
                variant="normal"
                disabled={deciding}
                loading={denyMutation.isPending}
                onClick={() =>
                  denyMutation.mutate({ escalationId: openRow.id, note: guidanceNote })
                }
              >
                {guidanceNote.trim() ? 'Deny with guidance' : 'Deny'}
              </Button>
              <Button
                variant="primary"
                disabled={deciding}
                loading={approveMutation.isPending}
                onClick={() => approveMutation.mutate(openRow.id)}
              >
                Approve &amp; apply
              </Button>
            </div>
          ) : (
            <div className="ev2-esc__actions ev2-esc__actions--closed">
              This escalation is {openRow?.status ?? 'terminal'} — decisions are only available
              while it is “requested”.
            </div>
          )
        }
      >
        {openRow && <EscalationDetail row={openRow} />}
        {openRow?.decidable && (
          <div className="ev2-esc__deny">
            <FormField
              label="Guidance note"
              description="Optional. A note here denies with guidance — it is returned to the requesting agent session so it can correct course instead of retrying blindly."
            >
              <textarea
                className="ev2-esc__textarea"
                rows={3}
                value={guidanceNote}
                disabled={deciding}
                placeholder="Why this is denied, and what to do instead…"
                aria-label="Guidance note"
                onChange={(event) => setGuidanceNote(event.target.value)}
              />
            </FormField>
          </div>
        )}
      </Modal>
    </Box>
  )
}

function EscalationDetail({ row }: { row: EscalationRow }) {
  const item: EscalationItem = row.item
  const snapshot = item.diff?.target_snapshot
  const drift = item.diff?.drift

  return (
    <div className="ev2-esc__detail">
      <KeyValuePairs
        columns={3}
        items={[
          { label: 'Status', value: <StatusChip status={row.status} /> },
          { label: 'Mutation type', value: item.mutation_type ?? '—', mono: true },
          { label: 'Target record', value: row.targetRecordId, mono: true },
          { label: 'Requested by', value: row.requestedBySession, mono: true },
          { label: 'Agent type', value: item.requested_by?.agent_type_id ?? '—', mono: true },
          { label: 'Age', value: row.ageLabel },
          { label: 'Created', value: row.createdAt, mono: true },
          { label: 'Decided by', value: item.approved_by?.email ?? '—', mono: true },
          { label: 'Applied at', value: item.applied_at ?? '—', mono: true },
        ]}
      />

      {row.justification && (
        <Container header={<Header variant="h3">Justification</Header>}>
          <p className="ev2-esc__prose">{row.justification}</p>
        </Container>
      )}

      {item.guidance_note && (
        <Container header={<Header variant="h3">Guidance returned</Header>}>
          <p className="ev2-esc__prose">{item.guidance_note}</p>
        </Container>
      )}

      {drift?.detected && (
        <Alert type="warning" header="Target record changed after this was filed">
          The escalation expected version {drift.expected_version ?? '—'}; the record is now at
          sync_version {drift.current_sync_version ?? '—'} (updated{' '}
          {drift.current_updated_at ?? '—'}). Approving applies the requested mutation against the
          record as it stands now.
        </Alert>
      )}

      {item.diff?.target_missing && (
        <Alert type="error" header="Target record not found">
          {row.targetRecordId} could not be read on this plane. Approving cannot apply a mutation to
          a record that does not exist here.
        </Alert>
      )}

      {snapshot && (
        <Container header={<Header variant="h3">Target record now</Header>}>
          <KeyValuePairs
            columns={3}
            items={[
              { label: 'Title', value: snapshot.title ?? '—' },
              { label: 'Status', value: snapshot.status ?? '—', mono: true },
              { label: 'Transition type', value: snapshot.transition_type ?? '—', mono: true },
              { label: 'Checkout state', value: snapshot.checkout_state ?? '—', mono: true },
              { label: 'Sync version', value: String(snapshot.sync_version ?? '—'), mono: true },
              { label: 'Updated', value: snapshot.updated_at ?? '—', mono: true },
            ]}
          />
        </Container>
      )}

      <Container header={<Header variant="h3">Requested mutation payload</Header>}>
        <pre className="ev2-esc__payload">{JSON.stringify(item.payload ?? {}, null, 2)}</pre>
      </Container>

      {item.diff && (
        <Container header={<Header variant="h3">Computed diff</Header>}>
          <pre className="ev2-esc__payload">{JSON.stringify(item.diff, null, 2)}</pre>
        </Container>
      )}
    </div>
  )
}
