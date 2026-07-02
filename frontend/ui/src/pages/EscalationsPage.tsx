import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  approveEscalation,
  denyEscalation,
  escalationKeys,
  fetchEscalations,
} from '../api/escalations'
import type { EscalationDiff, EscalationItem } from '../api/escalations'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { EmptyState } from '../components/shared/EmptyState'

// ENC-FTR-121 Ph3 (ENC-TSK-J70): io's Escalations approval queue
// (DOC-5B888FCA43B8 §5.7). Pending cards render a FRESH current-vs-requested
// diff (fetched at render time by the backend, never the cached request) with
// a prominent drift warning when expected_version mismatches; io may still
// approve (informed consent) or deny. Terminal escalations stay browsable in
// a collapsed audit section.

const PROJECT_ID = 'enceladus'

const STATUS_COLORS: Record<string, string> = {
  requested: 'bg-amber-500/20 text-amber-300',
  approved: 'bg-sky-500/20 text-sky-300',
  applying: 'bg-sky-500/20 text-sky-300',
  applied: 'bg-emerald-500/20 text-emerald-300',
  denied: 'bg-rose-500/20 text-rose-300',
  denied_with_guidance: 'bg-rose-500/20 text-rose-300',
  failed: 'bg-rose-600/30 text-rose-200',
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_COLORS[status] ?? 'bg-slate-600/40 text-slate-300'}`}
    >
      {status}
    </span>
  )
}

function DiffBlock({ diff }: { diff: EscalationDiff }) {
  if (diff.target_missing) {
    return <p className="text-sm text-rose-300">Target record no longer exists.</p>
  }
  return (
    <div className="text-sm space-y-1" data-testid="escalation-diff">
      <div className="flex items-center gap-2 font-mono">
        <span className="text-slate-400">{diff.field}:</span>
        <span className="text-rose-300 line-through">{String(diff.current ?? '—')}</span>
        <span className="text-slate-500">→</span>
        <span className="text-emerald-300">{String(diff.requested ?? '—')}</span>
      </div>
      {diff.field_values &&
        Object.entries(diff.field_values).map(([field, delta]) => (
          <div key={field} className="flex items-center gap-2 font-mono text-xs">
            <span className="text-slate-400">{field}:</span>
            <span className="text-rose-300 line-through">
              {JSON.stringify(delta.current ?? null)}
            </span>
            <span className="text-slate-500">→</span>
            <span className="text-emerald-300">{JSON.stringify(delta.requested)}</span>
          </div>
        ))}
      {diff.target_snapshot && (
        <p className="text-xs text-slate-500">
          Live target: status={diff.target_snapshot.status} · arc=
          {diff.target_snapshot.transition_type} · sync_version=
          {String(diff.target_snapshot.sync_version ?? '—')}
        </p>
      )}
    </div>
  )
}

function PendingCard({
  escalation,
  onApprove,
  onDeny,
  busy,
}: {
  escalation: EscalationItem
  onApprove: (id: string) => void
  onDeny: (id: string, guidanceNote?: string) => void
  busy: boolean
}) {
  const [showGuidance, setShowGuidance] = useState(false)
  const [guidanceNote, setGuidanceNote] = useState('')
  const drift = escalation.diff?.drift

  return (
    <div
      className="bg-slate-800 border border-slate-700 rounded-lg p-4 space-y-3"
      data-testid={`escalation-card-${escalation.item_id}`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm text-slate-200">{escalation.item_id}</span>
          <StatusBadge status={escalation.status} />
        </div>
        <span className="text-xs text-slate-500">{escalation.created_at}</span>
      </div>

      <div className="text-sm text-slate-300">
        <span className="font-mono text-sky-300">{escalation.target_record_id}</span>
        {escalation.diff?.target_snapshot?.title && (
          <span className="text-slate-400"> — {escalation.diff.target_snapshot.title}</span>
        )}
      </div>

      <div className="text-xs text-slate-400">
        <span className="font-medium text-slate-300">{escalation.mutation_type}</span>
        {' · requested by '}
        <span className="font-mono">{escalation.requested_by?.session_id ?? 'unknown'}</span>
      </div>

      {drift?.detected && (
        <div
          className="bg-amber-500/10 border border-amber-500/40 rounded px-3 py-2 text-xs text-amber-300"
          data-testid="drift-warning"
        >
          ⚠ Target drifted since request: expected {drift.expected_version}, now
          sync_version={drift.current_sync_version} (updated {drift.current_updated_at}).
          Approving applies the cached mutation to the CURRENT record state.
        </div>
      )}

      {escalation.diff && <DiffBlock diff={escalation.diff} />}

      <p className="text-sm text-slate-300 bg-slate-900/60 rounded px-3 py-2">
        {escalation.justification}
      </p>

      {showGuidance ? (
        <div className="space-y-2">
          <textarea
            value={guidanceNote}
            onChange={(e) => setGuidanceNote(e.target.value)}
            placeholder="Guidance for the requesting agent…"
            aria-label="Guidance note"
            className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-slate-200"
            rows={2}
          />
          <div className="flex gap-2">
            <button
              onClick={() => onDeny(escalation.item_id, guidanceNote.trim() || undefined)}
              disabled={busy}
              className="px-3 py-1.5 rounded bg-rose-600/80 hover:bg-rose-600 text-sm text-white disabled:opacity-50"
            >
              Send denial
            </button>
            <button
              onClick={() => setShowGuidance(false)}
              className="px-3 py-1.5 rounded bg-slate-700 text-sm text-slate-300"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <div className="flex gap-2">
          <button
            onClick={() => onApprove(escalation.item_id)}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-emerald-600/80 hover:bg-emerald-600 text-sm text-white disabled:opacity-50"
          >
            Approve
          </button>
          <button
            onClick={() => onDeny(escalation.item_id)}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-rose-600/80 hover:bg-rose-600 text-sm text-white disabled:opacity-50"
          >
            Deny
          </button>
          <button
            onClick={() => setShowGuidance(true)}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600 text-sm text-slate-200"
          >
            Deny with guidance
          </button>
        </div>
      )}
    </div>
  )
}

export function EscalationsPage() {
  const queryClient = useQueryClient()
  const [actionError, setActionError] = useState('')
  const [lastOutcome, setLastOutcome] = useState('')

  const { data, isPending, isError } = useQuery({
    queryKey: escalationKeys.feed(PROJECT_ID),
    queryFn: () => fetchEscalations(PROJECT_ID),
    refetchInterval: 30_000,
  })

  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: escalationKeys.feed(PROJECT_ID) })

  const approveMutation = useMutation({
    mutationFn: (escalationId: string) => approveEscalation(PROJECT_ID, escalationId),
    onSuccess: (result) => {
      setActionError('')
      setLastOutcome(
        result.applied
          ? `${result.escalation_id} approved and applied.`
          : `${result.escalation_id} approved; apply pending${result.apply_error ? ` (${result.apply_error})` : ''}.`,
      )
      refresh()
    },
    onError: (err: Error) => setActionError(err.message),
  })

  const denyMutation = useMutation({
    mutationFn: ({ escalationId, guidanceNote }: { escalationId: string; guidanceNote?: string }) =>
      denyEscalation(PROJECT_ID, escalationId, guidanceNote),
    onSuccess: (result) => {
      setActionError('')
      setLastOutcome(`${result.escalation_id} ${result.status}.`)
      refresh()
    },
    onError: (err: Error) => setActionError(err.message),
  })

  if (isPending) return <LoadingState />
  if (isError || !data) return <ErrorState />

  const busy = approveMutation.isPending || denyMutation.isPending
  const pending = data.pending ?? []
  const terminal = data.terminal ?? []

  return (
    <div className="p-4 space-y-4">
      <p className="text-xs text-slate-500">
        Human-gated mutation overrides (ENC-FTR-121). Approval is non-delegable: decisions
        here are the sole origin of override authorization.
      </p>

      {actionError && (
        <div className="bg-rose-500/10 border border-rose-500/40 rounded px-3 py-2 text-sm text-rose-300">
          {actionError}
        </div>
      )}
      {lastOutcome && !actionError && (
        <div className="bg-emerald-500/10 border border-emerald-500/40 rounded px-3 py-2 text-sm text-emerald-300">
          {lastOutcome}
        </div>
      )}

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-slate-300">
          Pending ({pending.length})
        </h2>
        {pending.length === 0 ? (
          <EmptyState message="No pending escalations." />
        ) : (
          pending.map((escalation) => (
            <PendingCard
              key={escalation.item_id}
              escalation={escalation}
              busy={busy}
              onApprove={(id) => approveMutation.mutate(id)}
              onDeny={(id, guidanceNote) => denyMutation.mutate({ escalationId: id, guidanceNote })}
            />
          ))
        )}
      </section>

      <details className="group" data-testid="terminal-section">
        <summary className="text-sm font-semibold text-slate-400 cursor-pointer select-none">
          History ({terminal.length})
        </summary>
        <div className="mt-3 space-y-2">
          {terminal.map((escalation) => (
            <div
              key={escalation.item_id}
              className="bg-slate-800/60 border border-slate-700/60 rounded-lg px-4 py-3 text-sm"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-slate-300">{escalation.item_id}</span>
                  <StatusBadge status={escalation.status} />
                </div>
                <span className="text-xs text-slate-500">{escalation.updated_at}</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                {escalation.mutation_type} on{' '}
                <span className="font-mono">{escalation.target_record_id}</span>
                {escalation.approved_by?.email && ` · approved by ${escalation.approved_by.email}`}
                {escalation.guidance_note && ` · guidance: ${escalation.guidance_note}`}
              </p>
            </div>
          ))}
        </div>
      </details>
    </div>
  )
}
