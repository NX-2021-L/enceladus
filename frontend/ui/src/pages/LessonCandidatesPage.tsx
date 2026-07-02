import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  approveLessonCandidate,
  fetchPendingLessonCandidates,
  lessonCandidateKeys,
  rejectLessonCandidate,
  type LessonCandidate,
} from '../api/lessonCandidates'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { EmptyState } from '../components/shared/EmptyState'

// ENC-TSK-J53 / ENC-FTR-096 Ph3: Lesson-candidate curation queue (FTR-038 control-cluster).

const PROJECT_ID = 'enceladus'

function defaultObservation(candidate: LessonCandidate): string {
  return (
    candidate.description?.trim() ||
    `Lesson candidate ${candidate.document_id} drafted by memory consolidation (pending io review).`
  )
}

function defaultInsight(candidate: LessonCandidate): string {
  const members = candidate.cluster_member_ids
  if (members?.length) {
    return `Recurring co-citation cluster across handoffs suggests a transferable pattern involving ${members.join(', ')}.`
  }
  return 'Promote this auto-drafted candidate into governed semantic memory after io review.'
}

function CandidateCard({
  candidate,
  onApprove,
  onReject,
  busyId,
}: {
  candidate: LessonCandidate
  onApprove: (id: string, title: string, observation: string, insight: string) => void
  onReject: (id: string, reason: string) => void
  busyId: string | null
}) {
  const [title, setTitle] = useState(candidate.title ?? '')
  const [observation, setObservation] = useState(() => defaultObservation(candidate))
  const [insight, setInsight] = useState(() => defaultInsight(candidate))
  const [showReject, setShowReject] = useState(false)
  const [rejectReason, setRejectReason] = useState('')
  const busy = busyId === candidate.document_id

  return (
    <div
      className="bg-slate-800 border border-slate-700 rounded-lg p-4 space-y-3"
      data-testid={`candidate-card-${candidate.document_id}`}
    >
      <div className="flex items-center justify-between gap-2">
        <Link
          to={`/documents/${candidate.document_id}`}
          className="font-mono text-sm text-sky-300 hover:text-sky-200"
        >
          {candidate.document_id}
        </Link>
        <span className="text-xs text-amber-300 bg-amber-500/10 px-2 py-0.5 rounded">
          pending
        </span>
      </div>

      <div className="space-y-2 text-sm">
        <label className="block text-xs text-slate-400">Title</label>
        <input
          className="w-full bg-slate-900 border border-slate-600 rounded px-2 py-1 text-slate-100"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          disabled={busy}
        />
        <label className="block text-xs text-slate-400">Observation</label>
        <textarea
          className="w-full bg-slate-900 border border-slate-600 rounded px-2 py-1 text-slate-100 min-h-[72px]"
          value={observation}
          onChange={(e) => setObservation(e.target.value)}
          disabled={busy}
        />
        <label className="block text-xs text-slate-400">Insight</label>
        <textarea
          className="w-full bg-slate-900 border border-slate-600 rounded px-2 py-1 text-slate-100 min-h-[72px]"
          value={insight}
          onChange={(e) => setInsight(e.target.value)}
          disabled={busy}
        />
      </div>

      {showReject ? (
        <div className="space-y-2 border-t border-slate-700 pt-3">
          <label htmlFor={`reject-${candidate.document_id}`} className="block text-xs text-slate-400">
            Rejection reason (min 10 chars)
          </label>
          <textarea
            id={`reject-${candidate.document_id}`}
            aria-label="Rejection reason"
            className="w-full bg-slate-900 border border-slate-600 rounded px-2 py-1 text-slate-100 min-h-[60px]"
            value={rejectReason}
            onChange={(e) => setRejectReason(e.target.value)}
            disabled={busy}
          />
          <div className="flex gap-2">
            <button
              type="button"
              disabled={busy || rejectReason.trim().length < 10}
              onClick={() => onReject(candidate.document_id, rejectReason.trim())}
              className="px-3 py-1.5 rounded text-sm bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white"
            >
              Confirm reject
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => setShowReject(false)}
              className="px-3 py-1.5 rounded text-sm bg-slate-700 hover:bg-slate-600 text-slate-200"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <div className="flex flex-wrap gap-2 pt-1" data-testid="control-cluster">
          <button
            type="button"
            disabled={busy || !title.trim() || !observation.trim() || !insight.trim()}
            onClick={() => onApprove(candidate.document_id, title.trim(), observation.trim(), insight.trim())}
            className="px-3 py-1.5 rounded text-sm bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white"
          >
            Approve → Lesson
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => setShowReject(true)}
            className="px-3 py-1.5 rounded text-sm bg-slate-700 hover:bg-slate-600 text-slate-200"
          >
            Reject
          </button>
        </div>
      )}
    </div>
  )
}

export function LessonCandidatesPage() {
  const queryClient = useQueryClient()
  const [busyId, setBusyId] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)

  const { data: candidates = [], isLoading, isError } = useQuery({
    queryKey: lessonCandidateKeys.pending(PROJECT_ID),
    queryFn: () => fetchPendingLessonCandidates(PROJECT_ID),
  })

  const approveMutation = useMutation({
    mutationFn: ({
      documentId,
      title,
      observation,
      insight,
    }: {
      documentId: string
      title: string
      observation: string
      insight: string
    }) =>
      approveLessonCandidate(documentId, {
        title,
        observation,
        insight,
        provenance: 'human',
      }),
    onMutate: async ({ documentId }) => {
      setBusyId(documentId)
      setActionError(null)
      await queryClient.cancelQueries({ queryKey: lessonCandidateKeys.pending(PROJECT_ID) })
      const previous = queryClient.getQueryData<LessonCandidate[]>(
        lessonCandidateKeys.pending(PROJECT_ID),
      )
      queryClient.setQueryData<LessonCandidate[]>(
        lessonCandidateKeys.pending(PROJECT_ID),
        (old = []) => old.filter((c) => c.document_id !== documentId),
      )
      return { previous }
    },
    onError: (err, _vars, context) => {
      if (context?.previous) {
        queryClient.setQueryData(lessonCandidateKeys.pending(PROJECT_ID), context.previous)
      }
      setActionError(err instanceof Error ? err.message : 'Approve failed')
    },
    onSettled: () => {
      setBusyId(null)
      void queryClient.invalidateQueries({ queryKey: lessonCandidateKeys.pending(PROJECT_ID) })
    },
  })

  const rejectMutation = useMutation({
    mutationFn: ({ documentId, reason }: { documentId: string; reason: string }) =>
      rejectLessonCandidate(documentId, reason),
    onMutate: async ({ documentId }) => {
      setBusyId(documentId)
      setActionError(null)
      await queryClient.cancelQueries({ queryKey: lessonCandidateKeys.pending(PROJECT_ID) })
      const previous = queryClient.getQueryData<LessonCandidate[]>(
        lessonCandidateKeys.pending(PROJECT_ID),
      )
      queryClient.setQueryData<LessonCandidate[]>(
        lessonCandidateKeys.pending(PROJECT_ID),
        (old = []) => old.filter((c) => c.document_id !== documentId),
      )
      return { previous }
    },
    onError: (err, _vars, context) => {
      if (context?.previous) {
        queryClient.setQueryData(lessonCandidateKeys.pending(PROJECT_ID), context.previous)
      }
      setActionError(err instanceof Error ? err.message : 'Reject failed')
    },
    onSettled: () => {
      setBusyId(null)
      void queryClient.invalidateQueries({ queryKey: lessonCandidateKeys.pending(PROJECT_ID) })
    },
  })

  if (isLoading) return <LoadingState />
  if (isError) return <ErrorState message="Failed to load lesson candidates." />

  return (
    <div className="p-4 max-w-3xl mx-auto space-y-4">
      <div>
        <h1 className="text-lg font-semibold text-slate-100">Lesson Candidates</h1>
        <p className="text-sm text-slate-400 mt-1">
          Approve or reject memory-consolidation drafts (ENC-FTR-096). Cognito session required.
        </p>
      </div>

      {actionError && (
        <div className="text-sm text-rose-300 bg-rose-900/20 border border-rose-500/30 rounded px-3 py-2">
          {actionError}
        </div>
      )}

      {candidates.length === 0 ? (
        <EmptyState message="No pending lesson candidates." />
      ) : (
        <div className="space-y-4">
          {candidates.map((candidate) => (
            <CandidateCard
              key={candidate.document_id}
              candidate={candidate}
              busyId={busyId}
              onApprove={(documentId, title, observation, insight) =>
                approveMutation.mutate({ documentId, title, observation, insight })
              }
              onReject={(documentId, reason) =>
                rejectMutation.mutate({ documentId, reason })
              }
            />
          ))}
        </div>
      )}
    </div>
  )
}
