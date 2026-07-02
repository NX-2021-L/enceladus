import type { Document } from '../types/feeds'
import { fetchWithAuth } from './client'

// ENC-TSK-J53 / ENC-FTR-096 Ph3: io-gated lesson-candidate curation queue.
// List via document_api filters (J46); approve/reject via coordination_api (Cognito only).

const DOCUMENTS_BASE = '/api/v1/documents'
const COORDINATION_BASE = '/api/v1/coordination'

export interface LessonCandidate extends Document {
  handoff_status?: string
  description?: string
}

export interface LessonCandidateApproveBody {
  title: string
  observation: string
  insight: string
  provenance?: string
}

export interface LessonCandidateApproveResponse {
  success: boolean
  document_id: string
  lesson_id: string
  handoff_status: string
}

export interface LessonCandidateRejectResponse {
  success: boolean
  document_id: string
  handoff_status: string
}

export const lessonCandidateKeys = {
  pending: (projectId: string) => ['lesson-candidates', 'pending', projectId] as const,
}

export async function fetchPendingLessonCandidates(
  projectId = 'enceladus',
): Promise<LessonCandidate[]> {
  const qs = new URLSearchParams({
    project: projectId,
    document_subtype: 'lesson-candidate',
    handoff_status: 'pending',
    sort: 'created_at',
  })
  const res = await fetchWithAuth(`${DOCUMENTS_BASE}?${qs.toString()}`)
  if (!res.ok) throw new Error(`Failed to fetch lesson candidates: ${res.status}`)
  const data = await res.json()
  return data.documents ?? []
}

export async function approveLessonCandidate(
  documentId: string,
  body: LessonCandidateApproveBody,
): Promise<LessonCandidateApproveResponse> {
  const res = await fetchWithAuth(
    `${COORDINATION_BASE}/lesson-candidates/${encodeURIComponent(documentId)}/approve`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  )
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.error || err.message || `Approve failed: ${res.status}`)
  }
  return res.json()
}

export async function rejectLessonCandidate(
  documentId: string,
  rejectionReason: string,
): Promise<LessonCandidateRejectResponse> {
  const res = await fetchWithAuth(
    `${COORDINATION_BASE}/lesson-candidates/${encodeURIComponent(documentId)}/reject`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rejection_reason: rejectionReason }),
    },
  )
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.error || err.message || `Reject failed: ${res.status}`)
  }
  return res.json()
}
