/**
 * dedup.ts — PWA client for the dedup tier-review surface (ENC-TSK-I08, Dedup P4).
 *
 * Routes: POST /api/v1/tracker/{projectId}/dedup-review with { op: 'propose' | 'approve' }.
 *   - op=propose : mutation-free tier derivation over I05 clusters + I06 verdicts.
 *   - op=approve : io-Cognito-gated supersession of approved duplicates into the
 *                  canonical (the internal-key/agent path is rejected server-side —
 *                  the agent can never self-authorize a merge). credentials:'include'
 *                  sends the enceladus_id_token session cookie that proves io identity.
 *
 * It PROPOSES; io APPROVES. T-MID is a whole-cluster plan; T-LOW is whole-cluster
 * OR a per-record subset. T-HIGH (certificate-certified) is deferred to ENC-TSK-I09's
 * flag-gated arc-walker and is never actionable here. See DOC-DF651F07D5C2 §5/§7/§8.
 */

const BASE = import.meta.env.VITE_MUTATION_BASE_URL ?? '/api/v1/tracker'

export type DedupTier = 'T-HIGH' | 'T-MID' | 'T-LOW'
export type DedupGranularity = 'plan' | 'per-record' | 'deferred' | 'none'

/** One I05 cluster object (clusters.jsonl), passed through to the propose endpoint. */
export interface I05Cluster {
  cluster_id: string
  record_type: string
  project_id: string
  canonical: string
  members: string[]
  duplicates?: string[]
  [k: string]: unknown
}

/** One I06 verdict object (verdicts.jsonl), passed through to the propose endpoint. */
export interface I06Verdict {
  a: string
  b: string
  record_type: string
  calibrated_prob: number | null
  tier?: string
  certificate?: { passed?: boolean; [k: string]: unknown }
  signals?: { cosine?: number | null; [k: string]: unknown }
  [k: string]: unknown
}

export interface DedupDuplicate {
  record_id: string
  tier: DedupTier
  calibrated_prob: number | null
  cosine: number | null
  certificate_passed: boolean
}

export interface DedupProposal {
  cluster_id: string
  record_type: string
  project_id: string
  canonical?: string
  cluster_tier: DedupTier | null
  actionable: boolean
  granularity: DedupGranularity
  defer_to: string | null
  duplicates: DedupDuplicate[]
  dropped_distinct: string[]
  excluded: boolean
  reason?: string
}

export interface DedupProposeResponse {
  success: boolean
  project_id: string
  tau_mid: number
  review_floor: number
  proposal_count: number
  counts: Record<string, number>
  proposals: DedupProposal[]
  note: string
}

export interface DedupApproveResult {
  superseded_id: string
  status_code: number
  ok: boolean
  idempotent: boolean
  supersession?: Record<string, unknown> | null
  detail?: string | null
}

export interface DedupApproveResponse {
  success: boolean
  project_id: string
  canonical_id: string
  cluster_id: string | null
  tier: DedupTier
  approved_by: string
  requested_count: number
  superseded_count: number
  rejected_count: number
  results: DedupApproveResult[]
  note: string
}

export class DedupApiError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'DedupApiError'
    this.status = status
  }
}

async function post<T>(projectId: string, body: Record<string, unknown>): Promise<T> {
  const res = await fetch(`${BASE}/${projectId}/dedup-review`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = (await res.json().catch(() => null)) as
    | (T & { error?: string })
    | { error?: string }
    | null
  if (!res.ok) {
    const message =
      (data && typeof data === 'object' && 'error' in data && typeof data.error === 'string'
        ? data.error
        : `HTTP ${res.status}`) || `HTTP ${res.status}`
    throw new DedupApiError(res.status, message)
  }
  return data as T
}

/**
 * op=propose — mutation-free. Returns tiered proposals for io review. Any
 * authenticated caller may propose; nothing is written.
 */
export async function proposeDedup(
  projectId: string,
  input: { clusters: I05Cluster[]; verdicts: I06Verdict[]; tau_mid?: number; review_floor?: number },
): Promise<DedupProposeResponse> {
  return post<DedupProposeResponse>(projectId, { op: 'propose', ...input })
}

/**
 * op=approve — io Cognito session only. Supersedes the approved duplicates into
 * the canonical via the I07 soft-supersession primitive (reversible). For a
 * T-MID plan pass the whole cluster's duplicates; for T-LOW pass either the whole
 * set or a selected subset (per-record). T-HIGH is not accepted here.
 */
export async function approveDedup(
  projectId: string,
  input: {
    canonical_id: string
    superseded_ids: string[]
    tier: Exclude<DedupTier, 'T-HIGH'>
    cluster_id?: string
    reason?: string
  },
): Promise<DedupApproveResponse> {
  return post<DedupApproveResponse>(projectId, { op: 'approve', ...input })
}
