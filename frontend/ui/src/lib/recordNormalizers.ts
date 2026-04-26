/**
 * recordNormalizers — Per-record-type projection from raw tracker API payloads
 * into the feed-shape-compatible objects that existing detail page renderers
 * expect (ENC-FTR-073 Phase 2b / ENC-TSK-D95).
 *
 * Background:
 *   The live feed transforms (`backend/lambda/feed_query/lambda_function.py
 *   ::_transform_*_from_ddb`) produce typed, field-renamed, back-filled views.
 *   The tracker API (`backend/lambda/tracker_mutation/lambda_function.py
 *   ::_handle_get_record`) returns the raw DDB item with no projection applied.
 *   A record fetched via direct-API fallback must be projected into the feed
 *   shape so the existing render paths do not need to branch on data origin.
 *
 * Contract (per DOC-BB658D8644DF §4):
 *   - Baseline shim applied to every type:
 *       - `item_id` → `{type}_id`
 *       - discard `record_id` DDB sort-key echo
 *       - missing arrays default to `[]`
 *       - missing scalars default to `null` (matching types/feeds.ts)
 *       - status/priority enum defaults per type
 *       - computed ENC-TSK-A57 fields (`typed_relationships`, `context_node`)
 *         default safely: `[]` and `undefined` respectively.
 *   - The lesson normalizer is the only type with a non-trivial field-level
 *     remap due to `extensions` schema drift between feed (LessonExtension) and
 *     API (raw DDB shape).
 *
 * Safety:
 *   - Every normalizer is total on Record<string, unknown>|undefined|null.
 *     It never throws on malformed input; instead it returns a best-effort
 *     object and emits an optional `warning` signal for the UX layer to
 *     surface if desired.
 */

import type {
  Document,
  Feature,
  HistoryEntry,
  Issue,
  Lesson,
  LessonExtension,
  PillarScores,
  Plan,
  Task,
  TypedRelationshipEdge,
} from '../types/feeds'

// ---------------------------------------------------------------------------
// Result envelope
// ---------------------------------------------------------------------------

export interface NormalizationResult<T> {
  /** Feed-shape-compatible record (best effort). Always defined — the
   *  normalizer never returns undefined here; if the input is unusable the
   *  normalizer emits a warning and returns a minimally-valid record. */
  data: T
  /** Non-fatal warning describing what the normalizer had to patch up. */
  warning?: string
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

type RawRecord = Record<string, unknown>

function asRecord(value: unknown): RawRecord {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as RawRecord
  }
  return {}
}

function asString(value: unknown, fallback = ''): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return fallback
}

function asOptionalString(value: unknown, fallback: string | null = null): string | null {
  if (typeof value === 'string' && value.length > 0) return value
  return fallback
}

function asNumber(value: unknown, fallback = 0): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string' && value.length > 0) {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return fallback
}

function asBool(value: unknown, fallback = false): boolean {
  if (typeof value === 'boolean') return value
  return fallback
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  const out: string[] = []
  for (const entry of value) {
    if (typeof entry === 'string') out.push(entry)
  }
  return out
}

function asArray<T = unknown>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : []
}

function emptyToNull(value: unknown): string | null {
  if (typeof value === 'string') return value.length > 0 ? value : null
  return null
}

function normalizeHistory(value: unknown): HistoryEntry[] {
  const arr = asArray<RawRecord>(value)
  return arr.map((raw) => ({
    timestamp: asString(raw.timestamp),
    status: asString(raw.status),
    description: asString(raw.description),
  }))
}

function normalizeTypedRelationships(value: unknown): TypedRelationshipEdge[] {
  const arr = asArray<RawRecord>(value)
  return arr.map((raw) => ({
    relationship_type: asString(raw.relationship_type),
    target_id: asString(raw.target_id),
    weight: asNumber(raw.weight, 1),
    confidence: asNumber(raw.confidence, 1),
    reason: asOptionalString(raw.reason, null),
    created_at: asOptionalString(raw.created_at, null),
  }))
}

// ---------------------------------------------------------------------------
// Task (ENC-FTR-073 §4.1)
// ---------------------------------------------------------------------------

export function normalizeTask(input: unknown): NormalizationResult<Task> {
  const raw = asRecord(input)
  const warnings: string[] = []
  const taskId = asString(raw.task_id ?? raw.item_id)
  if (!taskId) warnings.push('task record missing identifier (item_id/task_id)')

  const data: Task = {
    task_id: taskId,
    project_id: asString(raw.project_id),
    title: asString(raw.title),
    description: asString(raw.description),
    status: (asOptionalString(raw.status) ?? 'open') as Task['status'],
    priority: (asOptionalString(raw.priority) ?? 'P2') as Task['priority'],
    assigned_to: asOptionalString(raw.assigned_to, null),
    related_feature_ids: asStringArray(raw.related_feature_ids),
    related_task_ids: asStringArray(raw.related_task_ids),
    related_issue_ids: asStringArray(raw.related_issue_ids),
    checklist_total: asNumber(raw.checklist_total, 0),
    checklist_done: asNumber(raw.checklist_done, 0),
    checklist: asStringArray(raw.checklist),
    history: normalizeHistory(raw.history),
    parent: asOptionalString(raw.parent, null),
    updated_at: asOptionalString(raw.updated_at, null),
    last_update_note: asOptionalString(raw.last_update_note, null),
    created_at: asOptionalString(raw.created_at, null),
    active_agent_session: raw.active_agent_session != null ? asBool(raw.active_agent_session) : undefined,
    active_agent_session_id: typeof raw.active_agent_session_id === 'string' ? raw.active_agent_session_id : undefined,
    active_agent_session_parent:
      raw.active_agent_session_parent != null ? asBool(raw.active_agent_session_parent) : undefined,
    checkout_state: (emptyToNull(raw.checkout_state) as Task['checkout_state']) ?? null,
    checked_out_by: emptyToNull(raw.checked_out_by),
    checked_out_at: emptyToNull(raw.checked_out_at),
    checked_in_by: emptyToNull(raw.checked_in_by),
    checked_in_at: emptyToNull(raw.checked_in_at),
    coordination: raw.coordination != null ? asBool(raw.coordination) : undefined,
    github_issue_url: typeof raw.github_issue_url === 'string' ? raw.github_issue_url : undefined,
    category: asOptionalString(raw.category, null),
    intent: asOptionalString(raw.intent, null),
    acceptance_criteria: Array.isArray(raw.acceptance_criteria)
      ? (raw.acceptance_criteria as Task['acceptance_criteria'])
      : [],
    subtask_ids: asStringArray(raw.subtask_ids),
    transition_type: asOptionalString(raw.transition_type, null),
    typed_relationships: normalizeTypedRelationships(raw.typed_relationships),
    context_node: raw.context_node != null ? (raw.context_node as Task['context_node']) : undefined,
  }

  return warnings.length > 0 ? { data, warning: warnings.join('; ') } : { data }
}

// ---------------------------------------------------------------------------
// Issue (ENC-FTR-073 §4.2)
// ---------------------------------------------------------------------------

export function normalizeIssue(input: unknown): NormalizationResult<Issue> {
  const raw = asRecord(input)
  const warnings: string[] = []
  const issueId = asString(raw.issue_id ?? raw.item_id)
  if (!issueId) warnings.push('issue record missing identifier (item_id/issue_id)')

  const data: Issue = {
    issue_id: issueId,
    project_id: asString(raw.project_id),
    title: asString(raw.title),
    description: asString(raw.description),
    status: (asOptionalString(raw.status) ?? 'open') as Issue['status'],
    priority: (asOptionalString(raw.priority) ?? 'P2') as Issue['priority'],
    severity: (asOptionalString(raw.severity) ?? 'medium') as Issue['severity'],
    hypothesis: asOptionalString(raw.hypothesis, null),
    related_feature_ids: asStringArray(raw.related_feature_ids),
    related_task_ids: asStringArray(raw.related_task_ids),
    related_issue_ids: asStringArray(raw.related_issue_ids),
    history: normalizeHistory(raw.history),
    parent: asOptionalString(raw.parent, null),
    updated_at: asOptionalString(raw.updated_at, null),
    last_update_note: asOptionalString(raw.last_update_note, null),
    created_at: asOptionalString(raw.created_at, null),
    coordination: raw.coordination != null ? asBool(raw.coordination) : undefined,
    github_issue_url: typeof raw.github_issue_url === 'string' ? raw.github_issue_url : undefined,
    category: asOptionalString(raw.category, null),
    intent: asOptionalString(raw.intent, null),
    primary_task: asOptionalString(raw.primary_task, null),
    evidence: Array.isArray(raw.evidence)
      ? (raw.evidence as Issue['evidence'])
      : [],
    typed_relationships: normalizeTypedRelationships(raw.typed_relationships),
    context_node: raw.context_node != null ? (raw.context_node as Issue['context_node']) : undefined,
  }

  return warnings.length > 0 ? { data, warning: warnings.join('; ') } : { data }
}

// ---------------------------------------------------------------------------
// Feature (ENC-FTR-073 §4.3)
// ---------------------------------------------------------------------------

export function normalizeFeature(input: unknown): NormalizationResult<Feature> {
  const raw = asRecord(input)
  const warnings: string[] = []
  const featureId = asString(raw.feature_id ?? raw.item_id)
  if (!featureId) warnings.push('feature record missing identifier (item_id/feature_id)')

  const successMetrics = asStringArray(raw.success_metrics)

  const data: Feature = {
    feature_id: featureId,
    project_id: asString(raw.project_id),
    title: asString(raw.title),
    description: asString(raw.description),
    status: (asOptionalString(raw.status) ?? 'planned') as Feature['status'],
    owners: asStringArray(raw.owners),
    success_metrics_count: asNumber(raw.success_metrics_count, successMetrics.length),
    success_metrics: successMetrics,
    related_task_ids: asStringArray(raw.related_task_ids),
    related_feature_ids: asStringArray(raw.related_feature_ids),
    related_issue_ids: asStringArray(raw.related_issue_ids),
    history: normalizeHistory(raw.history),
    parent: asOptionalString(raw.parent, null),
    updated_at: asOptionalString(raw.updated_at, null),
    last_update_note: asOptionalString(raw.last_update_note, null),
    created_at: asOptionalString(raw.created_at, null),
    coordination: raw.coordination != null ? asBool(raw.coordination) : undefined,
    github_issue_url: typeof raw.github_issue_url === 'string' ? raw.github_issue_url : undefined,
    category: asOptionalString(raw.category, null),
    intent: asOptionalString(raw.intent, null),
    user_story: asOptionalString(raw.user_story, null),
    primary_task: asOptionalString(raw.primary_task, null),
    acceptance_criteria: Array.isArray(raw.acceptance_criteria)
      ? (raw.acceptance_criteria as Feature['acceptance_criteria'])
      : [],
    typed_relationships: normalizeTypedRelationships(raw.typed_relationships),
    context_node: raw.context_node != null ? (raw.context_node as Feature['context_node']) : undefined,
  }

  return warnings.length > 0 ? { data, warning: warnings.join('; ') } : { data }
}

// ---------------------------------------------------------------------------
// Plan (ENC-FTR-073 §4.4)
// ---------------------------------------------------------------------------

export function normalizePlan(input: unknown): NormalizationResult<Plan> {
  const raw = asRecord(input)
  const warnings: string[] = []
  const planId = asString(raw.plan_id ?? raw.item_id)
  if (!planId) warnings.push('plan record missing identifier (item_id/plan_id)')

  const data: Plan = {
    plan_id: planId,
    project_id: asString(raw.project_id),
    title: asString(raw.title),
    description: asString(raw.description),
    status: (asOptionalString(raw.status) ?? 'drafted') as Plan['status'],
    priority: (asOptionalString(raw.priority) ?? 'P2') as Plan['priority'],
    category: asOptionalString(raw.category, null),
    objectives_set: asStringArray(raw.objectives_set),
    attached_documents: asStringArray(raw.attached_documents),
    related_feature_id: asOptionalString(raw.related_feature_id, null),
    checkout_state: emptyToNull(raw.checkout_state),
    checked_out_by: emptyToNull(raw.checked_out_by),
    checked_out_at: emptyToNull(raw.checked_out_at),
    related_task_ids: asStringArray(raw.related_task_ids),
    related_issue_ids: asStringArray(raw.related_issue_ids),
    related_feature_ids: asStringArray(raw.related_feature_ids),
    history: normalizeHistory(raw.history),
    updated_at: asOptionalString(raw.updated_at, null),
    last_update_note: asOptionalString(raw.last_update_note, null),
    created_at: asOptionalString(raw.created_at, null),
    typed_relationships: normalizeTypedRelationships(raw.typed_relationships),
  }

  return warnings.length > 0 ? { data, warning: warnings.join('; ') } : { data }
}

// ---------------------------------------------------------------------------
// Lesson (ENC-FTR-073 §4.5)
// ---------------------------------------------------------------------------
//
// Only record type with a non-trivial field-level remap: the raw DDB shape
// for `extensions` is `{evidence_ids, author, content, timestamp}` while the
// feed shape (LessonDetailPage render contract) is `{description, timestamp,
// provider?}`. Rename author -> provider, content -> description, drop
// evidence_ids.

function normalizeLessonExtensions(value: unknown): LessonExtension[] {
  const arr = asArray<RawRecord>(value)
  return arr.map((raw) => {
    // Accept already-normalized feed shape unchanged (description/provider).
    // Accept API shape (author/content) with the documented remap.
    const description =
      typeof raw.description === 'string'
        ? raw.description
        : typeof raw.content === 'string'
          ? raw.content
          : ''
    const provider =
      typeof raw.provider === 'string'
        ? raw.provider
        : typeof raw.author === 'string'
          ? raw.author
          : undefined
    return {
      description,
      timestamp: asString(raw.timestamp),
      provider,
    }
  })
}

function normalizePillarScores(value: unknown): PillarScores {
  const raw = asRecord(value)
  return {
    efficiency: asNumber(raw.efficiency, 0),
    human_protection: asNumber(raw.human_protection, 0),
    intention: asNumber(raw.intention, 0),
    alignment: asNumber(raw.alignment, 0),
  }
}

export function normalizeLesson(input: unknown): NormalizationResult<Lesson> {
  const raw = asRecord(input)
  const warnings: string[] = []
  const lessonId = asString(raw.lesson_id ?? raw.item_id)
  if (!lessonId) warnings.push('lesson record missing identifier (item_id/lesson_id)')

  const analysisReference =
    typeof raw.analysis_reference === 'string' && raw.analysis_reference.length > 0
      ? raw.analysis_reference
      : undefined
  const governanceProposal =
    typeof raw.governance_proposal === 'string' && raw.governance_proposal.length > 0
      ? raw.governance_proposal
      : undefined

  const data: Lesson = {
    lesson_id: lessonId,
    project_id: asString(raw.project_id),
    title: asString(raw.title),
    observation: asString(raw.observation),
    insight: asString(raw.insight),
    evidence_chain: asStringArray(raw.evidence_chain),
    provenance: asString(raw.provenance),
    confidence: asNumber(raw.confidence, 0),
    pillar_scores: normalizePillarScores(raw.pillar_scores),
    resonance_score: asNumber(raw.resonance_score, 0),
    pillar_composite: asNumber(raw.pillar_composite, 0),
    extensions: normalizeLessonExtensions(raw.extensions),
    category: asString(raw.category),
    status: (asOptionalString(raw.status) ?? 'active') as Lesson['status'],
    lesson_version: asNumber(raw.lesson_version, 1),
    analysis_reference: analysisReference,
    governance_proposal: governanceProposal,
    related_task_ids: asStringArray(raw.related_task_ids),
    related_issue_ids: asStringArray(raw.related_issue_ids),
    related_feature_ids: asStringArray(raw.related_feature_ids),
    history: normalizeHistory(raw.history),
    updated_at: asOptionalString(raw.updated_at, null),
    last_update_note: asOptionalString(raw.last_update_note, null),
    created_at: asOptionalString(raw.created_at, null),
  }

  return warnings.length > 0 ? { data, warning: warnings.join('; ') } : { data }
}

// ---------------------------------------------------------------------------
// Document (ENC-FTR-073 §4.6)
// ---------------------------------------------------------------------------
//
// Identity-ish normalizer — the document_api already returns feed-shape
// objects. Provided for symmetry so useRecordFallback can dispatch by
// recordType without a special-case.

export function normalizeDocument(input: unknown): NormalizationResult<Document> {
  const raw = asRecord(input)
  const warnings: string[] = []
  const documentId = asString(raw.document_id ?? raw.item_id)
  if (!documentId) warnings.push('document record missing identifier (document_id/item_id)')

  const data: Document = {
    document_id: documentId,
    project_id: asString(raw.project_id),
    title: asString(raw.title),
    description: asString(raw.description),
    file_name: asString(raw.file_name),
    content_type: asString(raw.content_type),
    content_hash: asString(raw.content_hash),
    size_bytes: asNumber(raw.size_bytes, 0),
    keywords: asStringArray(raw.keywords),
    related_items: asStringArray(raw.related_items),
    status: (asOptionalString(raw.status) ?? 'active') as Document['status'],
    created_by: asString(raw.created_by),
    created_at: asString(raw.created_at),
    updated_at: asString(raw.updated_at),
    version: asNumber(raw.version, 1),
    content: typeof raw.content === 'string' ? raw.content : undefined,
    document_subtype: typeof raw.document_subtype === 'string'
      ? (raw.document_subtype as Document['document_subtype'])
      : undefined,
    source_record_id: typeof raw.source_record_id === 'string' ? raw.source_record_id : undefined,
    handoff_status: typeof raw.handoff_status === 'string'
      ? (raw.handoff_status as Document['handoff_status'])
      : undefined,
    prerequisite_state: typeof raw.prerequisite_state === 'string' ? raw.prerequisite_state : undefined,
    action_checklist: asStringArray(raw.action_checklist),
    verification_criteria: typeof raw.verification_criteria === 'string' ? raw.verification_criteria : undefined,
    expires_at: typeof raw.expires_at === 'string' ? raw.expires_at : undefined,
    claimed_by: typeof raw.claimed_by === 'string' ? raw.claimed_by : undefined,
    claimed_at: typeof raw.claimed_at === 'string' ? raw.claimed_at : undefined,
    created_by_session: typeof raw.created_by_session === 'string' ? raw.created_by_session : undefined,
  }

  return warnings.length > 0 ? { data, warning: warnings.join('; ') } : { data }
}

// ---------------------------------------------------------------------------
// Dispatch map — useful for the useRecordFallback hook.
// ---------------------------------------------------------------------------

export type RecordType = 'task' | 'issue' | 'feature' | 'plan' | 'lesson' | 'document'

export interface RecordTypeMap {
  task: Task
  issue: Issue
  feature: Feature
  plan: Plan
  lesson: Lesson
  document: Document
}

const NORMALIZERS = {
  task: normalizeTask,
  issue: normalizeIssue,
  feature: normalizeFeature,
  plan: normalizePlan,
  lesson: normalizeLesson,
  document: normalizeDocument,
} as const

export function normalizeRecord<T extends RecordType>(
  recordType: T,
  input: unknown,
): NormalizationResult<RecordTypeMap[T]> {
  const fn = NORMALIZERS[recordType]
  // Runtime dispatch; cast is safe because NORMALIZERS[recordType] is the
  // normalizer returning NormalizationResult<RecordTypeMap[T]>.
  return fn(input) as NormalizationResult<RecordTypeMap[T]>
}
