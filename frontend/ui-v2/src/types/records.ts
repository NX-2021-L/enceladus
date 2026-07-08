/**
 * Record type contracts for the six Enceladus governance primitives.
 *
 * These mirror the canonical shapes in frontend/ui/src/types/feeds.ts. The
 * ui-v2 scaffold owns its own copy so it never imports from the legacy app
 * (per the ENC-TSK-K21 scope constraint). Fields are trimmed to what the
 * scaffold primitives render; extend as real screens land.
 */

export type RecordType =
  | 'task'
  | 'issue'
  | 'feature'
  | 'plan'
  | 'lesson'
  | 'document'

export interface HistoryEntry {
  timestamp: string
  status: string
  description: string
}

export interface TypedRelationshipEdge {
  relationship_type: string
  target_id: string
  weight: number
  confidence: number
  reason: string | null
  created_at: string | null
}

export interface ContextNodeMeta {
  freshness_score: number
  structural_importance: number
  information_density: number
  access_frequency: number
}

export interface RecordExtensions {
  typed_relationships?: TypedRelationshipEdge[]
  context_node?: ContextNodeMeta
  subtask_ids?: string[]
}

/** AC evidence stamp (ENC-TSK-M23 / FND-03) -- the shape tracker.get returns
 *  under `acceptance_criteria` for governed records. */
export interface AcceptanceCriterion {
  description: string
  evidence: string
  evidence_acceptance: boolean
}

/**
 * Governed lifecycle metadata shared by every checked-out-able tracker
 * record (ENC-TSK-M23 / FND-03). Extended for ENC-TSK-M33 (v3 action
 * parity): checkout/session fields drive the state-aware primary action
 * (Check In vs advance/revert), `github_issue_url` drives the GitHub link
 * button, and `components` feeds the chip row.
 */
export interface GovernedLifecycleMeta {
  transition_type?: string
  checkout_state?: string
  checked_out_by?: string | null
  checked_in_by?: string | null
  checked_in_at?: string | null
  /** True while an agent (or a borrowed Cognito user_initiated write) holds
   *  this record's checkout lock -- the authoritative "checked out" signal. */
  active_agent_session?: boolean
  active_agent_session_id?: string | null
  /** ENC-TSK-L47 If-Match revision counter -- required for safe concurrent writes. */
  sync_version?: number
  /** Populated once the record is linked to a GitHub PR/issue/commit. */
  github_issue_url?: string | null
  commit_sha?: string | null
  components?: string[]
}

export interface Task extends GovernedLifecycleMeta {
  task_id: string
  project_id: string
  title: string
  description: string
  status: string
  priority: 'P0' | 'P1' | 'P2' | 'P3'
  assigned_to: string | null
  related_feature_ids: string[]
  related_task_ids: string[]
  related_issue_ids: string[]
  checklist_total: number
  checklist_done: number
  history: HistoryEntry[]
  updated_at: string | null
  created_at: string | null
  sync_version?: number
  typed_relationships?: TypedRelationshipEdge[]
  context_node?: ContextNodeMeta
  subtask_ids?: string[]
  acceptance_criteria?: AcceptanceCriterion[]
  commit_approval_id?: string | null
  commit_complete_id?: string | null
}

export interface IssueEvidence {
  description: string
  steps_to_duplicate?: string[]
}

export interface Issue extends GovernedLifecycleMeta {
  issue_id: string
  project_id: string
  title: string
  description: string
  status: 'open' | 'in-progress' | 'closed'
  priority: 'P0' | 'P1' | 'P2' | 'P3'
  severity: 'low' | 'medium' | 'high' | 'critical'
  category?: string | null
  hypothesis: string | null
  evidence?: IssueEvidence[]
  related_task_ids: string[]
  history: HistoryEntry[]
  updated_at: string | null
  created_at: string | null
  typed_relationships?: TypedRelationshipEdge[]
  context_node?: ContextNodeMeta
}

export interface Feature extends GovernedLifecycleMeta {
  feature_id: string
  project_id: string
  title: string
  description: string
  status: 'planned' | 'in-progress' | 'completed' | 'production' | 'deprecated'
  category?: string | null
  user_story?: string | null
  acceptance_criteria?: AcceptanceCriterion[]
  owners: string[]
  success_metrics: string[]
  related_task_ids: string[]
  history: HistoryEntry[]
  updated_at: string | null
  created_at: string | null
  typed_relationships?: TypedRelationshipEdge[]
  context_node?: ContextNodeMeta
}

export interface Plan extends GovernedLifecycleMeta {
  plan_id: string
  project_id: string
  title: string
  description: string
  status: 'drafted' | 'started' | 'complete' | 'incomplete'
  priority: 'P0' | 'P1' | 'P2' | 'P3'
  category: string | null
  objectives_set: string[]
  attached_documents: string[]
  related_task_ids: string[]
  history: HistoryEntry[]
  updated_at: string | null
  created_at: string | null
  typed_relationships?: TypedRelationshipEdge[]
  context_node?: ContextNodeMeta
}

export interface PillarScores {
  efficiency: number
  human_protection: number
  intention: number
  alignment: number
}

export interface Lesson {
  lesson_id: string
  project_id: string
  title: string
  observation: string
  insight: string
  evidence_chain: string[]
  provenance: string
  confidence: number
  pillar_scores: PillarScores
  pillar_composite: number
  resonance_score: number
  category: string
  status: string
  updated_at: string | null
  created_at: string | null
}

export interface Document {
  document_id: string
  project_id: string
  title: string
  description: string
  file_name: string
  content_type: string
  keywords: string[]
  related_items: string[]
  status: 'active' | 'archived'
  created_by: string
  created_at: string
  updated_at: string
  version: number
  document_subtype?: string
  /** Full raw markdown body. Present when fetched with include_content=true
   *  (the default for a single-document GET) — ENC-TSK-M34. */
  content?: string
  content_hash?: string
  size_bytes?: number
  compliance_score?: number
  compliance_warnings?: string[]
}

export interface RecordShapeMap {
  task: Task
  issue: Issue
  feature: Feature
  plan: Plan
  lesson: Lesson
  document: Document
}
