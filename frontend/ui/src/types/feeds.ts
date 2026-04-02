// --- Changelog types (ENC-FTR-033) ---

export interface ChangelogEntry {
  project_id: string
  spec_id: string
  version: string
  previous_version: string
  change_type: 'major' | 'minor' | 'patch'
  release_summary: string
  changes: string[]
  deployed_at: string
  related_record_ids: string[]
  files_changed?: string[]
  deployment_type?: string
}

export interface ProjectVersion {
  project_id: string
  version: string
  deployed_at: string
  spec_id: string
}

// --- Core tracker types ---

export interface HistoryEntry {
  timestamp: string
  status: string
  description: string
}

export interface ProjectSummary {
  project_id: string
  name: string
  prefix: string
  status: string
  summary: string
  last_sprint: string
  open_tasks: number
  closed_tasks: number
  total_tasks: number
  open_issues: number
  closed_issues: number
  total_issues: number
  in_progress_features: number
  completed_features: number
  total_features: number
  planned_tasks: number
  updated_at: string | null
  last_update_note: string | null
}

export interface Task {
  task_id: string
  project_id: string
  title: string
  description: string
  status: 'open' | 'in-progress' | 'coding-complete' | 'committed' | 'pushed' | 'merged-main' | 'deploy-init' | 'deploy-success' | 'coding-updates' | 'closed' | 'deployed' // 'deployed' kept for legacy compat until TSK-704 migration
  priority: 'P0' | 'P1' | 'P2' | 'P3'
  assigned_to: string | null
  related_feature_ids: string[]
  related_task_ids: string[]
  related_issue_ids: string[]
  checklist_total: number
  checklist_done: number
  checklist: string[]
  history: HistoryEntry[]
  parent: string | null
  updated_at: string | null
  last_update_note: string | null
  created_at: string | null
  // Active agent session fields
  active_agent_session?: boolean
  active_agent_session_id?: string
  active_agent_session_parent?: boolean
  checkout_state?: 'checked_out' | 'checked_in' | null
  checked_out_by?: string | null
  checked_out_at?: string | null
  checked_in_by?: string | null
  checked_in_at?: string | null
  // Coordination flag
  coordination?: boolean
  // GitHub integration (ENC-FTR-021)
  github_issue_url?: string
  // Philosophy fields (ENC-FTR-017)
  category?: string | null
  intent?: string | null
  acceptance_criteria?: Array<string | { description: string; evidence?: string; evidence_acceptance?: boolean }>
  // Plan tree fields (ENC-ISS-139 / ENC-TSK-A57)
  subtask_ids?: string[]
  transition_type?: string | null
  // Extensions (ENC-TSK-A57)
  typed_relationships?: TypedRelationshipEdge[]
  context_node?: ContextNodeMeta
}

export interface Issue {
  issue_id: string
  project_id: string
  title: string
  description: string
  status: 'open' | 'in-progress' | 'closed'
  priority: 'P0' | 'P1' | 'P2' | 'P3'
  severity: 'low' | 'medium' | 'high' | 'critical'
  hypothesis: string | null
  related_feature_ids: string[]
  related_task_ids: string[]
  related_issue_ids: string[]
  history: HistoryEntry[]
  parent: string | null
  updated_at: string | null
  last_update_note: string | null
  created_at: string | null
  // Coordination flag
  coordination?: boolean
  // GitHub integration (ENC-FTR-021)
  github_issue_url?: string
  // Philosophy fields (ENC-FTR-017)
  category?: string | null
  intent?: string | null
  primary_task?: string | null
  evidence?: Array<{
    description: string
    steps_to_duplicate: string[]
    observed_by?: string
    timestamp?: string
  }>
  // Extensions (ENC-TSK-A57)
  typed_relationships?: TypedRelationshipEdge[]
  context_node?: ContextNodeMeta
}

export interface Feature {
  feature_id: string
  project_id: string
  title: string
  description: string
  status: 'planned' | 'in-progress' | 'completed' | 'production' | 'deprecated'
  owners: string[]
  success_metrics_count: number
  success_metrics: string[]
  related_task_ids: string[]
  related_feature_ids: string[]
  related_issue_ids: string[]
  history: HistoryEntry[]
  parent: string | null
  updated_at: string | null
  last_update_note: string | null
  created_at: string | null
  // Coordination flag
  coordination?: boolean
  // GitHub integration (ENC-FTR-021)
  github_issue_url?: string
  // Philosophy fields (ENC-FTR-017)
  category?: string | null
  intent?: string | null
  user_story?: string | null
  primary_task?: string | null
  acceptance_criteria?: Array<{
    description: string
    evidence: string
    evidence_acceptance: boolean
  }>
  // Extensions (ENC-TSK-A57)
  typed_relationships?: TypedRelationshipEdge[]
  context_node?: ContextNodeMeta
}

export interface PillarScores {
  efficiency: number
  human_protection: number
  intention: number
  alignment: number
}

export interface LessonExtension {
  description: string
  timestamp: string
  provider?: string
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
  resonance_score: number
  pillar_composite: number
  extensions: LessonExtension[]
  category: string
  status: string
  lesson_version: number
  analysis_reference?: string
  governance_proposal?: string
  related_task_ids: string[]
  related_issue_ids: string[]
  related_feature_ids: string[]
  history: HistoryEntry[]
  updated_at: string | null
  last_update_note: string | null
  created_at: string | null
}

// --- Typed relationship edges (ENC-FTR-049 / ENC-ISS-137) ---

export interface TypedRelationshipEdge {
  relationship_type: string
  target_id: string
  weight: number
  confidence: number
  reason: string | null
  created_at: string | null
}

// --- Context node metadata (ENC-FTR-050 / ENC-ISS-138) ---

export interface ContextNodeMeta {
  freshness_score: number
  structural_importance: number
  information_density: number
  access_frequency: number
}

// Mixin for records that may have typed relationships and context nodes
export interface RecordExtensions {
  typed_relationships?: TypedRelationshipEdge[]
  context_node?: ContextNodeMeta
  subtask_ids?: string[]
}

export interface FeedEnvelope<T> {
  generated_at: string
  version: string
  [key: string]: T[] | string
}

export interface ProjectsFeed extends FeedEnvelope<ProjectSummary> {
  projects: ProjectSummary[]
}

export interface TasksFeed extends FeedEnvelope<Task> {
  tasks: Task[]
}

export interface IssuesFeed extends FeedEnvelope<Issue> {
  issues: Issue[]
}

export interface FeaturesFeed extends FeedEnvelope<Feature> {
  features: Feature[]
}

export interface LessonsFeed extends FeedEnvelope<Lesson> {
  lessons: Lesson[]
}

export interface DocumentsFeed extends FeedEnvelope<Document> {
  documents: Document[]
}

export interface Document {
  document_id: string
  project_id: string
  title: string
  description: string
  file_name: string
  content_type: string
  content_hash: string
  size_bytes: number
  keywords: string[]
  related_items: string[]
  status: 'active' | 'archived'
  created_by: string
  created_at: string
  updated_at: string
  version: number
  content?: string
}
