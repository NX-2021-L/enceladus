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

export interface Task {
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
  related_task_ids: string[]
  history: HistoryEntry[]
  updated_at: string | null
  created_at: string | null
}

export interface Feature {
  feature_id: string
  project_id: string
  title: string
  description: string
  status: 'planned' | 'in-progress' | 'completed' | 'production' | 'deprecated'
  owners: string[]
  success_metrics: string[]
  related_task_ids: string[]
  history: HistoryEntry[]
  updated_at: string | null
  created_at: string | null
}

export interface Plan {
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
}

/**
 * Maps each record type to its concrete record interface. Used to keep the
 * query-options factories, the primitive registry, and the routes in lockstep
 * so `useSuspenseQuery` returns a fully-typed `T`, never `T | undefined`.
 */
export interface RecordShapeMap {
  task: Task
  issue: Issue
  feature: Feature
  plan: Plan
  lesson: Lesson
  document: Document
}
