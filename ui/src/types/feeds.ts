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
  status: 'open' | 'closed' | 'in_progress' | 'planned'
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
}

export interface Issue {
  issue_id: string
  project_id: string
  title: string
  description: string
  status: 'open' | 'closed'
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
}

export interface Feature {
  feature_id: string
  project_id: string
  title: string
  description: string
  status: 'planned' | 'in_progress' | 'completed' | 'closed'
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
