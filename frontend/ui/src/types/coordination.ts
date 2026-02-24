export interface CoordinationStateHistoryEntry {
  timestamp: string
  from: string
  to: string
  description?: string
}

export interface DispatchPlanSummary {
  plan_id: string
  dispatches_count: number
  strategy?: {
    rationale: string
    decomposition: string
    estimated_duration_minutes?: number
  }
}

export interface CoordinationResult {
  summary?: string
  failure_class?: string
}

export interface CoordinationRequest {
  request_id: string
  project_id: string
  initiative_title: string
  state: string
  execution_mode?: string | null
  outcomes: string[]
  constraints?: Record<string, unknown> | null
  requestor_session_id?: string | null
  related_record_ids?: string[]
  created_at: string
  updated_at: string
  dispatch_plan?: DispatchPlanSummary | null
  state_history?: CoordinationStateHistoryEntry[]
  state_history_count?: number
  dispatch_attempts?: number
  result?: CoordinationResult | null
  provider_preferences?: Record<string, unknown> | null
  mcp?: Record<string, unknown> | null
}

export interface CoordinationMonitorResponse {
  success: boolean
  generated_at: string
  requests: CoordinationRequest[]
  count: number
}

export interface CoordinationDetailResponse {
  success: boolean
  request: CoordinationRequest
}
