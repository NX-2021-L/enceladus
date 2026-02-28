export interface TerminalSession {
  session_id: string
  provider: string
  project_id: string
  started_at: string
  last_activity_at: string
  turn_count: number
  latest_request_id: string
  latest_state: string
  is_active: boolean
}

export interface TerminalTurn {
  turn_index: number
  role: 'user' | 'assistant'
  content: string
  timestamp_utc?: string
  timestamp?: string
  dispatch_id?: string
}

export interface TerminalProvider {
  id: string
  name: string
  execution_mode: string
  description: string
}

export interface TerminalSessionsResponse {
  success: boolean
  generated_at: string
  sessions: TerminalSession[]
  count: number
}

export interface TerminalTurnsResponse {
  success: boolean
  session_id: string
  turns: TerminalTurn[]
  count: number
}

export interface SendMessageResponse {
  success: boolean
  request: {
    request_id: string
    state: string
    [key: string]: unknown
  }
}

export interface ActiveSessionState {
  session_id: string
  provider: string
  project_id: string
}
