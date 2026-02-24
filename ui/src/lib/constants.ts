// Feature flags — flip to false to disable without removing code
export const ENABLE_REFRESH_LINK = true

// ---------------------------------------------------------------------------
// Auth / Cognito constants
// ---------------------------------------------------------------------------

export const COGNITO_DOMAIN =
  'https://enceladus-status-356364570033.auth.us-east-1.amazoncognito.com'
export const COGNITO_CLIENT_ID = '6q607dk3liirhtecgps7hifmlk'
export const COGNITO_REDIRECT_URI = 'https://jreese.net/enceladus/callback'
export const COGNITO_SCOPES = 'openid email profile'

export const STATUS_COLORS: Record<string, string> = {
  open: 'bg-blue-500/20 text-blue-400',
  closed: 'bg-rose-500/20 text-rose-400',
  in_progress: 'bg-amber-500/20 text-amber-400',
  'in-progress': 'bg-amber-500/20 text-amber-400',
  planned: 'bg-purple-500/20 text-purple-400',
  completed: 'bg-emerald-500/20 text-emerald-400',
  created: 'bg-teal-500/20 text-teal-400',
  started: 'bg-blue-500/20 text-blue-400',
  worklog: 'bg-indigo-500/20 text-indigo-400',
  resolved: 'bg-emerald-500/20 text-emerald-400',
  blocked: 'bg-red-500/20 text-red-400',
  active: 'bg-emerald-500/20 text-emerald-400',
  archived: 'bg-slate-500/20 text-slate-400',
}

export const PRIORITY_COLORS: Record<string, string> = {
  P0: 'bg-red-500/20 text-red-400',
  P1: 'bg-orange-500/20 text-orange-400',
  P2: 'bg-yellow-500/20 text-yellow-400',
  P3: 'bg-slate-500/20 text-slate-400',
}

export const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-slate-500/20 text-slate-400',
}

export const STATUS_LABELS: Record<string, string> = {
  open: 'Open',
  closed: 'Closed',
  in_progress: 'In Progress',
  'in-progress': 'In Progress',
  planned: 'Planned',
  completed: 'Completed',
  created: 'Created',
  started: 'Started',
  worklog: 'Worklog',
  resolved: 'Resolved',
  blocked: 'Blocked',
  active: 'Active',
  archived: 'Archived',
}

export const TASK_STATUSES = ['open', 'in_progress', 'planned', 'closed'] as const
export const ISSUE_STATUSES = ['open', 'closed'] as const
export const FEATURE_STATUSES = ['planned', 'in_progress', 'completed', 'closed'] as const
export const PRIORITIES = ['P0', 'P1', 'P2', 'P3'] as const
export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const

export const SORT_OPTIONS_TASKS = [
  { value: 'updated', label: 'Last Updated' },
  { value: 'created', label: 'Created' },
  { value: 'priority', label: 'Priority' },
] as const

export const SORT_OPTIONS_ISSUES = [
  { value: 'updated', label: 'Last Updated' },
  { value: 'created', label: 'Created' },
  { value: 'priority', label: 'Priority' },
] as const

export const SORT_OPTIONS_FEATURES = [
  { value: 'updated', label: 'Last Updated' },
  { value: 'created', label: 'Created' },
] as const

export const PRIORITY_ORDER: Record<string, number> = {
  P0: 0,
  P1: 1,
  P2: 2,
  P3: 3,
}

export const FEED_RECORD_TYPES = ['task', 'issue', 'feature'] as const

export const RECORD_TYPE_LABELS: Record<string, string> = {
  task: 'Tasks',
  issue: 'Issues',
  feature: 'Features',
}

export const RECORD_TYPE_COLORS: Record<string, string> = {
  task: 'bg-blue-500/20 text-blue-400',
  issue: 'bg-amber-500/20 text-amber-400',
  feature: 'bg-emerald-500/20 text-emerald-400',
}

export const SORT_OPTIONS_FEED = [
  { value: 'updated', label: 'Last Updated' },
  { value: 'created', label: 'Created' },
] as const

// ---------------------------------------------------------------------------
// Coordination states
// ---------------------------------------------------------------------------

export const COORDINATION_STATES = [
  'intake_received', 'queued', 'dispatching', 'running',
  'succeeded', 'failed', 'cancelled', 'dead_letter',
] as const

export const COORDINATION_STATE_COLORS: Record<string, string> = {
  intake_received: 'bg-teal-500/20 text-teal-400',
  queued: 'bg-blue-500/20 text-blue-400',
  dispatching: 'bg-amber-500/20 text-amber-400',
  running: 'bg-cyan-500/20 text-cyan-400',
  succeeded: 'bg-emerald-500/20 text-emerald-400',
  failed: 'bg-red-500/20 text-red-400',
  cancelled: 'bg-slate-500/20 text-slate-400',
  dead_letter: 'bg-red-700/20 text-red-500',
}

export const COORDINATION_STATE_LABELS: Record<string, string> = {
  intake_received: 'Intake',
  queued: 'Queued',
  dispatching: 'Dispatching',
  running: 'Running',
  succeeded: 'Succeeded',
  failed: 'Failed',
  cancelled: 'Cancelled',
  dead_letter: 'Dead Letter',
}

// ---------------------------------------------------------------------------
// Active agent session and coordination flags
// ---------------------------------------------------------------------------

export const ACTIVE_SESSION_COLORS: Record<string, string> = {
  active: 'bg-emerald-500/20 text-emerald-400',
  inactive: 'bg-slate-500/20 text-slate-400',
}

export const ACTIVE_SESSION_LABELS: Record<string, string> = {
  active: 'Active',
  inactive: 'Inactive',
}

export const COORDINATION_FLAG_COLOR = 'bg-cyan-500/20 text-cyan-400'
export const COORDINATION_FLAG_LABEL = 'Coordination'

export const SORT_OPTIONS_COORDINATION = [
  { value: 'updated', label: 'Last Updated' },
  { value: 'created', label: 'Created' },
] as const

export const DOCUMENT_STATUSES = ['active', 'archived'] as const

export const SORT_OPTIONS_DOCUMENTS = [
  { value: 'updated', label: 'Last Updated' },
  { value: 'created', label: 'Created' },
  { value: 'size', label: 'Size' },
] as const
