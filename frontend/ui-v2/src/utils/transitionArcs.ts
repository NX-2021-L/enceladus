/**
 * Governed lifecycle-transition computation (ENC-TSK-M33 / DOC-B6B52E3BB9BB
 * §7). Pure functions, no React -- the state-aware primary action button
 * needs to compute, for any record, the correct next control(s):
 *
 *  - checked out (active_agent_session) -> a single "Check In" control,
 *    hiding the lifecycle stepper (matches the v3 direct visual capture:
 *    button 1 shows exactly one of Check In / revert / advance, never a
 *    lifecycle button while checkout is held).
 *  - otherwise -> zero, one, or two adjacent-step buttons (revert to the
 *    previous status, advance to the next), computed from the record's own
 *    lifecycle arc.
 *
 * Task arcs are keyed by `transition_type` and mirror the backend's
 * canonical matrix verbatim (backend/lambda/tracker_mutation/
 * transition_type_matrix.py ALLOWED_TRANSITIONS_BY_TYPE, ENC-FTR-059 /
 * DOC-B5B807D7C2CE), with the implicit 'open' starting state prefixed --
 * NOT the legacy v3 frontend's hand-rolled TASK_STATUSES array
 * (frontend/ui/src/lib/constants.ts), which is stale (`pushed` where the
 * backend matrix and validation_rules both say `pr` -- see
 * ENC-LSN feedback "validation_rules 'pushed' vs handler 'pr'"). Using the
 * real backend matrix is what "compute the valid next transition from the
 * record's transition_type arc" means; issue/feature/plan keep the simple
 * linear arcs the legacy app already uses (those record types don't carry a
 * transition_type).
 *
 * The one honest "cannot do this from the PWA" case this module detects is
 * a record whose current status isn't a member of its own computed arc (bad
 * data, or an arc this module doesn't yet know about) -- everything else a
 * human can legally attempt via the existing ENC-ISS-092 user_initiated
 * bypass (tasks) / revert_reason path (issue/feature/plan) is rendered live,
 * matching v3 parity exactly rather than inventing a new restriction v3
 * doesn't have.
 */

export type TrackerRecordType = 'task' | 'issue' | 'feature' | 'plan'

/** Mirrors backend ALLOWED_TRANSITIONS_BY_TYPE (transition_type_matrix.py),
 *  with 'open' prefixed as the implicit starting state. */
export const TASK_ARC_BY_TRANSITION_TYPE: Record<string, string[]> = {
  github_pr_deploy: [
    'open', 'in-progress', 'coding-complete', 'committed', 'pr',
    'merged-main', 'deploy-init', 'deploy-success', 'closed',
  ],
  lambda_deploy: [
    'open', 'in-progress', 'coding-complete', 'committed', 'pr',
    'merged-main', 'deploy-init', 'deploy-success', 'closed',
  ],
  web_deploy: [
    'open', 'in-progress', 'coding-complete', 'committed', 'pr',
    'merged-main', 'deploy-init', 'deploy-success', 'closed',
  ],
  code_only: [
    'open', 'in-progress', 'coding-complete', 'committed', 'pr',
    'merged-main', 'closed',
  ],
  no_code: [
    'open', 'in-progress', 'coding-complete', 'closed',
  ],
}

export const DEFAULT_TASK_TRANSITION_TYPE = 'github_pr_deploy'

/** Issue/feature/plan don't carry a transition_type -- one fixed linear arc
 *  each, matching the legacy PWA's LIFECYCLE_MAP (frontend/ui/src/components/
 *  shared/LifecycleActions.tsx) verbatim for parity. */
export const ISSUE_ARC = ['open', 'in-progress', 'closed']
export const FEATURE_ARC = ['planned', 'in-progress', 'completed', 'production', 'deprecated']
export const PLAN_ARC = ['drafted', 'started', 'complete', 'incomplete']

export const STATUS_LABELS: Record<string, string> = {
  open: 'Open',
  'in-progress': 'In Progress',
  'coding-complete': 'Coding Complete',
  committed: 'Committed',
  pr: 'PR',
  'merged-main': 'Merged to Main',
  'deploy-init': 'Deploy Init',
  'deploy-success': 'Deploy Success',
  'coding-updates': 'Coding Updates',
  closed: 'Closed',
  planned: 'Planned',
  completed: 'Completed',
  production: 'Production',
  deprecated: 'Deprecated',
  drafted: 'Drafted',
  started: 'Started',
  complete: 'Complete',
  incomplete: 'Incomplete',
}

export function labelForStatus(status: string): string {
  return STATUS_LABELS[status] ?? status
}

/** Returns the record's lifecycle arc: the ordered list of statuses it
 *  legitimately walks through. Unknown task transition_types fall back to
 *  github_pr_deploy (the strictest arc) rather than silently allowing
 *  nothing. */
export function arcFor(recordType: TrackerRecordType, transitionType?: string | null): string[] {
  if (recordType === 'task') {
    return (
      TASK_ARC_BY_TRANSITION_TYPE[transitionType ?? DEFAULT_TASK_TRANSITION_TYPE] ??
      TASK_ARC_BY_TRANSITION_TYPE[DEFAULT_TASK_TRANSITION_TYPE]
    )
  }
  if (recordType === 'issue') return ISSUE_ARC
  if (recordType === 'feature') return FEATURE_ARC
  return PLAN_ARC
}

export type TransitionActionKind = 'check-in' | 'advance' | 'revert'

export interface TransitionAction {
  kind: TransitionActionKind
  label: string
  /** Target status this action would set (absent for 'check-in', which is a
   *  checkout-release call, not a status write). */
  targetStatus?: string
  disabled?: boolean
  disabledReason?: string
  /** True only for a task's forward step -- the primary action modal offers
   *  a "Submit + Close" terminal shortcut alongside the normal advance
   *  (matches v3's LifecycleActions "Submit + Close" for tasks only). */
  allowSubmitClose?: boolean
}

/**
 * Computes the primary action button(s) for a record's current lifecycle +
 * checkout state (ENC-TSK-M33 AC-2). Checkout takes priority over the
 * lifecycle stepper: a checked-out record renders exactly one "Check In"
 * control (releases the checkout; does not touch status). Otherwise returns
 * 0-2 buttons: a revert (if the record isn't at the arc's first status) and
 * an advance (if it isn't at the arc's last status).
 */
export function computePrimaryActions(params: {
  recordType: TrackerRecordType
  status: string
  transitionType?: string | null
  checkedOut: boolean
}): TransitionAction[] {
  const { recordType, status, transitionType, checkedOut } = params

  if (checkedOut) {
    return [{ kind: 'check-in', label: 'Check In' }]
  }

  const arc = arcFor(recordType, transitionType)
  const idx = arc.indexOf(status)

  if (idx === -1) {
    const arcLabel = recordType === 'task' ? (transitionType ?? DEFAULT_TASK_TRANSITION_TYPE) : recordType
    return [
      {
        kind: 'advance',
        label: 'Advance',
        disabled: true,
        disabledReason:
          `Status "${status}" isn't recognized in this record's ${arcLabel} lifecycle arc -- ` +
          'cannot safely compute the next transition from the PWA. Escalate to an agent session.',
      },
    ]
  }

  const actions: TransitionAction[] = []

  if (idx > 0) {
    const target = arc[idx - 1]
    actions.push({ kind: 'revert', label: `← ${labelForStatus(target)}`, targetStatus: target })
  }

  if (idx < arc.length - 1) {
    const target = arc[idx + 1]
    actions.push({
      kind: 'advance',
      label: `${labelForStatus(target)} →`,
      targetStatus: target,
      allowSubmitClose: recordType === 'task' && target !== 'closed',
    })
  }

  return actions
}

/** True when a record is considered "checked out" for primary-action
 *  purposes -- active_agent_session is the authoritative live signal;
 *  checkout_state is a secondary fallback for records the corpus/detail
 *  fetch didn't populate active_agent_session on. */
export function isCheckedOut(record: {
  active_agent_session?: boolean
  checkout_state?: string
}): boolean {
  return Boolean(record.active_agent_session) || record.checkout_state === 'checked_out'
}
