/**
 * Approval queue contract (ENC-TSK-S84, ENC-PLN-107). Written so DVP-TSK-L94 can move this module
 * into io-kit unchanged: no imports from the app, only React and the adapter the app supplies.
 */
export type Verdict = 'approve' | 'reject'

/** Thrown by an adapter's decide() for a decision the server refused. 412 may carry the refreshed item. */
export class ApprovalDecisionError<T> extends Error {
  readonly status: number
  readonly refreshed?: T
  constructor(status: number, message: string, refreshed?: T) {
    super(message)
    this.name = 'ApprovalDecisionError'
    this.status = status
    this.refreshed = refreshed
  }
}

export interface ApprovalAdapter<T, P = unknown, O = unknown> {
  list(): Promise<T[]>
  key(item: T): string
  version(item: T): string | number
  /** Resolves with an outcome (for example the minted ID); throws ApprovalDecisionError on refusal. */
  decide(item: T, verdict: Verdict, payload: P): Promise<O>
}

export type DecisionState = 'running' | 'ok' | 'conflict' | 'error'

export interface DecisionResult<O = unknown> {
  key: string
  verdict: Verdict
  state: DecisionState
  status?: number
  message?: string
  outcome?: O
}
