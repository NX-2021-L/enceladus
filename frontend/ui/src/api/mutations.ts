/**
 * mutations.ts — PWA write API for the project tracker.
 *
 * Sends PATCH requests to /api/v1/tracker/{projectId}/{recordType}/{recordId}
 * authenticated via the enceladus_id_token cookie (credentials: 'include').
 *
 * On 401 or timeout, automatically attempts credential refresh and retries
 * up to 3 cycles. After all cycles exhausted, throws MutationRetryExhaustedError
 * with full debug details (URL, payload, attempt log).
 */

import { refreshCredentials } from './auth'

const BASE = import.meta.env.VITE_MUTATION_BASE_URL ?? '/api/v1/tracker'

export interface MutationResult {
  success: boolean
  action: 'close' | 'note' | 'reopen'
  record_id: string
  updated_at: string
  updated_status?: string
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

export interface MutationAttempt {
  cycle: number
  url: string
  error: string
  timestamp: string
}

/**
 * Thrown after all retry cycles are exhausted. Carries full debug context
 * so the UI can display actionable error information.
 */
export class MutationRetryExhaustedError extends Error {
  readonly url: string
  readonly payload: object
  readonly attempts: MutationAttempt[]

  constructor(url: string, payload: object, attempts: MutationAttempt[], reason: string) {
    const summary = `Failed after ${attempts.length} attempt(s): ${reason}`
    super(summary)
    this.name = 'MutationRetryExhaustedError'
    this.url = url
    this.payload = payload
    this.attempts = attempts
  }

  /** Human-readable debug string for display in the UI */
  toDebugString(): string {
    const lines = [
      `Failed after ${this.attempts.length} attempt(s).`,
      `URL: ${this.url}`,
      `Payload: ${JSON.stringify(this.payload)}`,
      '',
      ...this.attempts.map(
        (a) => `[${a.cycle}] ${a.timestamp} — ${a.error}`
      ),
    ]
    return lines.join('\n')
  }
}

export function isMutationRetryExhaustedError(
  error: unknown
): error is MutationRetryExhaustedError {
  return error instanceof MutationRetryExhaustedError
}

// ---------------------------------------------------------------------------
// Retry-aware mutation
// ---------------------------------------------------------------------------

const MAX_CYCLES = 3
const CYCLE_TIMEOUT_MS = 10_000

async function mutateWithRetry(
  projectId: string,
  recordType: 'task' | 'issue' | 'feature',
  recordId: string,
  body: { action: 'close' | 'note' | 'reopen'; note?: string },
): Promise<MutationResult> {
  const url = `${BASE}/${projectId}/${recordType}/${recordId}`
  const attempts: MutationAttempt[] = []

  for (let cycle = 1; cycle <= MAX_CYCLES; cycle++) {
    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), CYCLE_TIMEOUT_MS)

      const res = await fetch(url, {
        method: 'PATCH',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      })
      clearTimeout(timeout)

      if (res.status === 401) {
        const data = await res.json().catch(() => null)
        const errorText = (
          data &&
          typeof data === 'object' &&
          'error' in data &&
          typeof (data as { error?: unknown }).error === 'string' &&
          (data as { error: string }).error.trim()
        )
          ? `HTTP 401 — ${(data as { error: string }).error}`
          : 'HTTP 401 — Session expired'

        attempts.push({
          cycle,
          url,
          error: errorText,
          timestamp: new Date().toISOString(),
        })

        // Attempt credential refresh before next cycle
        const refreshed = await refreshCredentials()
        if (!refreshed && cycle === MAX_CYCLES) {
          throw new MutationRetryExhaustedError(
            url, body, attempts, 'Credential refresh failed'
          )
        }
        continue // retry with (possibly) refreshed credentials
      }

      // Parse response body
      const data = await res.json().catch(() => ({ error: `HTTP ${res.status}` }))

      if (!res.ok) {
        // Validation/client errors are not recoverable via credential refresh.
        if (res.status >= 400 && res.status < 500) {
          const message = data?.error ?? `HTTP ${res.status}`
          throw new Error(message)
        }

        attempts.push({
          cycle,
          url,
          error: data?.error ?? `HTTP ${res.status}`,
          timestamp: new Date().toISOString(),
        })
        if (cycle === MAX_CYCLES) {
          throw new MutationRetryExhaustedError(
            url, body, attempts, 'Server returned error'
          )
        }
        // Attempt refresh in case it's a transient auth issue
        await refreshCredentials()
        continue
      }

      // Success
      return data as MutationResult
    } catch (err) {
      if (err instanceof MutationRetryExhaustedError) throw err

      const errMsg = err instanceof Error
        ? (err.name === 'AbortError' ? 'Request timed out (10s)' : err.message)
        : String(err)

      attempts.push({
        cycle,
        url,
        error: errMsg,
        timestamp: new Date().toISOString(),
      })

      if (cycle === MAX_CYCLES) {
        throw new MutationRetryExhaustedError(
          url, body, attempts, 'All retry cycles exhausted'
        )
      }

      // Attempt credential refresh before next cycle
      await refreshCredentials()
    }
  }

  // Should not reach here, but satisfy TypeScript
  throw new MutationRetryExhaustedError(
    url, body, attempts, 'All retry cycles exhausted'
  )
}

// ---------------------------------------------------------------------------
// Public API (unchanged signatures)
// ---------------------------------------------------------------------------

export async function closeRecord(
  projectId: string,
  recordType: 'task' | 'issue' | 'feature',
  recordId: string,
): Promise<MutationResult> {
  return mutateWithRetry(projectId, recordType, recordId, { action: 'close' })
}

export async function submitNote(
  projectId: string,
  recordType: 'task' | 'issue' | 'feature',
  recordId: string,
  note: string,
): Promise<MutationResult> {
  return mutateWithRetry(projectId, recordType, recordId, { action: 'note', note })
}

export async function reopenRecord(
  projectId: string,
  recordType: 'task' | 'issue' | 'feature',
  recordId: string,
): Promise<MutationResult> {
  return mutateWithRetry(projectId, recordType, recordId, { action: 'reopen' })
}
