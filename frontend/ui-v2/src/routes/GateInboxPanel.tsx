/**
 * DVP-TSK-970 (DVP-PLN-013 E4-W2.3): the all-projects inbox on @io-kit/gates.
 * DVP-TSK-A20: the chip-row card view is retired; this module keeps the shared kit plumbing
 * (gateFetch, humanSession, stepUpProvider, realtime nonce) the restored cockpit
 * (EscalationsCockpit.tsx) reads through.
 *
 * ONE inbox (ruling F-04): /escalations stays the only inbox route and the home
 * "Requires io" slot renders this same panel in compact form. Both read the
 * consolidated hub (GET /api/v1/coordination/escalations, DVP-TSK-967) through
 * the kit's createGateSource: project_id=* (all projects), kind/state filters,
 * ResolvedCall verbatim with diff and drift, and verdicts that carry If-Match
 * plus an Idempotency-Key (the kit does both; nothing here re-implements them).
 *
 * Auth. The kit's decide demands an injected interactive ID-token session. This
 * app holds its id token inside the @io-kit/auth client (cookie mode), so the
 * session handed to the kit carries a placeholder token and gateFetch drops that
 * placeholder Authorization header before auth.authFetch attaches the real
 * bearer (plus the HttpOnly cookie, credentials: 'include'). The backend, not
 * this file, remains the arbiter of the human-only gates.
 *
 * Step-up. Cards whose requiredAuth is step_up get the @io-kit/auth
 * cognito_max_age provider; until DVP-TSK-980 lands the server-side assurance
 * the hub treats interactive_human as sufficient and the slot stays dormant.
 *
 * Realtime. A live escalation record event (RealtimeFeedProvider, AppSync
 * namespace from DVP-TSK-928) bumps a nonce that swaps the source identity, which
 * makes the kit's useGateInbox refetch in place (card keys are stable, so an
 * open deny reason is not lost). A 412 card_changed from decide is handled inside
 * GateCardView (it re-renders the fresh card) and then refreshes the list.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import type { HumanSession } from '@io-kit/gates'
import type { StepUpProviderLike } from '@io-kit/gates/react'
import { COGNITO_MAX_AGE_METHOD } from '@io-kit/auth'
import { auth } from '../auth/authClient'
import { useRealtimeFeedEvents } from '../realtime/RealtimeFeedProvider'
import { useFeedBufferStore } from '../store/feedBufferStore'

const SESSION_PLACEHOLDER = 'session-held-by-auth-client'
const LIST_PATH = '/api/v1/coordination/escalations?'

/** Exported for tests: the fetch the kit source runs on. */
export async function gateFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  let url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
  const headers = new Headers(init?.headers)
  if (headers.get('Authorization') === `Bearer ${SESSION_PLACEHOLDER}`) headers.delete('Authorization')
  // tool_call / stale_lock cards are derived (opt-in on the hub); the kit does not send the flag.
  if ((init?.method ?? 'GET') === 'GET' && url.includes(LIST_PATH) && !url.includes('include_derived')) {
    url += '&include_derived=true'
  }
  // auth.authFetch resolves paths against its own '/api/v1' base, and the kit already sends
  // '/api/v1/coordination/...': strip the kit prefix so prod does not request
  // '/api/v1/api/v1/coordination/escalations' (404, found on prod 2026-10-12).
  url = url.replace(/^(https?:\/\/[^/]+)?\/api\/v1(?=\/)/, '')
  return auth.authFetch(url, { ...init, headers, credentials: 'include' })
}

export const humanSession = (): HumanSession | null =>
  auth.getSession().status === 'authenticated'
    ? { idToken: SESSION_PLACEHOLDER, tokenUse: 'id', interactive: true }
    : null

export const stepUpProvider: StepUpProviderLike = {
  method: COGNITO_MAX_AGE_METHOD,
  // DVP-TSK-B07: the edge round trip (GET /api/v1/auth/login) must bring the
  // user back to the escalation, so default returnTo to the current location.
  stepUp: (opts) =>
    auth.stepUp(COGNITO_MAX_AGE_METHOD, {
      ...opts,
      returnTo: opts?.returnTo ?? window.location.pathname + window.location.search,
    }),
}

const isEscalationEvent = (e: { record_type: string; recordId: string }) =>
  e.record_type.toLowerCase() === 'escalation' || /(^|-)ESC-/i.test(e.recordId)

/** Increments each time a newer escalation record event arrives (merged or still buffered). */
export function useEscalationRealtimeNonce(): number {
  const merged = useRealtimeFeedEvents()
  const buffered = useFeedBufferStore((s) => s.bufferedEvents)
  const latest = useMemo(() => {
    let max = 0
    for (const e of [...merged, ...buffered]) if (isEscalationEvent(e) && e.cursor > max) max = e.cursor
    return max
  }, [merged, buffered])
  const seen = useRef(latest)
  const [nonce, setNonce] = useState(0)
  useEffect(() => {
    if (latest !== seen.current) {
      seen.current = latest
      setNonce((n) => n + 1)
    }
  }, [latest])
  return nonce
}
