/**
 * Session record fetch (ENC-TSK-L35 — B67 PWA2.0 session detail page).
 *
 * Sessions are not project-scoped and are not tracker/document records, so
 * they deliberately bypass src/sync/readThrough.ts (the tier-2 offline cache
 * engine keys on project_id + record_id, and the corpus/delta sync feeds are
 * scoped to the six tracker RecordType shapes). This fetches straight from
 * the new GET /api/v1/coordination/agents/sessions/{id} endpoint
 * (ENC-TSK-L35 backend addition — there was previously no single-session
 * read, only the unfiltered/status-filtered list) via client.ts's
 * `requestJson`-equivalent conventions (credentials include, no-store cache,
 * 401 -> SessionExpiredError, 404 -> NotFoundError).
 */

import { queryOptions } from '@tanstack/react-query'
import { API_BASE, NotFoundError, SessionExpiredError } from './client'
import type { Session } from '../types/session'

type FetchInit = { signal?: AbortSignal; headers?: HeadersInit }

function withDefaultHeaders(input: HeadersInit | undefined): Headers {
  const headers = new Headers(input)
  if (!headers.has('accept')) headers.set('accept', 'application/json')
  if (!headers.has('x-requested-with')) headers.set('x-requested-with', 'XMLHttpRequest')
  return headers
}

/**
 * GET /api/v1/coordination/agents/sessions/{sessionId}. Backend envelopes as
 * `{ session: T }` (matching the tracker `{ record: T }` / document
 * `{ document: T }` envelope convention in client.ts).
 */
export async function fetchSessionRecord(
  sessionId: string,
  init?: FetchInit,
): Promise<Session> {
  const url = `${API_BASE}/coordination/agents/sessions/${encodeURIComponent(sessionId)}`
  const res = await fetch(url, {
    signal: init?.signal,
    headers: withDefaultHeaders(init?.headers),
    credentials: 'include',
    cache: 'no-store',
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (res.status === 404) throw new NotFoundError(`Not found: ${url}`)
  if (!res.ok) throw new Error(`Request failed (${res.status}): ${url}`)
  const body = (await res.json()) as { session?: Session } & Record<string, unknown>
  return (body.session ?? (body as unknown)) as Session
}

export const sessionKeys = {
  all: ['session'] as const,
  detail: (sessionId: string) => ['session', sessionId] as const,
}

export const sessionQueryOptions = (sessionId: string) =>
  queryOptions({
    queryKey: sessionKeys.detail(sessionId),
    queryFn: ({ signal }: { signal?: AbortSignal }) =>
      fetchSessionRecord(sessionId, { signal }),
  })

/** Builds a concrete href for a session detail page, e.g. sessionHref('ENC-SES-0A1') -> '/session/ENC-SES-0A1'. */
export function sessionHref(sessionId: string): string {
  return `/session/${encodeURIComponent(sessionId)}`
}
