// DVP-TSK-974: recipes surface API wiring. The browser talks to the hub recipe primitive (not the docstore) through
// the @io-kit/recipes run client, and to the escalations gate API through @io-kit/gates, both with the session
// cookie. Handlers the kit builds (declared here so the parity generator sees them):
//   GET /api/v1/tracker/{project}/recipe/list
//   GET /api/v1/tracker/{project}/recipe/{id}
//   POST /api/v1/tracker/{project}/recipe-run
//   GET /api/v1/tracker/{project}/recipe-run/{id}
//   POST /api/v1/tracker/{project}/recipe-run/{id}/resume
//   POST /api/v1/tracker/{project}/recipe-run/{id}/cancel
import { createGateSource } from '@io-kit/gates'
import { createRunClient, httpTransport } from '@io-kit/recipes'
import type { RunClient } from '@io-kit/recipes'
import { API_BASE } from './client'

/** The kit appends /api/v1/...; the base is the origin (empty = same origin). */
function apiOrigin(): string {
  return /^https?:\/\//.test(API_BASE) ? new URL(API_BASE).origin : ''
}

export const cookieFetch: typeof fetch = (input, init) => fetch(input, { ...init, credentials: 'include' })

/** Live runs poll every 5s while running/awaiting_gate (the realtime namespace is deferred with DVP-TSK-928). */
export const RUN_POLL_MS = 5000

const clients = new Map<string, RunClient>()

/** One client per project for the life of the page, so subscribers keep a stable identity across renders. */
export function createRecipeClient(project: string): RunClient {
  const known = clients.get(project)
  if (known) return known
  const client = createRunClient({
    project,
    intervalMs: RUN_POLL_MS,
    call: httpTransport({ baseUrl: apiOrigin(), fetch: cookieFetch, headers: () => ({ 'x-requested-with': 'XMLHttpRequest' }) }),
  })
  clients.set(project, client)
  return client
}

let gateSource: ReturnType<typeof createGateSource> | undefined

/** Same cookie fetch as the escalations inbox; GateCardView/GateForm decide through it. */
export function createRecipeGateSource() {
  gateSource ??= createGateSource({ baseUrl: apiOrigin(), fetch: cookieFetch })
  return gateSource
}

export function newIdempotencyKey(): string {
  const id = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `ui-${id}`
}
