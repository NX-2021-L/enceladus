import { SessionExpiredError } from '../lib/authSession'
const BASE_URL = import.meta.env.VITE_FEED_BASE_URL || '/mobile/v1'

type FetchTarget = Parameters<typeof fetch>[0]
type FetchOptions = Parameters<typeof fetch>[1]

function withDefaultHeaders(input: HeadersInit | undefined): Headers {
  const headers = new Headers(input)
  if (!headers.has('accept')) headers.set('accept', 'application/json')
  if (!headers.has('x-requested-with')) headers.set('x-requested-with', 'XMLHttpRequest')
  return headers
}

export async function fetchWithAuth(input: FetchTarget, init?: FetchOptions): Promise<Response> {
  const res = await fetch(input, {
    ...init,
    headers: withDefaultHeaders(init?.headers),
    credentials: 'include',
    cache: 'no-store',
  })
  if (res.status === 401) throw new SessionExpiredError()
  return res
}

export async function fetchFeed<T>(feedName: string): Promise<T> {
  const url = `${BASE_URL}/${feedName}.json`
  // credentials:'include' ensures the enceladus_id_token cookie (SameSite=None)
  // is sent with the fetch request so Lambda@Edge can authenticate it.
  const res = await fetchWithAuth(url)
  if (!res.ok) throw new Error(`Failed to fetch ${feedName}: ${res.status}`)
  return res.json()
}

export async function probeSession(): Promise<void> {
  const url = `${BASE_URL}/projects.json?auth_probe=${Date.now()}`
  const res = await fetchWithAuth(url)
  if (!res.ok) throw new Error(`Session probe failed: ${res.status}`)
}
