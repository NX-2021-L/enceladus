// DVP-TSK-861 / ENC-ISS-546: mid-session expiry re-auths instead of dead-ending.
// Wraps fetch for same-origin /api/v1 calls: on a 401 it runs the kit refresh
// (locked, single-flight inside the client) and retries once. If refresh fails the
// kit calls onReauthRequired (redirect to sign-in) and the original 401 surfaces.
interface Refresher {
  refresh(): Promise<void>
}

const API_PREFIX = '/api/v1/'
const AUTH_PREFIX = '/api/v1/auth/'

function pathOf(input: RequestInfo | URL): string | null {
  try {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const u = new URL(raw, window.location.origin)
    return u.origin === window.location.origin ? u.pathname : null
  } catch {
    return null
  }
}

export function installReauthFetch(client: Refresher, base: typeof fetch = window.fetch.bind(window)): typeof fetch {
  const wrapped: typeof fetch = async (input, init) => {
    const res = await base(input, init)
    const path = pathOf(input)
    if (res.status !== 401 || !path || !path.startsWith(API_PREFIX) || path.startsWith(AUTH_PREFIX)) return res
    try {
      await client.refresh()
    } catch {
      return res
    }
    return base(input, init)
  }
  return wrapped
}
