import { afterEach, describe, expect, it, vi } from 'vitest'

/**
 * DVP-TSK-B24: the PWA logs in on the managed-login v2 custom domain and adds
 * passkeys there; the classic prefix domain stays MCP-only.
 * DVP-TSK-B28: Add a passkey runs authorize prompt=login with a passkey-intent
 * state; auth_refresh continues to /passkeys/add after the code exchange.
 */
const CUSTOM = 'https://auth.enceladus.jreese.net'
const PREFIX = 'enceladus-status-356364570033.auth.us-east-1.amazoncognito.com'
const CLIENT = '6q607dk3liirhtecgps7hifmlk'

async function load() {
  vi.resetModules()
  return import('./authConfig')
}

afterEach(() => {
  vi.unstubAllEnvs()
  window.history.replaceState({}, '', '/')
})

describe('authConfig (managed-login v2 custom domain)', () => {
  it('builds the login URL on the custom domain, not the prefix domain', async () => {
    window.history.replaceState({}, '', '/projects?x=1')
    const { buildLoginUrl } = await load()
    const url = new URL(buildLoginUrl())
    expect(`${url.protocol}//${url.host}`).toBe(CUSTOM)
    expect(url.pathname).toBe('/oauth2/authorize')
    expect(url.searchParams.get('client_id')).toBe(CLIENT)
    expect(url.searchParams.get('response_type')).toBe('code')
    // ENC-TSK-Q84: passkey list/delete need the user-admin scope
    expect(url.searchParams.get('scope')).toBe('openid email profile aws.cognito.signin.user.admin')
    expect(buildLoginUrl()).not.toContain(PREFIX)
  })

  it('builds the add-passkey URL as a fresh-login authorize URL with a passkey-intent state', async () => {
    window.history.replaceState({}, '', '/projects?x=1')
    const { buildAddPasskeyUrl, buildLoginUrl, PASSKEY_ADD_STATE_PATH } = await load()
    const url = new URL(buildAddPasskeyUrl())
    const login = new URL(buildLoginUrl())
    expect(`${url.protocol}//${url.host}`).toBe(CUSTOM)
    expect(url.pathname).toBe('/oauth2/authorize')
    expect(url.searchParams.get('prompt')).toBe('login')
    expect(url.searchParams.get('client_id')).toBe(CLIENT)
    expect(url.searchParams.get('response_type')).toBe('code')
    for (const key of ['redirect_uri', 'scope', 'client_id', 'response_type']) {
      expect(url.searchParams.get(key)).toBe(login.searchParams.get(key))
    }
    expect([...url.searchParams.keys()].sort()).toEqual(
      ['client_id', 'prompt', 'redirect_uri', 'response_type', 'scope', 'state'],
    )
    // state is the FIXED marker (not the current path), base64url without padding
    const state = url.searchParams.get('state') as string
    expect(state).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(state).toBe(btoa('/__passkey_add__').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''))
    expect(atob(state.replace(/-/g, '+').replace(/_/g, '/'))).toBe('/__passkey_add__')
    expect(PASSKEY_ADD_STATE_PATH).toBe('/__passkey_add__')
    expect(buildAddPasskeyUrl()).not.toContain(PREFIX)
    expect(buildAddPasskeyUrl()).not.toContain('/passkeys/add')
  })

  it('leaves the login URL without prompt=login and with the current path as state', async () => {
    window.history.replaceState({}, '', '/projects?x=1')
    const { buildLoginUrl } = await load()
    const url = new URL(buildLoginUrl())
    expect(url.searchParams.has('prompt')).toBe(false)
    expect(atob(url.searchParams.get('state') as string)).toBe('/projects?x=1')
  })

  it('honours VITE_COGNITO_HOSTED_UI_DOMAIN and VITE_OAUTH_REDIRECT_URI overrides', async () => {
    vi.stubEnv('VITE_COGNITO_HOSTED_UI_DOMAIN', 'https://auth.example.test')
    vi.stubEnv('VITE_OAUTH_REDIRECT_URI', 'https://enceladus.jreese.net/api/v1/auth/callback')
    const { buildAddPasskeyUrl, buildLoginUrl } = await load()
    const add = new URL(buildAddPasskeyUrl())
    expect(add.origin).toBe('https://auth.example.test')
    expect(add.pathname).toBe('/oauth2/authorize')
    expect(add.searchParams.get('redirect_uri')).toBe('https://enceladus.jreese.net/api/v1/auth/callback')
    expect(new URL(buildLoginUrl()).origin).toBe('https://auth.example.test')
  })

  it('redirectToAddPasskey navigates the window to the add-passkey URL', async () => {
    const assign = vi.fn()
    const original = window.location
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...original, assign, pathname: '/', search: '' },
    })
    try {
      const { redirectToAddPasskey, buildAddPasskeyUrl } = await load()
      redirectToAddPasskey()
      expect(assign).toHaveBeenCalledWith(buildAddPasskeyUrl())
    } finally {
      Object.defineProperty(window, 'location', { configurable: true, value: original })
    }
  })
})
