import { afterEach, describe, expect, it, vi } from 'vitest'
import { authedChannel, getAppSyncEventsConfig } from './appsyncConfig'

// DVP-TSK-928: the Cognito namespace is an opt-in build variable; garbage must never produce a channel path.
describe('getAppSyncEventsConfig authed namespace', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
  })

  function stubBase() {
    vi.stubEnv('VITE_APPSYNC_HTTP_HOST', 'https://abc.appsync-api.us-west-2.amazonaws.com/event')
    vi.stubEnv('VITE_APPSYNC_REALTIME_HOST', 'abc.appsync-realtime-api.us-west-2.amazonaws.com')
    vi.stubEnv('VITE_APPSYNC_API_KEY', 'da2-key')
  }

  it('is empty by default, leaving the API-key transport as the only path', () => {
    stubBase()
    vi.stubEnv('VITE_APPSYNC_AUTHED_NAMESPACE', '')
    const config = getAppSyncEventsConfig()
    expect(config.authedNamespace).toBe('')
    expect(config.enabled).toBe(true)
  })

  it('accepts a bare or slash-wrapped namespace name', () => {
    stubBase()
    vi.stubEnv('VITE_APPSYNC_AUTHED_NAMESPACE', ' /authed/ ')
    expect(getAppSyncEventsConfig().authedNamespace).toBe('authed')
  })

  it('rejects names AppSync would not accept instead of building a bad channel', () => {
    stubBase()
    for (const bad of ['a/b', 'has space', '-lead', 'trail-', 'dot.ted', 'x'.repeat(51)]) {
      vi.stubEnv('VITE_APPSYNC_AUTHED_NAMESPACE', bad)
      expect(getAppSyncEventsConfig().authedNamespace).toBe('')
    }
  })

  it('enables realtime on a Cognito namespace alone, with no API key (production)', () => {
    vi.stubEnv('VITE_APPSYNC_HTTP_HOST', 'abc.appsync-api.us-west-2.amazonaws.com')
    vi.stubEnv('VITE_APPSYNC_REALTIME_HOST', 'abc.appsync-realtime-api.us-west-2.amazonaws.com')
    vi.stubEnv('VITE_APPSYNC_API_KEY', '')
    vi.stubEnv('VITE_APPSYNC_AUTHED_NAMESPACE', 'authed')
    const config = getAppSyncEventsConfig()
    expect(config.enabled).toBe(true)
    expect(config.apiKey).toBe('')
  })

  it('stays disabled with neither an API key nor a Cognito namespace', () => {
    vi.stubEnv('VITE_APPSYNC_HTTP_HOST', 'abc.appsync-api.us-west-2.amazonaws.com')
    vi.stubEnv('VITE_APPSYNC_REALTIME_HOST', 'abc.appsync-realtime-api.us-west-2.amazonaws.com')
    vi.stubEnv('VITE_APPSYNC_API_KEY', '')
    vi.stubEnv('VITE_APPSYNC_AUTHED_NAMESPACE', '')
    expect(getAppSyncEventsConfig().enabled).toBe(false)
  })

  it('prefixes channel paths with the namespace', () => {
    expect(authedChannel('authed', '/feed/updates')).toBe('/authed/feed/updates')
    expect(authedChannel('authed', 'records/X')).toBe('/authed/records/X')
  })
})
