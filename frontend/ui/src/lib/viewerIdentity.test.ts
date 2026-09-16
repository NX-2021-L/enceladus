import { afterEach, describe, expect, it } from 'vitest'
import { getViewingUserSub } from './viewerIdentity'

function setCookie(value: string) {
  document.cookie = value
}

function clearCookies() {
  document.cookie = 'enceladus_viewer_sub=; Path=/; Max-Age=0'
}

describe('getViewingUserSub', () => {
  afterEach(() => {
    clearCookies()
  })

  it('returns the sentinel when no identity cookie is set', () => {
    expect(getViewingUserSub()).toBe('unknown')
  })

  it('reads a forward-compatible identity cookie when present', () => {
    setCookie('enceladus_viewer_sub=cognito-sub-123; Path=/')
    expect(getViewingUserSub()).toBe('cognito-sub-123')
  })

  it('URL-decodes the cookie value', () => {
    setCookie(`enceladus_viewer_sub=${encodeURIComponent('sub with spaces')}; Path=/`)
    expect(getViewingUserSub()).toBe('sub with spaces')
  })
})
