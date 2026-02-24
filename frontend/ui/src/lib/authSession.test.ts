import { describe, expect, it } from 'vitest'
import { SessionExpiredError, isSessionExpiredError } from './authSession'

describe('authSession', () => {
  it('constructs SessionExpiredError with default values', () => {
    const err = new SessionExpiredError()
    expect(err.name).toBe('SessionExpiredError')
    expect(err.message).toBe('Session expired')
    expect(err.status).toBe(401)
  })

  it('constructs SessionExpiredError with custom values', () => {
    const err = new SessionExpiredError('Token expired', 403)
    expect(err.message).toBe('Token expired')
    expect(err.status).toBe(403)
  })

  it('detects SessionExpiredError instances', () => {
    expect(isSessionExpiredError(new SessionExpiredError())).toBe(true)
    expect(isSessionExpiredError(new Error('x'))).toBe(false)
    expect(isSessionExpiredError({})).toBe(false)
  })
})
