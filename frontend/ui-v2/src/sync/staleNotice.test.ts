import { describe, expect, it } from 'vitest'
import { staleCorpusNotice } from './staleNotice'

describe('staleCorpusNotice (ENC-TSK-Q33 AC-4)', () => {
  const now = Date.parse('2026-10-08T05:00:00Z')

  it('is silent while the seed is healthy', () => {
    expect(staleCorpusNotice(null, '2026-10-08T04:00:00Z', now)).toBeNull()
  })

  it('names the error and the last successful refresh time', () => {
    const text = staleCorpusNotice('Request failed (502)', '2026-10-08T03:00:00Z', now)
    expect(text).toContain('last refreshed 2h ago (2026-10-08T03:00:00Z)')
    expect(text).toContain('The live refresh failed: Request failed (502).')
  })

  it('says so when this device never completed a refresh', () => {
    expect(staleCorpusNotice('offline', null, now)).toContain('never completed a live refresh')
  })
})
