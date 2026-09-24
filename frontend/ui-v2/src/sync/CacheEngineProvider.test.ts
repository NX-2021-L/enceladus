import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { seedCacheFromCorpus } from './corpusSeed'
import { seedCacheFromCorpusWithRetry } from './CacheEngineProvider'

/**
 * ENC-TSK-M36 (feed data-truth) -- seedCacheFromCorpusWithRetry. Before this,
 * CacheEngineProvider called seedCacheFromCorpus() exactly once on mount; any
 * single failure (the corpus endpoint is confirmed to take up to ~20s on a
 * cold Lambda cache, live on gamma) permanently stranded `isWarm` at false
 * for the whole session with no retry. These tests mock ./corpusSeed and use
 * fake timers so the retry backoff (1s, 3s) doesn't actually slow the suite.
 */
vi.mock('./corpusSeed', () => ({
  seedCacheFromCorpus: vi.fn(),
}))

describe('seedCacheFromCorpusWithRetry', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.mocked(seedCacheFromCorpus).mockReset()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('returns immediately on first-attempt success (no retry needed)', async () => {
    vi.mocked(seedCacheFromCorpus).mockResolvedValue({ pages: 1, records: 10, durationMs: 5 })

    const result = await seedCacheFromCorpusWithRetry()
    expect(result).toEqual({ pages: 1, records: 10, durationMs: 5 })
    expect(seedCacheFromCorpus).toHaveBeenCalledTimes(1)
  })

  it('retries after a transient failure and succeeds on the second attempt', async () => {
    vi.mocked(seedCacheFromCorpus)
      .mockRejectedValueOnce(new Error('network error'))
      .mockResolvedValueOnce({ pages: 2, records: 40, durationMs: 20000 })

    const promise = seedCacheFromCorpusWithRetry()
    await vi.runAllTimersAsync()
    const result = await promise

    expect(result.records).toBe(40)
    expect(seedCacheFromCorpus).toHaveBeenCalledTimes(2)
  })

  it('gives up after exhausting all retries and throws the last error', async () => {
    vi.mocked(seedCacheFromCorpus).mockRejectedValue(new Error('still failing'))

    const promise = seedCacheFromCorpusWithRetry()
    // Swallow the eventual rejection so it doesn't surface as an unhandled
    // rejection while the fake-timer flush below is still in flight.
    promise.catch(() => {})
    await vi.runAllTimersAsync()
    await expect(promise).rejects.toThrow('still failing')
    // Initial attempt + one retry per configured delay (2 delays -> 3 calls).
    expect(seedCacheFromCorpus).toHaveBeenCalledTimes(3)
  })
})
