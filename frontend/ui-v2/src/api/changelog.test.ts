import { beforeEach, describe, expect, it, vi } from 'vitest'
import { SessionExpiredError } from './client'
import { ChangelogFetchError, changelogKeys, fetchChangelogHistory } from './changelog'

describe('fetchChangelogHistory', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  it('requests the multi-project history endpoint and unwraps entries', async () => {
    const entries = [
      {
        project_id: 'enceladus',
        spec_id: 'ENC-2026.07.01-1',
        version: '4.12.0',
        previous_version: '4.11.0',
        change_type: 'minor' as const,
        release_summary: 'Changelog page',
        changes: ['Added changelog page'],
        deployed_at: '2026-07-01T12:00:00Z',
        related_record_ids: ['ENC-TSK-L33'],
      },
    ]
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ entries, count: 1 }), { status: 200 }),
    )

    const result = await fetchChangelogHistory(['enceladus', 'other-program'])

    expect(fetch).toHaveBeenCalledTimes(1)
    const [url, init] = vi.mocked(fetch).mock.calls[0]!
    expect(String(url)).toContain('/changelog/history?projects=enceladus%2Cother-program')
    expect(init).toMatchObject({ credentials: 'include', cache: 'no-store' })
    expect(result).toEqual(entries)
  })

  it('defaults to an empty array when entries is missing', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({}), { status: 200 }))
    const result = await fetchChangelogHistory(['enceladus'])
    expect(result).toEqual([])
  })

  it('throws SessionExpiredError on 401', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 401 }))
    await expect(fetchChangelogHistory(['enceladus'])).rejects.toBeInstanceOf(SessionExpiredError)
  })

  it('throws ChangelogFetchError on non-ok, non-401 responses', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 500 }))
    await expect(fetchChangelogHistory(['enceladus'])).rejects.toBeInstanceOf(ChangelogFetchError)
  })
})

describe('changelogKeys.history', () => {
  it('sorts project ids so key identity is order-independent', () => {
    expect(changelogKeys.history(['b', 'a'])).toEqual(changelogKeys.history(['a', 'b']))
  })
})
