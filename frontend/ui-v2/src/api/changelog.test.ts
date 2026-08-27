import { beforeEach, describe, expect, it, vi } from 'vitest'
import { SessionExpiredError } from './client'
import {
  ChangelogFetchError,
  changelogKeys,
  chunkProjectIds,
  fetchChangelogHistory,
  MAX_PROJECTS_PER_REQUEST,
} from './changelog'

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

describe('changelog chunking (ENC-TSK-P62 / ENC-ISS-716)', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  function entry(projectId: string, deployedAt: string) {
    return {
      project_id: projectId,
      spec_id: `${projectId}-spec`,
      version: '1.0.0',
      previous_version: '0.9.0',
      change_type: 'minor' as const,
      release_summary: 'x',
      changes: [],
      deployed_at: deployedAt,
      related_record_ids: [],
    }
  }

  it('chunkProjectIds splits at the API cap', () => {
    const ids = Array.from({ length: 26 }, (_, i) => `p${i}`)
    const chunks = chunkProjectIds(ids)
    expect(chunks).toHaveLength(2)
    expect(chunks[0]).toHaveLength(MAX_PROJECTS_PER_REQUEST)
    expect(chunks[1]).toHaveLength(6)
    expect(chunks.flat()).toEqual(ids)
  })

  it('26 projects issue two requests, each within the cap, merged sorted by deploy time', async () => {
    const ids = Array.from({ length: 26 }, (_, i) => `p${String(i).padStart(2, '0')}`)
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = new URL(String(input), 'https://x')
      const projects = (url.searchParams.get('projects') ?? '').split(',')
      expect(projects.length).toBeLessThanOrEqual(MAX_PROJECTS_PER_REQUEST)
      const body =
        projects[0] === 'p00'
          ? { entries: [entry('p00', '2026-08-01T00:00:00Z')] }
          : { entries: [entry('p20', '2026-08-26T00:00:00Z')] }
      return new Response(JSON.stringify(body), { status: 200 })
    })

    const result = await fetchChangelogHistory(ids)
    expect(fetch).toHaveBeenCalledTimes(2)
    expect(result.map((e) => e.project_id)).toEqual(['p20', 'p00'])
  })

  it('a failing chunk fails the whole fetch (no silent partial history)', async () => {
    const ids = Array.from({ length: 21 }, (_, i) => `p${i}`)
    vi.mocked(fetch)
      .mockResolvedValueOnce(new Response(JSON.stringify({ entries: [] }), { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 500 }))
    await expect(fetchChangelogHistory(ids)).rejects.toBeInstanceOf(ChangelogFetchError)
  })
})
