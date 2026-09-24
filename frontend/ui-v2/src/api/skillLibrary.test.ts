import { beforeEach, describe, expect, it, vi } from 'vitest'
import { SessionExpiredError } from './client'
import { fetchSkillLibrary, isTestSkillRecord, skillLibraryKeys } from './skillLibrary'

const SKILL_DOCS = [
  {
    document_id: 'DOC-89D35679FE91',
    title: 'enceladus-agent-webui-alpha',
    description: 'Governed Web UI agent skill.',
    version: '7',
    updated_at: '2026-07-05T11:07:03Z',
    runtime_hint: 'claude,agentskills',
    document_subtype: 'skill',
  },
  {
    document_id: 'DOC-82D57A4FE6DC',
    title: 'E2E skill — FTR-078 phase-8 seed (cross-platform portable)',
    description: '',
    version: '0.1.0',
    updated_at: '2026-04-19T01:49:27Z',
    runtime_hint: 'claude,agentskills',
    document_subtype: 'skill',
  },
]

describe('fetchSkillLibrary', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  it('requests the body-excluded skill projection and unwraps documents', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ documents: SKILL_DOCS, count: 2, total_matches: 2 }), {
        status: 200,
      }),
    )

    const result = await fetchSkillLibrary('enceladus')

    expect(fetch).toHaveBeenCalledTimes(1)
    const [url, init] = vi.mocked(fetch).mock.calls[0]!
    expect(String(url)).toContain('/documents?')
    expect(String(url)).toContain('project=enceladus')
    expect(String(url)).toContain('document_subtype=skill')
    expect(String(url)).toContain('include_content=false')
    expect(init).toMatchObject({ credentials: 'include', cache: 'no-store' })

    // AC-4: the ftr-078-e2e-skill test fixture is excluded by default.
    expect(result).toHaveLength(1)
    expect(result[0]!.document_id).toBe('DOC-89D35679FE91')
  })

  it('defaults to an empty array when documents is missing', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({}), { status: 200 }))
    const result = await fetchSkillLibrary('enceladus')
    expect(result).toEqual([])
  })

  it('throws SessionExpiredError on 401', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 401 }))
    await expect(fetchSkillLibrary('enceladus')).rejects.toBeInstanceOf(SessionExpiredError)
  })

  it('throws on non-ok, non-401 responses', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 500 }))
    await expect(fetchSkillLibrary('enceladus')).rejects.toThrow('Failed to fetch skill library (500)')
  })
})

describe('isTestSkillRecord', () => {
  it('flags the known ftr-078-e2e-skill fixture', () => {
    expect(isTestSkillRecord({ document_id: 'DOC-82D57A4FE6DC' })).toBe(true)
  })

  it('does not flag ordinary skill records', () => {
    expect(isTestSkillRecord({ document_id: 'DOC-89D35679FE91' })).toBe(false)
  })
})

describe('skillLibraryKeys.list', () => {
  it('is a stable per-project query key', () => {
    expect(skillLibraryKeys.list('enceladus')).toEqual(['skill-library', 'enceladus'])
  })
})
