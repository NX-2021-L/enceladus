import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  createProject,
  fetchProjectsList,
  ProjectCreateError,
  validatePrefix,
  validateProjectId,
  validateRepo,
  validateSummary,
} from './projects'
import { SessionExpiredError } from './client'

describe('validateProjectId', () => {
  it('accepts a lowercase slug', () => {
    expect(validateProjectId('my-project')).toEqual({ valid: true })
  })
  it('rejects empty input', () => {
    expect(validateProjectId('  ').valid).toBe(false)
  })
  it('rejects uppercase / leading digit', () => {
    expect(validateProjectId('1abc').valid).toBe(false)
    expect(validateProjectId('ABC').valid).toBe(false)
  })
})

describe('validatePrefix', () => {
  it('accepts exactly 3 uppercase letters', () => {
    expect(validatePrefix('ENC')).toEqual({ valid: true })
  })
  it('rejects wrong length', () => {
    expect(validatePrefix('EN').valid).toBe(false)
    expect(validatePrefix('ENCX').valid).toBe(false)
  })
  it('is case-insensitive (normalizes before checking, like the backend)', () => {
    expect(validatePrefix('enc')).toEqual({ valid: true })
  })
})

describe('validateSummary', () => {
  it('requires non-empty text', () => {
    expect(validateSummary('').valid).toBe(false)
  })
  it('rejects text over 500 chars', () => {
    expect(validateSummary('a'.repeat(501)).valid).toBe(false)
  })
  it('accepts a normal summary', () => {
    expect(validateSummary('A project').valid).toBe(true)
  })
})

describe('validateRepo', () => {
  it('treats blank as valid (optional field)', () => {
    expect(validateRepo('')).toEqual({ valid: true })
  })
  it('accepts a well-formed URL', () => {
    expect(validateRepo('https://github.com/org/repo')).toEqual({ valid: true })
  })
  it('rejects a malformed URL', () => {
    expect(validateRepo('not a url').valid).toBe(false)
  })
})

describe('fetchProjectsList', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('returns the projects array from a successful response', async () => {
    vi.mocked(fetch).mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({ success: true, projects: [{ project_id: 'enceladus', prefix: 'ENC' }], count: 1 }),
    } as Response)

    const projects = await fetchProjectsList()
    expect(projects).toEqual([{ project_id: 'enceladus', prefix: 'ENC' }])
  })

  it('throws SessionExpiredError on 401', async () => {
    vi.mocked(fetch).mockResolvedValue({ status: 401, ok: false, json: async () => ({}) } as Response)
    await expect(fetchProjectsList()).rejects.toBeInstanceOf(SessionExpiredError)
  })
})

describe('createProject', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('posts to /projects and returns the created project on success', async () => {
    vi.mocked(fetch).mockResolvedValue({
      status: 201,
      ok: true,
      json: async () => ({
        success: true,
        project: { project_id: 'new-proj', prefix: 'NEW', summary: 'x', status: 'planning' },
        initialization: { projects_table: 'created' },
      }),
    } as Response)

    const result = await createProject({
      name: 'new-proj',
      prefix: 'NEW',
      summary: 'x',
      status: 'planning',
    })

    expect(result.project.project_id).toBe('new-proj')
    const [, init] = vi.mocked(fetch).mock.calls[0]!
    expect(init?.method).toBe('POST')
  })

  it('throws ProjectCreateError with server message on 409 conflict', async () => {
    vi.mocked(fetch).mockResolvedValue({
      status: 409,
      ok: false,
      json: async () => ({ error: "Project 'new-proj' already exists" }),
    } as Response)

    await expect(createProject({ name: 'new-proj', prefix: 'NEW', summary: 'x', status: 'planning' })).rejects.toMatchObject(
      { status: 409 } satisfies Partial<ProjectCreateError>,
    )
  })

  it('throws SessionExpiredError on 401', async () => {
    vi.mocked(fetch).mockResolvedValue({ status: 401, ok: false, json: async () => ({}) } as Response)
    await expect(
      createProject({ name: 'new-proj', prefix: 'NEW', summary: 'x', status: 'planning' }),
    ).rejects.toBeInstanceOf(SessionExpiredError)
  })
})
