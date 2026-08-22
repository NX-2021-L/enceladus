/**
 * projectUpdate.test.ts — ENC-FTR-131 / ENC-TSK-N89
 *
 * Covers getProject and updateProject: the PATCH request shape, the 401 refresh-retry
 * cycle inherited from createProject, and error surfacing.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getProject, updateProject, ProjectServiceError } from './projects'

vi.mock('./auth', () => ({
  refreshCredentials: vi.fn(),
}))

import { refreshCredentials } from './auth'

const mockRefresh = vi.mocked(refreshCredentials)

const projectBody = {
  success: true,
  project: {
    project_id: 'finance',
    prefix: 'FIN',
    summary: 'Project to manage my finances.',
    status: 'development',
    created_at: '2026-04-02T00:36:20Z',
    updated_at: '2026-04-02T00:36:20Z',
  },
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('getProject', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    fetchMock.mockReset()
    mockRefresh.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => vi.unstubAllGlobals())

  it('fetches a single project by name', async () => {
    fetchMock.mockResolvedValue(jsonResponse(projectBody))
    const res = await getProject('finance')
    expect(res.project.project_id).toBe('finance')
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toContain('/projects/finance')
    expect(init.method).toBe('GET')
    expect(init.credentials).toBe('include')
  })

  it('encodes the project name into the path', async () => {
    fetchMock.mockResolvedValue(jsonResponse(projectBody))
    await getProject('weird name/../x')
    const [url] = fetchMock.mock.calls[0]
    expect(url).not.toContain('../')
    expect(url).toContain(encodeURIComponent('weird name/../x'))
  })

  it('surfaces a 404 as ProjectServiceError', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ error: "Project 'nope' not found" }, 404))
    await expect(getProject('nope')).rejects.toBeInstanceOf(ProjectServiceError)
  })
})

describe('updateProject', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    fetchMock.mockReset()
    mockRefresh.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => vi.unstubAllGlobals())

  it('issues a PATCH carrying exactly the supplied fields', async () => {
    fetchMock.mockResolvedValue(jsonResponse(projectBody))
    await updateProject('finance', { repo: 'https://github.com/NX-2021-L/finance' })

    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toContain('/projects/finance')
    expect(init.method).toBe('PATCH')
    expect(JSON.parse(init.body)).toEqual({
      repo: 'https://github.com/NX-2021-L/finance',
    })
  })

  it('sends an empty-string repo through as the clear sentinel', async () => {
    fetchMock.mockResolvedValue(jsonResponse(projectBody))
    await updateProject('finance', { repo: '' })
    const [, init] = fetchMock.mock.calls[0]
    expect(JSON.parse(init.body)).toEqual({ repo: '' })
  })

  it('retries with credential refresh on 401 and succeeds', async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ error: 'Token expired' }, 401))
      .mockResolvedValueOnce(jsonResponse(projectBody))
    mockRefresh.mockResolvedValue(true)

    const res = await updateProject('finance', { summary: 'x' })
    expect(res.success).toBe(true)
    expect(mockRefresh).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('surfaces a 401 as an auth error once refresh keeps failing', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ error: 'Token expired' }, 401))
    mockRefresh.mockResolvedValue(false)

    await expect(updateProject('finance', { summary: 'x' })).rejects.toMatchObject({
      status: 401,
    })
  })

  it('surfaces the backend message on a 400 immutable-field rejection', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ error: 'immutable field(s) not editable: prefix' }, 400)
    )

    await expect(
      updateProject('finance', { summary: 'x' })
    ).rejects.toMatchObject({
      status: 400,
      message: 'immutable field(s) not editable: prefix',
    })
  })
})
