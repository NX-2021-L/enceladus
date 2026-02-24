/**
 * projects.test.ts — Regression tests for createProject auth retry behavior
 *
 * Covers ENC-ISS-042: "New project setup shows session-expired error immediately
 * after login". Validates that createProject() retries with credential refresh
 * on 401, matching the pattern in mutations.ts.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createProject, ProjectServiceError } from './projects'

// Mock the auth module's refreshCredentials
vi.mock('./auth', () => ({
  refreshCredentials: vi.fn(),
}))

import { refreshCredentials } from './auth'

const mockRefresh = vi.mocked(refreshCredentials)

describe('createProject', () => {
  const fetchMock = vi.fn()
  const validPayload = {
    name: 'test-project',
    prefix: 'TST',
    summary: 'A test project',
    status: 'development',
  }

  const successBody = {
    success: true,
    project: {
      project_id: 'test-project',
      prefix: 'TST',
      summary: 'A test project',
      status: 'development',
      created_at: '2026-02-24T00:00:00Z',
      updated_at: '2026-02-24T00:00:00Z',
      created_by: 'test-user',
    },
    initialization: {},
  }

  beforeEach(() => {
    fetchMock.mockReset()
    mockRefresh.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  // -----------------------------------------------------------------------
  // Happy path
  // -----------------------------------------------------------------------

  it('creates project successfully on first attempt', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify(successBody), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const result = await createProject(validPayload)
    expect(result.success).toBe(true)
    expect(result.project.project_id).toBe('test-project')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(mockRefresh).not.toHaveBeenCalled()
  })

  // -----------------------------------------------------------------------
  // 401 retry with successful refresh (ENC-ISS-042 fix validation)
  // -----------------------------------------------------------------------

  it('retries with credential refresh on 401 and succeeds', async () => {
    // First call: 401 (token expired)
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'Token expired' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    // Refresh succeeds
    mockRefresh.mockResolvedValueOnce(true)
    // Second call: success
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(successBody), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const result = await createProject(validPayload)
    expect(result.success).toBe(true)
    expect(result.project.project_id).toBe('test-project')
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(mockRefresh).toHaveBeenCalledTimes(1)
  })

  it('retries multiple times on repeated 401s and eventually succeeds', async () => {
    // First call: 401
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'Token expired' }), { status: 401 }),
    )
    mockRefresh.mockResolvedValueOnce(true)
    // Second call: still 401
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'Token expired' }), { status: 401 }),
    )
    mockRefresh.mockResolvedValueOnce(true)
    // Third call: success
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(successBody), { status: 200 }),
    )

    const result = await createProject(validPayload)
    expect(result.success).toBe(true)
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(mockRefresh).toHaveBeenCalledTimes(2)
  })

  // -----------------------------------------------------------------------
  // 401 with failed refresh — surfaces auth error
  // -----------------------------------------------------------------------

  it('throws 401 ProjectServiceError when refresh fails on first 401', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'Token expired' }), { status: 401 }),
    )
    mockRefresh.mockResolvedValue(false)

    await expect(createProject(validPayload)).rejects.toThrow(ProjectServiceError)
    try {
      await createProject(validPayload)
    } catch (e) {
      expect(e).toBeInstanceOf(ProjectServiceError)
      expect((e as ProjectServiceError).status).toBe(401)
      expect((e as ProjectServiceError).message).toContain('session has expired')
    }
  })

  it('throws 401 after all 3 cycles exhausted with persistent 401', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'Token expired' }), { status: 401 }),
    )
    // Refresh succeeds but token stays expired server-side
    mockRefresh.mockResolvedValue(true)

    await expect(createProject(validPayload)).rejects.toThrow(ProjectServiceError)
  })

  // -----------------------------------------------------------------------
  // Non-auth errors are NOT retried
  // -----------------------------------------------------------------------

  it('does not retry on 409 conflict', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'Project already exists' }), {
        status: 409,
      }),
    )

    await expect(createProject(validPayload)).rejects.toThrow(ProjectServiceError)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(mockRefresh).not.toHaveBeenCalled()
  })

  it('does not retry on 400 validation error', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'Invalid prefix' }), { status: 400 }),
    )

    await expect(createProject(validPayload)).rejects.toThrow(ProjectServiceError)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(mockRefresh).not.toHaveBeenCalled()
  })

  // -----------------------------------------------------------------------
  // Network error retry
  // -----------------------------------------------------------------------

  it('retries on network error with credential refresh', async () => {
    // First call: network error
    fetchMock.mockRejectedValueOnce(new Error('Failed to fetch'))
    mockRefresh.mockResolvedValueOnce(true)
    // Second call: success
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(successBody), { status: 200 }),
    )

    const result = await createProject(validPayload)
    expect(result.success).toBe(true)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(mockRefresh).toHaveBeenCalledTimes(1)
  })

  it('throws network error after all retry cycles exhausted', async () => {
    fetchMock.mockRejectedValue(new Error('Failed to fetch'))
    mockRefresh.mockResolvedValue(false)

    await expect(createProject(validPayload)).rejects.toThrow(ProjectServiceError)
    try {
      await createProject(validPayload)
    } catch (e) {
      expect((e as ProjectServiceError).status).toBe(0)
      expect((e as ProjectServiceError).message).toContain('Network error')
    }
  })

  // -----------------------------------------------------------------------
  // Request format validation
  // -----------------------------------------------------------------------

  it('sends request with correct headers and credentials', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify(successBody), { status: 200 }),
    )

    await createProject(validPayload)
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/projects'),
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        }),
      }),
    )
  })
})
