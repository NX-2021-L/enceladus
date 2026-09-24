import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  isContentHashMismatch,
  isSectionPatchError,
  patchSection,
  SectionPatchError,
} from './documentSections'

const BASE_REQUEST = {
  document_id: 'DOC-ABC',
  project_id: 'enceladus',
  anchor: { block_id: '01HXYZ' },
  op: 'replace' as const,
  body: 'new text',
  if_match: 'hash-1',
  include_heading: false,
  rebase_headings: true,
  caused_by: 'sub-123',
}

describe('patchSection', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('POSTs to /documents/{id}/sections and returns the success body', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          document_id: 'DOC-ABC',
          version: 4,
          content_hash: 'hash-2',
          size_bytes: 120,
          event_id: 'evt-1',
          anchor_resolved: { heading_path: ['A'], level: 2, ordinal: 0, block_id: '01HXYZ' },
          bytes_changed: 8,
          outline: [],
        }),
        { status: 200 },
      ),
    )

    const response = await patchSection('DOC-ABC', BASE_REQUEST)
    expect(response.content_hash).toBe('hash-2')

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/v1/documents/DOC-ABC/sections')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toMatchObject({ caused_by: 'sub-123', op: 'replace' })
  })

  it('parses a 412 error_envelope into SectionPatchError with code CONTENT_HASH_MISMATCH', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          error_envelope: {
            code: 'CONTENT_HASH_MISMATCH',
            message: 'stale hash',
            details: { expected_hash: 'hash-1', current_hash: 'hash-9', current_version: 5 },
          },
        }),
        { status: 412 },
      ),
    )

    await expect(patchSection('DOC-ABC', BASE_REQUEST)).rejects.toSatisfy((err: unknown) => {
      expect(isSectionPatchError(err)).toBe(true)
      expect(isContentHashMismatch(err)).toBe(true)
      const sectionErr = err as SectionPatchError
      expect(sectionErr.status).toBe(412)
      expect(sectionErr.details.current_hash).toBe('hash-9')
      return true
    })
  })

  it('tolerates a flat top-level code (no error_envelope wrapper)', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ code: 'ANCHOR_NOT_FOUND', message: 'no such anchor', details: { outline: [] } }), {
        status: 404,
      }),
    )
    await expect(patchSection('DOC-ABC', BASE_REQUEST)).rejects.toSatisfy((err: unknown) => {
      const sectionErr = err as SectionPatchError
      expect(sectionErr.code).toBe('ANCHOR_NOT_FOUND')
      expect(sectionErr.status).toBe(404)
      expect(isContentHashMismatch(err)).toBe(false)
      return true
    })
  })

  it('surfaces ANCHOR_AMBIGUOUS with candidates', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          error_envelope: {
            code: 'ANCHOR_AMBIGUOUS',
            message: 'multiple matches',
            details: { candidates: [{ ordinal: 0 }, { ordinal: 1 }] },
          },
        }),
        { status: 409 },
      ),
    )
    await expect(patchSection('DOC-ABC', BASE_REQUEST)).rejects.toSatisfy((err: unknown) => {
      const sectionErr = err as SectionPatchError
      expect(sectionErr.code).toBe('ANCHOR_AMBIGUOUS')
      expect(sectionErr.details.candidates).toHaveLength(2)
      return true
    })
  })
})
