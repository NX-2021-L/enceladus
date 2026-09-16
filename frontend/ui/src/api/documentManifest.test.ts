import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchDocumentManifest } from './documentManifest'
import { NotFoundError } from './tracker'

describe('fetchDocumentManifest', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('fetches the manifest projection and normalizes the outline', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          document_id: 'DOC-ABC',
          project_id: 'enceladus',
          title: 'Doc',
          version: 3,
          content_hash: 'hash-1',
          size_bytes: 100,
          updated_at: '2026-09-01T00:00:00Z',
          outline: [
            { heading_path: ['A'], level: 2, ordinal: 0, block_id: null, line_start: 1, line_end: 2, section_bytes: 10 },
          ],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )

    const manifest = await fetchDocumentManifest('DOC-ABC')
    expect(manifest.content_hash).toBe('hash-1')
    expect(manifest.outline).toHaveLength(1)
    expect(manifest.outline[0]?.heading_path).toEqual(['A'])

    const [url] = fetchMock.mock.calls[0] as [string]
    expect(url).toBe('/api/v1/documents/DOC-ABC/manifest')
  })

  it('falls back to the ETag header for content_hash when the body omits it', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ document_id: 'DOC-ABC', outline: [] }), {
        status: 200,
        headers: { ETag: '"etag-hash"' },
      }),
    )
    const manifest = await fetchDocumentManifest('DOC-ABC')
    expect(manifest.content_hash).toBe('etag-hash')
  })

  it('defaults outline to [] when missing', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ document_id: 'DOC-ABC', content_hash: 'h' }), { status: 200 }),
    )
    const manifest = await fetchDocumentManifest('DOC-ABC')
    expect(manifest.outline).toEqual([])
  })

  it('throws NotFoundError on 404', async () => {
    fetchMock.mockResolvedValue(new Response('', { status: 404 }))
    await expect(fetchDocumentManifest('DOC-MISSING')).rejects.toBeInstanceOf(NotFoundError)
  })

  it('throws a generic error on other non-2xx statuses', async () => {
    fetchMock.mockResolvedValue(new Response('', { status: 500 }))
    await expect(fetchDocumentManifest('DOC-ABC')).rejects.toThrow('500')
  })
})
