import { describe, expect, it, vi } from 'vitest'
import { downloadTextFile } from './downloadTextFile'

describe('downloadTextFile (ENC-TSK-M34 AC-2)', () => {
  it('builds a Blob, triggers a download anchor, and revokes the object URL', () => {
    const createObjectURL = vi.fn(() => 'blob:mock-url')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', { ...URL, createObjectURL, revokeObjectURL })

    const clickSpy = vi.fn()
    const originalCreateElement = document.createElement.bind(document)
    const appendSpy = vi.spyOn(document.body, 'appendChild')
    vi.spyOn(document, 'createElement').mockImplementation((tag: string) => {
      const el = originalCreateElement(tag)
      if (tag === 'a') el.click = clickSpy
      return el
    })

    downloadTextFile('DOC-B6B52E3BB9BB.md', '# hello world', 'text/markdown')

    expect(createObjectURL).toHaveBeenCalledTimes(1)
    const [blobArg] = createObjectURL.mock.calls[0]
    expect(blobArg).toBeInstanceOf(Blob)
    expect(appendSpy).toHaveBeenCalled()
    expect(clickSpy).toHaveBeenCalledTimes(1)
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock-url')

    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })
})
