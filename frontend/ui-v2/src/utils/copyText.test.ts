import { afterEach, describe, expect, it, vi } from 'vitest'
import { copyText } from './copyText'

describe('copyText (ENC-FTR-151 AC-5)', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true })
  })

  it('uses navigator.clipboard when available', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    await expect(copyText('ENC-TSK-1')).resolves.toBe(true)
    expect(writeText).toHaveBeenCalledWith('ENC-TSK-1')
  })

  it('falls back to a textarea + execCommand when the Clipboard API is missing', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true })
    let copiedValue = ''
    document.execCommand = vi.fn(() => {
      copiedValue = (document.querySelector('textarea') as HTMLTextAreaElement).value
      return true
    })
    await expect(copyText('ENC-TSK-2')).resolves.toBe(true)
    expect(copiedValue).toBe('ENC-TSK-2')
    expect(document.querySelector('textarea')).toBeNull()
  })

  it('falls back when the Clipboard API rejects', async () => {
    const writeText = vi.fn().mockRejectedValue(new Error('denied'))
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    document.execCommand = vi.fn(() => true)
    await expect(copyText('ENC-TSK-3')).resolves.toBe(true)
    expect(document.execCommand).toHaveBeenCalledWith('copy')
  })
})
