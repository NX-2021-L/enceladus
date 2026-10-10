import { describe, expect, it } from 'vitest'
import { DEFAULT_MARKDOWN_ENGINE, resolveMarkdownEngine } from './markdownEngine'

describe('resolveMarkdownEngine (DVP-TSK-916 AC3: flag default off)', () => {
  it('defaults to the legacy parser this release', () => {
    expect(DEFAULT_MARKDOWN_ENGINE).toBe('legacy')
    expect(resolveMarkdownEngine('', null)).toBe('legacy')
    expect(resolveMarkdownEngine('?other=1', 'bogus')).toBe('legacy')
  })
  it('?md=kit turns the kit docstore renderer on', () => {
    expect(resolveMarkdownEngine('?md=kit', null)).toBe('kit')
    expect(resolveMarkdownEngine('?x=1&md=KIT', null)).toBe('kit')
  })
  it('honors a per-user preference, and the query flag wins over it', () => {
    expect(resolveMarkdownEngine('', 'kit')).toBe('kit')
    expect(resolveMarkdownEngine('?md=legacy', 'kit')).toBe('legacy')
    expect(resolveMarkdownEngine('?md=nonsense', 'kit')).toBe('kit')
  })
})
