import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { parseFeedSearch, parseFocus } from './feedUrl'

// DVP-TSK-995: the header SearchLauncher navigates with focus=1. validateSearch used to strip it, so the page could
// never focus its input. The route keeps it and the page passes autoFocus (kit search-ui 1.0.1+) plus a restoreKey.
const srcRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const read = (rel: string) => readFileSync(resolve(srcRoot, rel), 'utf8')

describe('focus=1 survives route validation', () => {
  it('parseFocus accepts the launcher string, a parsed number and true; nothing else', () => {
    expect(parseFocus({ focus: '1' })).toBe(true)
    expect(parseFocus({ focus: 1 })).toBe(true)
    expect(parseFocus({ focus: true })).toBe(true)
    expect(parseFocus({ focus: '0' })).toBe(false)
    expect(parseFocus({ focus: 'yes' })).toBe(false)
    expect(parseFocus({})).toBe(false)
  })

  it('parseFeedSearch keeps focus=1 and omits the key otherwise (existing shape unchanged)', () => {
    expect(parseFeedSearch({ q: 'x', focus: '1' })).toMatchObject({ q: 'x', focus: 1 })
    expect('focus' in parseFeedSearch({ q: 'x' })).toBe(false)
    expect('focus' in parseFeedSearch({ focus: 'nope' })).toBe(false)
  })

  it('the /docs route validateSearch keeps focus too', () => {
    expect(read('routes/router.tsx')).toMatch(/path: '\/docs'[\s\S]*?parseFocus\(raw\)/)
  })

  it('/feed and /docs pass autoFocus on focus=1 and a restoreKey to CollectionSearch', () => {
    const feed = read('feed/FeedSearchPage.tsx')
    expect(feed).toMatch(/autoFocus=\{autoFocus\}/)
    expect(feed).toMatch(/feedSearch\.focus === 1/)
    expect(feed).toMatch(/restoreKey="feed"/)
    const docs = read('routes/DocsSearchPage.tsx')
    expect(docs).toMatch(/autoFocus=\{focus === 1\}/)
    expect(docs).toMatch(/restoreKey="docs"/)
  })

  it('focus never enters the persisted feed return search', () => {
    expect(read('feed/FeedSearchPage.tsx')).toMatch(/persistFeedReturnSearch\(persistable\)/)
  })
})
