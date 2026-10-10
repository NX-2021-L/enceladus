import { act, useEffect } from 'react'
import { createRoot } from 'react-dom/client'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it, vi } from 'vitest'
import type { TieredSearchSnapshot } from '../types/search'

const body = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '__fixtures__/enc-graphsearch-hybrid.json'), 'utf8'))
vi.mock('./enceladusSearchSource', async () => {
  const real = await vi.importActual<typeof import('./enceladusSearchSource')>('./enceladusSearchSource')
  return {
    ...real,
    hostSearchSource: real.createHostSearchSource({ fetch: async () => ({ ok: true, status: 200, json: async () => body }) }),
  }
})

import { useTieredSearch } from './useTieredSearch'

;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

function Probe({ q, onSnap }: { q: string; onSnap: (s: TieredSearchSnapshot) => void }) {
  const s = useTieredSearch({ projectId: 'enceladus', query: q }, [
    { recordId: 'ENC-TSK-LOCAL1', recordType: 'task', projectId: 'enceladus', title: 'feed local row', status: 'open' },
  ])
  useEffect(() => {
    onSnap(s)
  })
  return null
}

async function run(q: string) {
  const snaps: TieredSearchSnapshot[] = []
  const root = createRoot(document.createElement('div'))
  await act(async () => root.render(<Probe q={q} onSnap={(s) => snaps.push(s)} />))
  await act(async () => {
    await new Promise((r) => setTimeout(r, 400))
  })
  act(() => root.unmount())
  return snaps
}

describe('useTieredSearch on @io-kit/search', () => {
  it('paints the local tier first, then hybrid order with evidence and the graph signal degraded', async () => {
    const snaps = await run('feed')
    expect(snaps[0]!.hits[0]!.tier).toBe('local')
    expect(snaps[0]!.hybridPending).toBe(true)
    const last = snaps.at(-1)!
    expect(last.hybridPending).toBe(false)
    expect(last.hybridCount).toBeGreaterThan(0)
    expect(last.hits[0]!.tier).toBe('hybrid')
    expect(last.hits.some((h) => h.recordId === 'ENC-TSK-LOCAL1' && h.tier === 'local')).toBe(true)
    expect(last.availability?.graph).toBe('unavailable')
    expect(last.degraded.map((d) => d.signal)).toContain('graph')
    expect(last.serverDown).toBe(false)
    const ev = last.evidenceById.get(last.hits[0]!.recordId)!
    expect(ev.find((e) => e.signal === 'graph')!.rank).toBeNull()
  })
  it('a blank query is browse mode: the whole local corpus, no hybrid call', async () => {
    const snaps = await run('')
    const last = snaps.at(-1)!
    expect(last.hits.map((h) => h.recordId)).toEqual(['ENC-TSK-LOCAL1'])
    expect(last.hybridPending).toBe(false)
    expect(last.availability).toBeUndefined()
  })
})
