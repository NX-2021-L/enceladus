import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchFeedSnapshot } from './feeds'

// ENC-ISS-711: the cold-start snapshot must be ordered by each record's own
// updated_at, not by its position in tasks.json. The server emits rows grouped
// by type and sorted by record_id ascending, so a file-position sort surfaced
// old MOD-* records at first paint. These tests pin recency ordering.
describe('fetchFeedSnapshot (ENC-ISS-711 cold-start ordering)', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  function respondWith(tasks: unknown[]) {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ generated_at: '2026-08-27T05:00:00Z', tasks }), {
        status: 200,
      }),
    )
  }

  it('orders events by recordUpdatedAt desc, not by file position', async () => {
    // The freshest record is placed LAST in the file (a plain file-position sort
    // would have put the oldest MOD row on top).
    respondWith([
      { item_id: 'MOD-PLN-001', title: 'Legacy plan', updated_at: '2023-01-01T00:00:00Z' },
      { item_id: 'ENC-TSK-P56', title: 'Cursor fix', updated_at: '2026-08-27T02:00:00Z' },
      { item_id: 'ENC-ISS-711', title: 'Band', updated_at: '2026-08-27T04:30:00Z' },
    ])

    const snapshot = await fetchFeedSnapshot()
    const ids = snapshot.events.map((e) => e.recordId)

    expect(ids).toEqual(['ENC-ISS-711', 'ENC-TSK-P56', 'MOD-PLN-001'])
  })

  it('keeps the 50 most-recently-updated rows, not the file tail', async () => {
    const old = Array.from({ length: 60 }, (_, i) => ({
      item_id: `MOD-TSK-${String(i).padStart(3, '0')}`,
      title: `old ${i}`,
      updated_at: '2022-01-01T00:00:00Z',
    }))
    const fresh = {
      item_id: 'ENC-TSK-P60',
      title: 'fresh',
      updated_at: '2026-08-27T04:00:00Z',
    }
    // fresh row is first in the file; the 60 old rows follow.
    respondWith([fresh, ...old])

    const snapshot = await fetchFeedSnapshot()
    const ids = snapshot.events.map((e) => e.recordId)

    expect(ids).toHaveLength(50)
    expect(ids[0]).toBe('ENC-TSK-P60')
  })

  it('sorts rows with a missing updated_at to the end', async () => {
    respondWith([
      { item_id: 'ENC-TSK-A', title: 'dated', updated_at: '2026-08-27T04:00:00Z' },
      { item_id: 'ENC-TSK-B', title: 'undated' },
    ])

    const snapshot = await fetchFeedSnapshot()
    const ids = snapshot.events.map((e) => e.recordId)

    expect(ids).toEqual(['ENC-TSK-A', 'ENC-TSK-B'])
  })
})
