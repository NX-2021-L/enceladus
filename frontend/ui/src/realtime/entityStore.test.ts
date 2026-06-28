import { describe, it, expect, beforeEach } from 'vitest'
import { useEntityStore } from './entityStore'

describe('normalized entity store (AC-12 cross-page consistency)', () => {
  beforeEach(() => useEntityStore.getState().reset())

  it('upserts and reads back a single entity', () => {
    useEntityStore.getState().upsert('task', 'ENC-TSK-B67', { status: 'open', title: 'Cockpit' })
    const e = useEntityStore.getState().get('task', 'ENC-TSK-B67')
    expect(e?.status).toBe('open')
    expect(e?.title).toBe('Cockpit')
    expect(e?.recordId).toBe('ENC-TSK-B67')
  })

  it('shallow-merges patches (single update propagates new field)', () => {
    const s = useEntityStore.getState()
    s.upsert('task', 'ENC-TSK-B67', { status: 'open', title: 'Cockpit' })
    s.upsert('task', 'ENC-TSK-B67', { status: 'closed' })
    const e = useEntityStore.getState().get('task', 'ENC-TSK-B67')
    expect(e?.status).toBe('closed')
    expect(e?.title).toBe('Cockpit')
  })

  it('a single upsert changes the entity reference for selector re-render', () => {
    const s = useEntityStore.getState()
    s.upsert('task', 'T1', { status: 'open' })
    const before = useEntityStore.getState().get('task', 'T1')
    s.upsert('task', 'T1', { status: 'closed' })
    const after = useEntityStore.getState().get('task', 'T1')
    expect(before).not.toBe(after) // new reference → subscribers re-render
  })

  it('hydrate bulk-loads a collection', () => {
    useEntityStore.getState().hydrate('issue', [
      { recordId: 'I1', record_type: 'issue', status: 'open' },
      { recordId: 'I2', record_type: 'issue', status: 'closed' },
    ])
    expect(useEntityStore.getState().get('issue', 'I2')?.status).toBe('closed')
  })

  it('removes an entity', () => {
    const s = useEntityStore.getState()
    s.upsert('task', 'T1', { status: 'open' })
    s.remove('task', 'T1')
    expect(useEntityStore.getState().get('task', 'T1')).toBeUndefined()
  })
})
