import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { FeedRealtimeEvent } from '../types/feedEvents'

const handlers = new Map<string, (event: FeedRealtimeEvent) => void>()
const upsertTier2 = vi.fn(async () => {})

vi.mock('./RealtimeFeedProvider', () => ({
  useRealtimeFeed: () => ({
    watchRecord: (id: string, fn: (event: FeedRealtimeEvent) => void) => {
      handlers.set(id, fn)
      return () => handlers.delete(id)
    },
  }),
}))
vi.mock('../sync/cacheEngine', () => ({ getCacheEngine: () => ({ upsertTier2 }) }))

import { recordKeys } from '../api/queryOptions'
import { normalizeRecordBody } from './normalizeRecordBody'
import { useRecordRealtimeSync } from './useRecordRealtimeSync'

type TrackerType = 'task' | 'issue' | 'feature' | 'plan' | 'lesson'
const TYPES: { type: TrackerType; id: string }[] = [
  { type: 'task', id: 'ENC-TSK-100' },
  { type: 'issue', id: 'INT-ISS-157' },
  { type: 'feature', id: 'ENC-FTR-300' },
  { type: 'plan', id: 'ENC-PLN-400' },
  { type: 'lesson', id: 'ENC-LSN-500' },
]

function Probe({ type, project, id }: { type: TrackerType; project: string; id: string }) {
  useRecordRealtimeSync(type, project, id)
  return null
}

/**
 * ENC-TSK-T30 (ENC-ISS-926): the /records/{id} body is the raw DynamoDB stream
 * image. It has item_id but no `{type}_id`, and none of the read-time record
 * extensions. Written over the cached detail body as-is, the open page lost its
 * id and threw on the next render.
 */
describe('useRecordRealtimeSync writes the realtime body in the detail API shape', () => {
  let container: HTMLDivElement
  let root: Root
  let qc: QueryClient

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    handlers.clear()
    upsertTier2.mockClear()
    qc = new QueryClient()
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
  })
  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  for (const { type, id } of TYPES) {
    it(`${type}: keeps ${type}_id and the extension keys when a raw stream body arrives`, () => {
      const project = id.startsWith('INT-') ? 'intelligence' : 'enceladus'
      const key = recordKeys.detail(type, project, id)
      const typed = [{ relationship_type: 'implements', target_id: 'ENC-FTR-001' }]
      const context = { freshness_score: 1 }
      qc.setQueryData(key, {
        [`${type}_id`]: id,
        item_id: id,
        title: 'before',
        status: 'open',
        updated_at: '2026-11-24T01:00:00Z',
        typed_relationships: typed,
        context_node: context,
      })
      act(() =>
        root.render(
          <QueryClientProvider client={qc}>
            <Probe type={type} project={project} id={id} />
          </QueryClientProvider>,
        ),
      )

      // The shape appsync_feed_publisher sends: the stored item, no `{type}_id`, no extensions.
      const raw = {
        record_id: `${type}#${id}`,
        item_id: id,
        project_id: project,
        record_type: type,
        title: 'after',
        status: 'closed',
        updated_at: '2026-11-24T01:13:34Z',
        write_kind: 'marker',
      }
      act(() => handlers.get(id)!({ action: 'updated', record: raw } as unknown as FeedRealtimeEvent))

      const body = qc.getQueryData<Record<string, unknown>>(key)!
      expect(body[`${type}_id`]).toBe(id)
      expect(body.title).toBe('after')
      expect(body.status).toBe('closed')
      expect(body.typed_relationships).toBe(typed)
      expect(body.context_node).toBe(context)
      // The Tier-2 mirror gets the same normalized body, so an offline reopen is safe too.
      expect(upsertTier2).toHaveBeenCalledWith(project, id, body, expect.any(String))
    })
  }

  it('still drops an event older than the cached body', () => {
    const key = recordKeys.detail('issue', 'enceladus', 'ENC-ISS-001')
    qc.setQueryData(key, { issue_id: 'ENC-ISS-001', title: 'new', updated_at: '2026-11-24T02:00:00Z' })
    act(() =>
      root.render(
        <QueryClientProvider client={qc}>
          <Probe type="issue" project="enceladus" id="ENC-ISS-001" />
        </QueryClientProvider>,
      ),
    )
    act(() =>
      handlers.get('ENC-ISS-001')!({
        action: 'updated',
        record: { item_id: 'ENC-ISS-001', title: 'old', updated_at: '2026-11-24T01:00:00Z' },
      } as unknown as FeedRealtimeEvent),
    )
    expect(qc.getQueryData<Record<string, unknown>>(key)!.title).toBe('new')
    expect(upsertTier2).not.toHaveBeenCalled()
  })
})

describe('normalizeRecordBody', () => {
  it('takes {type}_id from the body when the body already has it', () => {
    expect(normalizeRecordBody('task', 'ENC-TSK-1', { task_id: 'ENC-TSK-1', item_id: 'X' }, undefined).task_id).toBe('ENC-TSK-1')
  })

  it('falls back to the route id when the body has neither {type}_id nor item_id', () => {
    expect(normalizeRecordBody('plan', 'ENC-PLN-9', { title: 't' }, undefined).plan_id).toBe('ENC-PLN-9')
  })

  it('prefers extension keys the event does carry over the cached ones', () => {
    const fresh = [{ relationship_type: 'blocks', target_id: 'ENC-TSK-2' }]
    const out = normalizeRecordBody('task', 'ENC-TSK-1', { item_id: 'ENC-TSK-1', typed_relationships: fresh }, {
      typed_relationships: [],
    })
    expect(out.typed_relationships).toBe(fresh)
  })

  it('does not mutate the event body', () => {
    const raw = { item_id: 'ENC-TSK-1' }
    normalizeRecordBody('task', 'ENC-TSK-1', raw, { context_node: {} })
    expect(raw).toEqual({ item_id: 'ENC-TSK-1' })
  })
})
