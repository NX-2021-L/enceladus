/** ENC-TSK-R82-0E -- Edit metadata panel: changed field goes through setField with the If-Match revision. */
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RecordMetadataPanel } from './RecordMetadataPanel'

const setField = vi.fn()
vi.mock('../api/mutations', async (orig) => {
  const actual = await orig<typeof import('../api/mutations')>()
  return { ...actual, setField: (...a: unknown[]) => setField(...a) }
})

const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 20)) })

describe('RecordMetadataPanel', () => {
  it('saves a changed field via setField with the revision; lifecycle field is not editable', async () => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    setField.mockResolvedValue({ success: true, record_id: 'ENC-TSK-1', updated_at: 'x', sync_version: 8 })
    const qc = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
    const container = document.createElement('div')
    document.body.appendChild(container)
    const root = createRoot(container)
    act(() => {
      root.render(
        <QueryClientProvider client={qc}>
          <RecordMetadataPanel
            projectId="enceladus"
            recordType="task"
            recordId="ENC-TSK-1"
            syncVersion={7}
            record={{ title: 'Old', description: 'd', priority: 'P2', assigned_to: null, status: 'open' }}
          />
        </QueryClientProvider>,
      )
    })
    await flush()
    const inputs = Array.from(container.querySelectorAll('input')) as HTMLInputElement[]
    const title = inputs.find((i) => i.value === 'Old')!
    expect(title).toBeTruthy()
    const status = inputs.find((i) => i.value === 'open')!
    expect(status.disabled || status.readOnly).toBe(true)
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!
      setter.call(title, 'New title')
      title.dispatchEvent(new Event('input', { bubbles: true }))
    })
    await act(async () => {
      container.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
    })
    await flush()
    expect(setField).toHaveBeenCalledTimes(1)
    expect(setField.mock.calls[0].slice(0, 6)).toEqual(['enceladus', 'task', 'ENC-TSK-1', 'title', 'New title', 7])
    expect(container.textContent).toContain('version 8')
    act(() => root.unmount())
  })
})
