import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'

// DVP-TSK-B06: the gate must follow the PermissionManifest, which arrives after the first render.
const state = { allowed: false, session: { status: 'authenticated', policyVersion: 'v0' } as Record<string, unknown> }
const listeners = new Set<() => void>()
vi.mock('./authClient', () => ({
  auth: {
    subscribe: (fn: () => void) => { listeners.add(fn); return () => { listeners.delete(fn) } },
    getSession: () => state.session,
    can: () => ({ allowed: state.allowed, visibility: state.allowed ? 'show' : 'disable' }),
  },
}))

import { useCanExecute } from './useCan'

function Probe() {
  const allowed = useCanExecute('escalation.request')
  return <span data-allowed={String(allowed)} />
}

describe('useCanExecute', () => {
  it('re-evaluates when the manifest lands after the first render', () => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    const host = document.createElement('div')
    const root = createRoot(host)
    act(() => root.render(<Probe />))
    expect(host.querySelector('span')?.getAttribute('data-allowed')).toBe('false')
    act(() => {
      state.allowed = true
      state.session = { ...state.session, policyVersion: 'v1' }
      listeners.forEach((fn) => fn())
    })
    expect(host.querySelector('span')?.getAttribute('data-allowed')).toBe('true')
    act(() => root.unmount())
  })
})
