import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { PasskeyResultNotice } from './PasskeyResultNotice'

/** DVP-TSK-B24: notice for the managed-login add-a-passkey return (`?passkey_result=`). */
describe('PasskeyResultNotice', () => {
  let container: HTMLDivElement
  let root: Root

  async function mountAt(url: string) {
    window.history.replaceState({}, '', url)
    await act(async () => {
      root.render(<PasskeyResultNotice />)
    })
  }

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
  })
  afterEach(() => {
    act(() => root.unmount())
    container.remove()
    window.history.replaceState({}, '', '/')
  })

  it('shows the success notice and strips the param', async () => {
    await mountAt('/projects?passkey_result=success&keep=1#top')
    expect(container.textContent).toContain('Passkey added. You can sign in with it next time.')
    expect(window.location.pathname).toBe('/projects')
    expect(window.location.search).toBe('?keep=1')
    expect(window.location.hash).toBe('#top')
  })

  it('shows the sign-in-again guidance for invalid_session and strips the param', async () => {
    await mountAt('/?passkey_result=invalid_session')
    expect(container.textContent).toContain(
      'To add a passkey, sign in again first, then choose Add a passkey within a few minutes.',
    )
    expect(window.location.search).toBe('')
  })

  it('shows a short neutral message for any other result', async () => {
    await mountAt('/?passkey_result=something_else')
    expect(container.textContent).toContain('The passkey step did not complete.')
    expect(container.textContent).not.toContain('Passkey added')
    expect(window.location.search).toBe('')
  })

  it('renders nothing when the param is absent', async () => {
    await mountAt('/feed?q=x')
    expect(container.textContent).toBe('')
    expect(window.location.search).toBe('?q=x')
  })
})
