import { useEffect, useState } from 'react'
import { Flashbar } from '../design-system'

/**
 * DVP-TSK-B24: result notice for the managed-login "Add a passkey" round trip.
 *
 * Managed login's /passkeys/add returns to the registered callback with
 * `?result=<value>`; auth_refresh turns that into `/?passkey_result=<value>`.
 * On first render this reads the param, strips it from the URL
 * (history.replaceState, so a reload does not repeat the notice) and shows a
 * dismissible design-system Flashbar item.
 */

export const PASSKEY_RESULT_PARAM = 'passkey_result'

type Notice = { type: 'success' | 'warning' | 'info'; header: string; content: string }

export function passkeyNoticeFor(result: string): Notice {
  if (result === 'success') {
    return {
      type: 'success',
      header: 'Passkey added',
      content: 'Passkey added. You can sign in with it next time.',
    }
  }
  if (result === 'invalid_session') {
    return {
      type: 'warning',
      header: 'Sign in again first',
      content:
        'To add a passkey, sign in again first, then choose Add a passkey within a few minutes.',
    }
  }
  return {
    type: 'info',
    header: 'Passkey not added',
    content: 'The passkey step did not complete. You can try Add a passkey again.',
  }
}

/** Read `passkey_result` and remove it from the address bar. Returns null if absent. */
export function consumePasskeyResult(): string | null {
  const url = new URL(window.location.href)
  const result = url.searchParams.get(PASSKEY_RESULT_PARAM)
  if (result === null) return null
  url.searchParams.delete(PASSKEY_RESULT_PARAM)
  window.history.replaceState(window.history.state, '', url.pathname + url.search + url.hash)
  return result
}

export function PasskeyResultNotice() {
  const [result, setResult] = useState<string | null>(null)

  useEffect(() => {
    const found = consumePasskeyResult()
    if (found !== null) setResult(found)
  }, [])

  if (result === null) return null
  const notice = passkeyNoticeFor(result)
  return (
    <Flashbar
      items={[
        {
          id: 'passkey-result',
          ...notice,
          dismissible: true,
          onDismiss: () => setResult(null),
        },
      ]}
    />
  )
}
