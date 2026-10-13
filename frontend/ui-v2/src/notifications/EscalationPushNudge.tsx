/**
 * DVP-TSK-B21: escalations push opt-in (io request 2026-10-13). The kit's PushNudge renders bare markup (a
 * paragraph, an unstyled button and a literal "x") that ignores the Enceladus design system, so
 * the cockpit renders its own: the same behaviour on the kit client (pushSupported /
 * currentSubscription / enablePush) and the kit's dismissal key, so a prior "x" still counts,
 * shown as a design-system Alert with a primary action, like every other notice on the page.
 */
import { useEffect, useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { currentSubscription, enablePush, pushSupported, type NotifyApi } from '@io-kit/notify'
import { PUSH_NUDGE_DISMISS_KEY } from '@io-kit/notify/react'
import { useDisplayMode } from '@io-kit/shell/react'
import { Alert, Button, Link } from '../design-system'

// 'check' = eligible, waiting on the async subscription lookup.
type PushState = 'hidden' | 'check' | 'prompt' | 'blocked'

// iOS Safari delivers push only to a Home Screen web app (the kit's own check, minus display mode,
// which comes from the shell's useDisplayMode: src never gates on display-mode itself).
function isIosSafari(): boolean {
  const ua = navigator.userAgent
  return /iP(hone|ad|od)/.test(ua) && /Safari/.test(ua) && !/(CriOS|FxiOS|EdgiOS)/.test(ua)
}

function wasDismissed(storage: Pick<Storage, 'getItem'>): boolean {
  try {
    return storage.getItem(PUSH_NUDGE_DISMISS_KEY) === '1'
  } catch {
    return false // private mode: keep offering
  }
}

export interface EscalationPushNudgeProps {
  api: NotifyApi
  storage?: Pick<Storage, 'getItem' | 'setItem'>
  className?: string
}

export function EscalationPushNudge({ api, storage, className }: EscalationPushNudgeProps) {
  const [dismissed, setDismissed] = useState(() => wasDismissed(storage ?? window.localStorage))
  const [state, setState] = useState<PushState>(() =>
    pushSupported() && Notification.permission === 'default' ? 'check' : 'hidden')
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()
  const displayMode = useDisplayMode()
  const iosBrowser = isIosSafari() && displayMode === 'browser'

  useEffect(() => {
    if (dismissed || iosBrowser || state !== 'check') return undefined
    let live = true
    currentSubscription()
      .then((s) => { if (live) setState(s ? 'hidden' : 'prompt') })
      .catch(() => { if (live) setState('hidden') })
    return () => { live = false }
  }, [dismissed, iosBrowser, state])

  if (dismissed || (!iosBrowser && state !== 'prompt' && state !== 'blocked')) return null

  const dismiss = () => {
    try { (storage ?? window.localStorage).setItem(PUSH_NUDGE_DISMISS_KEY, '1') } catch { /* private mode */ }
    setDismissed(true)
  }

  const turnOn = async () => {
    setBusy(true)
    try {
      const r = await enablePush(api)
      setState(r.ok ? 'hidden' : 'blocked')
    } catch {
      setState('blocked')
    } finally {
      setBusy(false)
    }
  }

  const settings = (
    <Link href="/settings/notifications" onFollow={() => void navigate({ to: '/settings/notifications' })}>notification settings</Link>
  )

  return (
    <div className={className} data-testid="push-nudge" data-state={iosBrowser ? 'ios' : state}>
      {!iosBrowser && state === 'prompt' && (
        <Alert type="info" header="Get notified when a gate needs your verdict" dismissible onDismiss={dismiss}
          action={<Button variant="primary" loading={busy} onClick={() => void turnOn()}>Turn on notifications</Button>}>
          New escalations and deploy approvals reach this device even when Enceladus is closed. Choose which ones in {settings}.
        </Alert>
      )}
      {!iosBrowser && state === 'blocked' && (
        <Alert type="warning" header="Notifications are blocked for this site" dismissible onDismiss={dismiss}>
          Allow notifications for this site in your browser settings, then reload the page.
        </Alert>
      )}
      {iosBrowser && (
        <Alert type="info" header="Add Enceladus to your Home Screen for notifications" dismissible onDismiss={dismiss}>
          On iPhone and iPad, notifications only reach the installed app: tap Share, then Add to Home Screen.
        </Alert>
      )}
    </div>
  )
}
