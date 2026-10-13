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
import { Alert, Button, Link } from '../design-system'

// 'check' = eligible, waiting on the async subscription lookup.
type NudgeState = 'hidden' | 'check' | 'prompt' | 'ios' | 'blocked'

// Mirrors the kit's private checks: iOS Safari delivers push only to a Home Screen web app.
function isIosSafari(): boolean {
  const ua = navigator.userAgent
  return /iP(hone|ad|od)/.test(ua) && /Safari/.test(ua) && !/(CriOS|FxiOS|EdgiOS)/.test(ua)
}

function isStandalone(): boolean {
  const nav = navigator as Navigator & { standalone?: boolean }
  return nav.standalone === true || (typeof window.matchMedia === 'function' && window.matchMedia('(display-mode: standalone)').matches)
}

export interface EscalationPushNudgeProps {
  api: NotifyApi
  storage?: Pick<Storage, 'getItem' | 'setItem'>
  className?: string
}

function initialState(storage: Pick<Storage, 'getItem'>): NudgeState {
  try {
    if (storage.getItem(PUSH_NUDGE_DISMISS_KEY) === '1') return 'hidden'
  } catch { /* private mode: keep offering */ }
  if (isIosSafari() && !isStandalone()) return 'ios'
  if (!pushSupported() || Notification.permission !== 'default') return 'hidden'
  return 'check'
}

export function EscalationPushNudge({ api, storage, className }: EscalationPushNudgeProps) {
  const [state, setState] = useState<NudgeState>(() => initialState(storage ?? window.localStorage))
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    if (state !== 'check') return undefined
    let live = true
    currentSubscription()
      .then((s) => { if (live) setState(s ? 'hidden' : 'prompt') })
      .catch(() => { if (live) setState('hidden') })
    return () => { live = false }
  }, [state])

  if (state === 'hidden' || state === 'check') return null

  const dismiss = () => {
    try { (storage ?? window.localStorage).setItem(PUSH_NUDGE_DISMISS_KEY, '1') } catch { /* private mode */ }
    setState('hidden')
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
    <div className={className} data-testid="push-nudge" data-state={state}>
      {state === 'prompt' && (
        <Alert type="info" header="Get notified when a gate needs your verdict" dismissible onDismiss={dismiss}
          action={<Button variant="primary" loading={busy} onClick={() => void turnOn()}>Turn on notifications</Button>}>
          New escalations and deploy approvals reach this device even when Enceladus is closed. Choose which ones in {settings}.
        </Alert>
      )}
      {state === 'blocked' && (
        <Alert type="warning" header="Notifications are blocked for this site" dismissible onDismiss={dismiss}>
          Allow notifications for this site in your browser settings, then reload the page.
        </Alert>
      )}
      {state === 'ios' && (
        <Alert type="info" header="Add Enceladus to your Home Screen for notifications" dismissible onDismiss={dismiss}>
          On iPhone and iPad, notifications only reach the installed app: tap Share, then Add to Home Screen.
        </Alert>
      )}
    </div>
  )
}
