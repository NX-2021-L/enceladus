/** DVP-TSK-A24 (E4-R28): the @io-kit/notify client bound to the coordination hub (DVP-TSK-A23 routes). */
import { createFetchNotifyApi, ensureSubscription } from '@io-kit/notify'
import { gateFetch } from '../routes/GateInboxPanel'

export const notifyApi = createFetchNotifyApi('/api/v1/coordination', gateFetch as typeof fetch)

/** On app start: when permission is already granted, keep the subscription valid (VAPID key rotation resubscribes). */
export function ensureNotifySubscription(): void {
  if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return
  void ensureSubscription(notifyApi).catch(() => undefined)
}
