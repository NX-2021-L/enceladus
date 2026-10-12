import { useSyncExternalStore } from 'react'
import type { ActionId, Mode } from '@io-kit/auth'
import { auth } from './authClient'

/** Session snapshot from the kit client (no provider needed; re-renders on change). */
export function useAuthSession() {
  return useSyncExternalStore(auth.subscribe, auth.getSession, auth.getSession)
}

/**
 * DVP-TSK-861: display-only gate for write actions and approvals, read from the
 * PermissionManifest issued by auth_refresh. The server stays authoritative; the
 * escalation decide path keeps its three server gates regardless of this value.
 */
export function useCanExecute(action: ActionId, mode: Mode = 'execute'): boolean {
  // DVP-TSK-B06: opt out of React Compiler memoization. auth.can() reads the
  // PermissionManifest, which loads after the first render; a memo keyed only on
  // (action, mode) froze that first manifest_stale answer for the component's
  // lifetime, so a hard reload or a deep link never showed Approve/Deny.
  'use no memo'
  useAuthSession()
  return auth.can(action, mode).allowed
}
