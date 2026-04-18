import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { RouterProvider } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { queryClient } from './lib/queryClient'
import { AuthStateProvider } from './lib/authState'
import { router } from './lib/routes'
import './index.css'

// ---------------------------------------------------------------------------
// Session timestamp bootstrap
// ---------------------------------------------------------------------------
// On app load, read the JS-readable enceladus_session_at cookie (set by
// Lambda@Edge on login and by the auth_refresh Lambda on token refresh).
// If it's newer than what's in localStorage, update localStorage so the
// session timer starts from the latest known authentication event.
// ---------------------------------------------------------------------------

const SESSION_LS_KEY = 'enceladus:session_last_active'

function bootstrapSessionTimestamp(): void {
  const cookies = document.cookie.split(';')
  let cookieValue: number | null = null

  for (const part of cookies) {
    const trimmed = part.trim()
    if (trimmed.startsWith('enceladus_session_at=')) {
      cookieValue = Number(trimmed.slice('enceladus_session_at='.length))
      break
    }
  }

  if (cookieValue && Number.isFinite(cookieValue) && cookieValue > 0) {
    // Always write the cookie value to localStorage — the cookie is the
    // server-authoritative timestamp set by Lambda@Edge at login or by
    // auth_refresh on token renewal.  The previous guard (cookieValue >
    // lsValue) could fail when client-clock skew made the stale
    // localStorage value larger than the server timestamp, causing
    // AuthStateProvider to re-initialize as 'logged-out' after a
    // successful re-login.
    localStorage.setItem(SESSION_LS_KEY, String(cookieValue))
  }
}

bootstrapSessionTimestamp()

// ---------------------------------------------------------------------------
// Service worker registration with updateViaCache:'none'
// ---------------------------------------------------------------------------
// vite-plugin-pwa's auto-generated registerSW.js does not support the
// updateViaCache option. Safari aggressively caches sw.js in its HTTP disk
// cache, so without updateViaCache:'none' the browser may never detect a
// new service worker after deployment. We register manually here instead.
// ---------------------------------------------------------------------------

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/enceladus/sw.js', {
      scope: '/enceladus/',
      updateViaCache: 'none',
    })
  })
}

// ---------------------------------------------------------------------------
// React app mount
// ---------------------------------------------------------------------------

const appTree = (
  <StrictMode>
    <AuthStateProvider>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </AuthStateProvider>
  </StrictMode>
)

const rootEl = document.getElementById('root')!
createRoot(rootEl).render(appTree)

// ENC-ISS-255 mount-guard: some browser extensions inject MAIN-world scripts
// that strip React fiber keys from #root by id after mount, leaving the
// rendered markup but breaking event delegation. At t=2s, if #root has zero
// __react*/_reactListening* own-properties, re-mount the app into a fresh
// <div id="root-live"> appended to body. One-shot; no retry loop.
setTimeout(() => {
  const fiberKeys = Object.getOwnPropertyNames(rootEl).filter((k) =>
    /^(__react|_reactListening)/.test(k),
  )
  if (fiberKeys.length === 0) {
    const liveEl = document.createElement('div')
    liveEl.id = 'root-live'
    document.body.appendChild(liveEl)
    createRoot(liveEl).render(appTree)
  }
}, 2000)
