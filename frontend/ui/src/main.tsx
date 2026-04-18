// ENC-ISS-255 Pass 2 probe — REMOVE AFTER DIAGNOSIS. Replaces Pass 1 probe.
(() => {
  if (typeof window === 'undefined') return;
  const SS_KEY = '__iss255p2_log';
  const events: any[] = [];
  const persist = () => { try { sessionStorage.setItem(SS_KEY, JSON.stringify(events)); } catch {} };
  const log = (ev: any) => { events.push({ t: performance.now(), ...ev }); if (events.length % 5 === 0) persist(); };
  (window as any).__iss255p2_events = events; // secondary (may be wiped)
  sessionStorage.setItem(SS_KEY, '[]');

  log({ type: 'probe.armed', marker: '__iss255p2' });

  const rootEl = document.getElementById('root');
  if (!rootEl) { log({ type: 'probe.no_root' }); persist(); return; }

  // === Layer 1: Reflect.deleteProperty trap ===
  const origReflectDelete = Reflect.deleteProperty;
  Reflect.deleteProperty = function (target: any, key: any) {
    const keyStr = String(key);
    const isRoot = target === rootEl;
    const isWindow = target === window;
    const isIss = /^__iss255/.test(keyStr);
    const isReact = /^__react|^_reactListening/.test(keyStr);
    if (isRoot || isWindow || isIss || isReact) {
      log({
        type: 'reflect.delete',
        target: isRoot ? '#root' : isWindow ? 'window' : target?.constructor?.name || typeof target,
        key: keyStr,
        stack: (new Error('iss255p2-reflect')).stack?.slice(0, 2500) || '',
      });
      persist();
    }
    return origReflectDelete.call(Reflect, target, key);
  };

  // === Layer 2: fiber-slot lock (runs on rAF until keys seen) ===
  let locked = false;
  const tryLock = () => {
    const keys = Object.getOwnPropertyNames(rootEl).filter(k => /^(__react|_reactListening)/.test(k));
    if (keys.length > 0 && !locked) {
      for (const k of keys) {
        try {
          const desc = Object.getOwnPropertyDescriptor(rootEl, k);
          if (desc && desc.configurable) {
            Object.defineProperty(rootEl, k, { ...desc, configurable: false });
            log({ type: 'fiber.locked', key: k });
          }
        } catch (e: any) {
          log({ type: 'fiber.lock_error', key: k, error: String(e?.message || e) });
        }
      }
      locked = true;
      persist();
    }
    if (!locked) requestAnimationFrame(tryLock);
  };
  requestAnimationFrame(tryLock);

  // === Layer 3: window-property delta sentinel (rAF diff) ===
  const baselineWindow = new Set(Object.getOwnPropertyNames(window));
  let tick = 0;
  const seenRemoved = new Set<string>();
  const sentinelTick = () => {
    tick++;
    const now = new Set(Object.getOwnPropertyNames(window));
    for (const k of baselineWindow) {
      if (!now.has(k) && !seenRemoved.has(k)) {
        seenRemoved.add(k);
        log({ type: 'window.removed', key: k, tick });
      }
    }
    // Also check fiber keys post-lock
    if (locked) {
      const present = Object.getOwnPropertyNames(rootEl).filter(k => /^(__react|_reactListening)/.test(k));
      if (present.length === 0) {
        log({ type: 'fiber.missing_despite_lock', tick });
        persist();
      }
    }
    if (tick < 900) requestAnimationFrame(sentinelTick); else persist();
  };
  requestAnimationFrame(sentinelTick);

  // === Layer 4: catch TypeErrors from delete-on-non-configurable (strict mode) ===
  window.addEventListener('error', (e) => {
    if (e.message && /configurable|cannot delete/i.test(e.message)) {
      log({ type: 'delete_trapped_strict', message: e.message, filename: (e as any).filename, lineno: (e as any).lineno, colno: (e as any).colno, stack: e.error?.stack?.slice(0, 2500) || '' });
      persist();
    }
  }, true);
  window.addEventListener('unhandledrejection', (e) => {
    const msg = String(e.reason?.message || e.reason || '');
    if (/configurable|cannot delete/i.test(msg)) {
      log({ type: 'delete_trapped_rejection', message: msg, stack: e.reason?.stack?.slice(0, 2500) || '' });
      persist();
    }
  }, true);

  // Final persist after 20s to capture the post-mount clobber window
  setTimeout(persist, 20000);
  console.log('[ISS-255] Pass 2 probe armed (sessionStorage key: __iss255p2_log)');
})();

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

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthStateProvider>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </AuthStateProvider>
  </StrictMode>
)
