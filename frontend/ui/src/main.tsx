// ENC-ISS-255 Pass 3 probe — REMOVE AFTER DIAGNOSIS. Replaces Pass 2 probe.
(() => {
  if (typeof window === 'undefined') return;
  const REALM_UUID = (crypto as any).randomUUID ? (crypto as any).randomUUID() : String(Math.random()).slice(2);
  const TIME_ORIGIN = performance.timeOrigin;
  const LS_KEY = '__iss255p3_log';
  const LS_COUNTER_KEY = '__iss255p3_init_counter';
  let initCount = 0;
  try { initCount = parseInt(localStorage.getItem(LS_COUNTER_KEY) || '0', 10) + 1; localStorage.setItem(LS_COUNTER_KEY, String(initCount)); } catch {}

  let bc: BroadcastChannel | null = null;
  try { bc = new BroadcastChannel('iss255p3'); } catch {}

  const events: any[] = [];
  const persist = () => { try { localStorage.setItem(LS_KEY, JSON.stringify(events.slice(-300))); } catch {} };
  const log = (ev: any) => {
    const full = { t: performance.now(), realmUuid: REALM_UUID, timeOrigin: TIME_ORIGIN, initCount, ...ev };
    events.push(full);
    try { bc?.postMessage(full); } catch {}
    if (events.length % 3 === 0) persist();
  };
  (window as any).__iss255p3_events = events;

  log({ type: 'probe.armed', url: location.href, visibility: document.visibilityState, readyState: document.readyState });

  // === Layer A: document.open/write/close traps ===
  const origDocOpen = Document.prototype.open;
  Document.prototype.open = function (this: Document, ...args: any[]) {
    log({ type: 'document.open', stack: (new Error('p3-docopen')).stack?.slice(0, 2500) });
    persist();
    return (origDocOpen as any).apply(this, args);
  } as any;
  const origDocWrite = Document.prototype.write;
  Document.prototype.write = function (this: Document, ...args: any[]) {
    log({ type: 'document.write', argsPreview: String(args[0] || '').slice(0, 300), stack: (new Error('p3-docwrite')).stack?.slice(0, 2500) });
    persist();
    return (origDocWrite as any).apply(this, args);
  } as any;
  const origDocWriteln = Document.prototype.writeln;
  Document.prototype.writeln = function (this: Document, ...args: any[]) {
    log({ type: 'document.writeln', argsPreview: String(args[0] || '').slice(0, 300), stack: (new Error('p3-docwriteln')).stack?.slice(0, 2500) });
    persist();
    return (origDocWriteln as any).apply(this, args);
  } as any;
  const origDocClose = Document.prototype.close;
  Document.prototype.close = function (this: Document) {
    log({ type: 'document.close', stack: (new Error('p3-docclose')).stack?.slice(0, 2500) });
    persist();
    return origDocClose.call(this);
  };

  // === Layer B: innerHTML/outerHTML setters on documentElement/body/#root ===
  const innerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  if (innerDesc?.set) {
    const origSet = innerDesc.set;
    Object.defineProperty(Element.prototype, 'innerHTML', {
      ...innerDesc,
      set(v: string) {
        const el = this as Element;
        if (el === document.documentElement || el === document.body || el.id === 'root' || el.id === 'root-live') {
          log({ type: 'innerHTML.set', target: el === document.documentElement ? 'html' : el === document.body ? 'body' : '#' + el.id, len: String(v || '').length, preview: String(v || '').slice(0, 200), stack: (new Error('p3-innerhtml')).stack?.slice(0, 2500) });
          persist();
        }
        return origSet.call(el, v);
      },
    });
  }
  const outerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
  if (outerDesc?.set) {
    const origSet = outerDesc.set;
    Object.defineProperty(Element.prototype, 'outerHTML', {
      ...outerDesc,
      set(v: string) {
        const el = this as Element;
        if (el === document.documentElement || el === document.body || el.id === 'root' || el.id === 'root-live') {
          log({ type: 'outerHTML.set', target: el.nodeName, len: String(v || '').length, stack: (new Error('p3-outerhtml')).stack?.slice(0, 2500) });
          persist();
        }
        return origSet.call(el, v);
      },
    });
  }

  // === Layer C: lifecycle event listeners ===
  const lifecycleEvents = ['pagehide', 'pageshow', 'beforeunload', 'unload', 'freeze', 'resume', 'prerenderingchange', 'visibilitychange'];
  for (const evName of lifecycleEvents) {
    window.addEventListener(evName, (e: any) => {
      log({ type: 'lifecycle.' + evName, persisted: (e as any).persisted, visibility: document.visibilityState });
      persist();
    }, true);
  }

  // === Layer D: fiber attach + vanish watcher ===
  const rootEl = document.getElementById('root') || document.getElementById('root-live');
  if (!rootEl) { log({ type: 'probe.no_root' }); persist(); }
  let seenFiber = false;
  let tick = 0;
  const sentinelTick = () => {
    tick++;
    const el = document.getElementById('root') || document.getElementById('root-live');
    if (el) {
      const keys = Object.getOwnPropertyNames(el).filter(k => /^(__react|_reactListening)/.test(k));
      if (keys.length > 0 && !seenFiber) { seenFiber = true; log({ type: 'fiber.attached', keys, elementId: el.id }); }
      if (seenFiber && keys.length === 0) { log({ type: 'fiber.vanished', tick, elementStillInDom: document.contains(el), elementId: el.id }); persist(); seenFiber = false; }
    }
    if (tick < 1800) requestAnimationFrame(sentinelTick); else persist();
  };
  requestAnimationFrame(sentinelTick);

  // Falsification gate — signal for createRoot target swap
  if (new URLSearchParams(location.search).has('iss255_falsify')) {
    (window as any).__iss255p3_falsify = true;
    log({ type: 'falsification.engaged', mode: 'mount-target-swap' });
    persist();
  }

  setTimeout(persist, 25000);
  console.log('[ISS-255-P3] probe armed. realm:', REALM_UUID, 'initCount:', initCount, 'falsify:', !!(window as any).__iss255p3_falsify);
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

const mountTarget = (window as any).__iss255p3_falsify
  ? (() => { const d = document.createElement('div'); d.id = 'root-live'; document.body.appendChild(d); return d; })()
  : document.getElementById('root')!

createRoot(mountTarget).render(
  <StrictMode>
    <AuthStateProvider>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </AuthStateProvider>
  </StrictMode>
)
