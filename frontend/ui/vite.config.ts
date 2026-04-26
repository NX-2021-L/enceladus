import { readdirSync } from 'fs'
import { resolve } from 'path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { VitePWA } from 'vite-plugin-pwa'
import type { Plugin, ResolvedConfig } from 'vite'

// ---------------------------------------------------------------------------
// ENC-ISS-211: Force-emit page chunks to prevent non-deterministic code
// splitting across Node versions. CodeBuild (Node 20) silently dropped the
// DeploymentManagerPage chunk after a module graph shift in PR #293.
// Rollup's emitFile API guarantees chunk inclusion regardless of tree-shaking
// or module graph analysis.
//
// Uses config.root (not __dirname) to resolve paths — __dirname is unreliable
// in Vite ESM config loading across Node versions (ENC-TSK-D54).
// ---------------------------------------------------------------------------
function forcePageChunks(): Plugin {
  let root: string
  return {
    name: 'force-page-chunks',
    configResolved(config: ResolvedConfig) {
      root = config.root
    },
    buildStart() {
      const pagesDir = resolve(root, 'src/pages')
      const pages = readdirSync(pagesDir).filter((f) =>
        /^[A-Z].*Page\.tsx$/.test(f),
      )
      for (const page of pages) {
        this.emitFile({
          type: 'chunk',
          id: resolve(pagesDir, page),
          name: page.replace(/\.tsx$/, ''),
        })
      }
    },
  }
}

export default defineConfig({
  base: '/enceladus/',
  plugins: [
    react(),
    tailwindcss(),
    forcePageChunks(),
    VitePWA({
      registerType: 'autoUpdate',
      // Disable auto-generated registerSW.js — we register the SW manually
      // in main.tsx with updateViaCache:'none' to force Safari to always
      // network-fetch sw.js instead of serving it from HTTP disk cache.
      injectRegister: false,
      // Scope the service worker to /enceladus/ so it only intercepts
      // requests under that path and doesn't conflict with /mobile/v1 auth.
      scope: '/enceladus/',
      base: '/enceladus/',
      manifest: {
        name: 'Project Status',
        short_name: 'ProjStatus',
        description: 'Mobile project status dashboard',
        display: 'standalone',
        start_url: '/enceladus/',
        scope: '/enceladus/',
        background_color: '#0f172a',
        theme_color: '#0f172a',
        icons: [
          { src: 'icon-192.png', sizes: '192x192', type: 'image/png' },
          { src: 'icon-512.png', sizes: '512x512', type: 'image/png' },
          { src: 'icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
        ],
      },
      workbox: {
        // Force the new service worker to activate immediately on install instead
        // of waiting for all existing tabs to close. Without these two flags,
        // VitePWA with injectRegister:false never sends the SKIP_WAITING message,
        // so the updated SW sits in "waiting" state indefinitely — users keep
        // running the old JS bundle until they manually close every tab.
        skipWaiting: true,
        clientsClaim: true,
        globPatterns: ['**/*.{js,css,html,ico,png,svg,woff2}'],
        // Do NOT cache /mobile/v1 feeds via service worker — they require
        // the auth cookie and are intercepted by Lambda@Edge. Network-only
        // fetches let the browser send cookies naturally through CloudFront.
        // ENC-ISS-260 / ENC-TSK-F10: explicit NetworkOnly bypass for
        // /api/v1/deploy/* — the Deployment Manager posts decide/approve/
        // divert/revert to these endpoints and the SW navigateFallback was
        // catching same-origin POSTs and returning the index.html app-shell,
        // producing "Unexpected token <" JSON-parse errors and silently
        // breaking every governed deployment approval (which also definitionally
        // blocks ENC-TSK-E76 AC3). NetworkOnly ensures every method on this
        // prefix goes straight to CloudFront without SW cache involvement.
        runtimeCaching: [
          {
            urlPattern: ({ url }) => url.pathname.startsWith('/api/v1/deploy/'),
            handler: 'NetworkOnly',
            method: 'POST',
            options: { matchOptions: { ignoreSearch: true } },
          },
          {
            urlPattern: ({ url }) => url.pathname.startsWith('/api/v1/deploy/'),
            handler: 'NetworkOnly',
            method: 'GET',
            options: { matchOptions: { ignoreSearch: true } },
          },
          {
            urlPattern: ({ url }) => url.pathname.startsWith('/api/v1/deploy/'),
            handler: 'NetworkOnly',
            method: 'DELETE',
            options: { matchOptions: { ignoreSearch: true } },
          },
          {
            urlPattern: ({ url }) => url.pathname.startsWith('/api/v1/deploy/'),
            handler: 'NetworkOnly',
            method: 'PATCH',
            options: { matchOptions: { ignoreSearch: true } },
          },
          {
            urlPattern: ({ url }) => url.pathname.startsWith('/api/v1/deploy/'),
            handler: 'NetworkOnly',
            method: 'PUT',
            options: { matchOptions: { ignoreSearch: true } },
          },
        ],
        // Exclude /enceladus/callback from the NavigationRoute fallback.
        // Lambda@Edge handles /callback server-side (token exchange + cookie
        // set + 302 redirect). If the SW intercepts this navigation, the
        // Set-Cookie headers from the 302 chain may not be flushed to
        // document.cookie before the app bootstrap reads them, causing the
        // session to appear expired after a successful re-login.
        // ENC-ISS-260 / ENC-TSK-F10: also exclude /api/* from the navigation
        // fallback as a belt-and-suspenders measure. Even though Workbox's
        // NavigationRoute normally only fires on accept:text/html GETs, the
        // denylist prevents any future misclassification from routing API
        // calls into the precached app shell.
        navigateFallbackDenylist: [/\/callback/, /\/api\//],
      },
    }),
  ],
  server: {
    proxy: {
      '/mobile/v1': {
        target: 'http://localhost:3001',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/mobile\/v1/, ''),
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('/node_modules/react/')) return 'react-core'
            if (id.includes('/node_modules/react-dom/')) return 'react-core'
            if (id.includes('/node_modules/react-router-dom/')) return 'react-router'
            if (id.includes('/node_modules/react-router/')) return 'react-router'
            if (id.includes('/node_modules/@remix-run/router/')) return 'react-router'
            if (id.includes('/@tanstack/react-query/')) return 'query'
            if (
              id.includes('/react-markdown/') ||
              id.includes('/react-syntax-highlighter/')
            ) {
              return 'markdown'
            }
            if (id.includes('/react-window/')) return 'virtualized'
            return undefined
          }

          // Pages get explicit chunks to prevent non-deterministic code
          // splitting across Node versions (ENC-ISS-211).
          const pageMatch = id.match(/\/src\/pages\/([A-Z][^/]+?)\.tsx$/)
          if (pageMatch) return pageMatch[1]

          if (id.includes('/src/lib/routes.tsx')) return 'routes'
          if (
            id.includes('/src/components/layout/AppShell.tsx') ||
            id.includes('/src/hooks/useSessionLifecycle.ts') ||
            id.includes('/src/lib/authState.tsx') ||
            id.includes('/src/lib/queryClient.ts')
          ) {
            return 'shell'
          }

          return undefined
        },
      },
    },
  },
})
