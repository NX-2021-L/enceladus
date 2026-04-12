import { readdirSync } from 'fs'
import { resolve } from 'path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { VitePWA } from 'vite-plugin-pwa'
import type { Plugin } from 'vite'

// ---------------------------------------------------------------------------
// ENC-ISS-211: Force-emit page chunks to prevent non-deterministic code
// splitting across Node versions. CodeBuild (Node 20) silently dropped the
// DeploymentManagerPage chunk after a module graph shift in PR #293.
// Rollup's emitFile API guarantees chunk inclusion regardless of tree-shaking
// or module graph analysis.
// ---------------------------------------------------------------------------
function forcePageChunks(): Plugin {
  return {
    name: 'force-page-chunks',
    buildStart() {
      const pagesDir = resolve(__dirname, 'src/pages')
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
        runtimeCaching: [],
        // Exclude /enceladus/callback from the NavigationRoute fallback.
        // Lambda@Edge handles /callback server-side (token exchange + cookie
        // set + 302 redirect). If the SW intercepts this navigation, the
        // Set-Cookie headers from the 302 chain may not be flushed to
        // document.cookie before the app bootstrap reads them, causing the
        // session to appear expired after a successful re-login.
        navigateFallbackDenylist: [/\/callback/],
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
      plugins: [forcePageChunks()],
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
