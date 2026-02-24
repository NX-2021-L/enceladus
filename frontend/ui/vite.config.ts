import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { VitePWA } from 'vite-plugin-pwa'

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
