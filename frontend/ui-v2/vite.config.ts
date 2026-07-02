import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { VitePWA } from 'vite-plugin-pwa'

// ENC-TSK-K21 · PWA 2.0 scaffold
//
// AC-16: React Compiler v1.0 is activated through babel-plugin-react-compiler,
// wired into @vitejs/plugin-react's babel pipeline below. With the compiler
// active, manual memoization (useMemo / useCallback / React.memo) is redundant
// and MUST NOT appear in component files.
export default defineConfig({
  plugins: [
    react({
      babel: {
        plugins: [
          // React Compiler v1.0 — target the React 19 runtime.
          ['babel-plugin-react-compiler', { target: '19' }],
        ],
      },
    }),
    tailwindcss(),
    // K25 owns the offline/caching story. Here we ship a manifest only — no
    // runtime caching strategies, no Workbox precache of app routes.
    VitePWA({
      registerType: 'prompt',
      injectRegister: null,
      workbox: {
        // Manifest-only: do not precache anything. Caching lands in K25.
        globPatterns: [],
      },
      manifest: {
        name: 'Enceladus Governance Cockpit',
        short_name: 'Enceladus',
        description: 'Enceladus PWA 2.0 governance cockpit',
        theme_color: '#0A0A0F',
        background_color: '#0A0A0F',
        display: 'standalone',
        start_url: '/',
        icons: [],
      },
    }),
  ],
})
