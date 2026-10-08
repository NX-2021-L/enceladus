import { defineConfig, type Plugin } from 'vite'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { VitePWA } from 'vite-plugin-pwa'
import { RUNTIME_CACHING, SW_FEED_CACHE_CLEANUP_SCRIPT } from './src/offline/runtimeCaching'

const uiRoot = path.dirname(fileURLToPath(import.meta.url))

/**
 * ENC-TSK-M37 — build-injected version string for the top-bar version tag
 * (spec SS4: "the version string appears in the top bar version tag on
 * every screen... never omit"). Derived from package.json + the short git
 * SHA at build time so it's meaningful in both local dev and CI without
 * requiring any new deploy-workflow secrets/vars (git history is already
 * checked out by the deploy job). Falls back to the bare package version if
 * git isn't available (e.g. a source tarball build).
 */
function resolveAppVersion(): string {
  const pkgVersion = JSON.parse(readFileSync(path.join(uiRoot, 'package.json'), 'utf-8')).version as string
  try {
    const sha = execSync('git rev-parse --short HEAD', { cwd: uiRoot }).toString().trim()
    return `v${pkgVersion}+${sha}`
  } catch {
    return `v${pkgVersion}`
  }
}

/** design-system-2 JSX uses React.Fragment without importing React. */
function designSystemReactInject(): Plugin {
  return {
    name: 'design-system-react-inject',
    transform(code, id) {
      if (!id.includes('design-system-2/v2/components/') || !id.endsWith('.jsx')) {
        return null
      }
      if (code.includes("from 'react'") || code.includes('from "react"')) {
        return null
      }
      return { code: `import React from 'react'\n${code}`, map: null }
    },
  }
}

// ENC-TSK-K21 · PWA 2.0 scaffold
//
// AC-16: React Compiler v1.0 is activated through babel-plugin-react-compiler,
// wired into @vitejs/plugin-react's babel pipeline below. With the compiler
// active, manual memoization (useMemo / useCallback / React.memo) is redundant
// and MUST NOT appear in component files.
export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(resolveAppVersion()),
  },
  // design-system-2 JSX components live outside this package root.
  server: {
    fs: {
      allow: ['..'],
    },
  },
  resolve: {
    alias: {
      react: path.resolve(uiRoot, 'node_modules/react'),
      'react-dom': path.resolve(uiRoot, 'node_modules/react-dom'),
    },
  },
  plugins: [
    designSystemReactInject(),
    react({
      babel: {
        plugins: [
          // React Compiler v1.0 — target the React 19 runtime.
          ['babel-plugin-react-compiler', { target: '19' }],
        ],
      },
    }),
    tailwindcss(),
    // ENC-TSK-K25 · B67 AC-17/18/19 offline layer (DOC-E470AC8CE9A8 §7)
    VitePWA({
      registerType: 'prompt',
      injectRegister: false,
      workbox: {
        globPatterns: ['**/*.{js,css,html,ico,png,svg,woff2,woff}'],
        navigateFallback: '/index.html',
        navigateFallbackDenylist: [/^\/api\//, /\/callback/, /^\/mobile\/v1\/auth/],
        // ENC-TSK-Q33: the route table lives in src/offline/runtimeCaching.ts so
        // its first-match resolution is unit-tested; the imported script
        // deletes the legacy StaleWhileRevalidate 'feed-api' cache on activate.
        importScripts: [SW_FEED_CACHE_CLEANUP_SCRIPT],
        runtimeCaching: RUNTIME_CACHING,
      },
      manifest: {
        name: 'Enceladus Governance Cockpit',
        short_name: 'Enceladus',
        description: 'Enceladus PWA 2.0 governance cockpit',
        theme_color: '#0A0A0F',
        background_color: '#0A0A0F',
        display: 'standalone',
        start_url: '/',
        icons: [
          { src: 'icon-192.png', sizes: '192x192', type: 'image/png' },
          { src: 'icon-512.png', sizes: '512x512', type: 'image/png' },
          { src: 'maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
        ],
      },
    }),
  ],
})
