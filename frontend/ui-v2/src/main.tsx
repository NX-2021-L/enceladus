import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import { registerSW } from 'virtual:pwa-register'
import { installIosFocusZoomGuard } from '@io-kit/shell'
import { queryClient } from './api/queryClient'
import { projectRegistryQueryOptions } from './api/projectRegistry'
import { router } from './routes/router'
import { RealtimeFeedProvider } from './realtime/RealtimeFeedProvider'
import { CorpusProvider } from './search/CorpusProvider'
import { AuthGate } from './auth/AuthGate'
import { useOfflineStore } from './store/offlineStore'
import { setUpdateSW } from './offline/swUpdate'
// DVP-TSK-956: kit 0.4.0 standalone primitives (the safe-area insets, top-inset
// class and no-focus-zoom class). Everything in it sits in cascade layers, so the
// unlayered design-system-2 styles always win and the desktop look is unchanged.
import '@io-kit/shell/io-kit.css'
import './styles.css'

const rootEl = document.getElementById('root')
if (!rootEl) throw new Error('Root element #root not found')

// DVP-TSK-A12 (io, iPhone): iOS zooms the page when a field under 16px takes focus. The guard adds maximum-scale=1 to
// the viewport on iOS/iPadOS only (pinch zoom still works there) and sets html[data-io-zoom-guard], which switches the
// kit's 16px field bump off so the search controls keep their design-system size (Space Grotesk 14px / Inter 14px).
installIosFocusZoomGuard()

void queryClient.prefetchQuery(projectRegistryQueryOptions)

if ('serviceWorker' in navigator) {
  // ENC-TSK-M37: capture registerSW's return value so the "App refresh"
  // control can force skipWaiting + reload (offline/swUpdate.ts) instead of
  // only ever showing the dismiss-only "update available" banner.
  const updateSW = registerSW({
    immediate: true,
    onNeedRefresh() {
      useOfflineStore.getState().setSwUpdateReady(true)
    },
    onOfflineReady() {
      /* precache warm — no auto reload (registerType: prompt) */
    },
  })
  setUpdateSW(updateSW)
}

createRoot(rootEl).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthGate>
        <CorpusProvider>
          <RealtimeFeedProvider>
            <RouterProvider router={router} />
          </RealtimeFeedProvider>
        </CorpusProvider>
      </AuthGate>
    </QueryClientProvider>
  </StrictMode>,
)
