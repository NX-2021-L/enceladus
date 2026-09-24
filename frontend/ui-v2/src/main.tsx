import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import { registerSW } from 'virtual:pwa-register'
import { queryClient } from './api/queryClient'
import { projectRegistryQueryOptions } from './api/projectRegistry'
import { router } from './routes/router'
import { RealtimeFeedProvider } from './realtime/RealtimeFeedProvider'
import { CacheEngineProvider } from './sync/CacheEngineProvider'
import { AuthGate } from './auth/AuthGate'
import { useOfflineStore } from './store/offlineStore'
import { setUpdateSW } from './offline/swUpdate'
import './styles.css'

const rootEl = document.getElementById('root')
if (!rootEl) throw new Error('Root element #root not found')

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
        <CacheEngineProvider>
          <RealtimeFeedProvider>
            <RouterProvider router={router} />
          </RealtimeFeedProvider>
        </CacheEngineProvider>
      </AuthGate>
    </QueryClientProvider>
  </StrictMode>,
)
