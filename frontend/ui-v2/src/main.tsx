import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import { registerPwa } from '@io-kit/shell/pwa-vite'
import { queryClient } from './api/queryClient'
import { projectRegistryQueryOptions } from './api/projectRegistry'
import { router } from './routes/router'
import { RealtimeFeedProvider } from './realtime/RealtimeFeedProvider'
import { CacheEngineProvider } from './sync/CacheEngineProvider'
import { AuthGate } from './auth/AuthGate'
import { setUpdateSW } from './offline/swUpdate'
import './styles.css'

const rootEl = document.getElementById('root')
if (!rootEl) throw new Error('Root element #root not found')

void queryClient.prefetchQuery(projectRegistryQueryOptions)

if ('serviceWorker' in navigator) {
  // DVP-TSK-860: kit helper owns registration (registerType 'prompt'); KitShell
  // shows the update toast. updateSW still backs the "App refresh" control
  // (offline/swUpdate.ts).
  setUpdateSW(registerPwa())
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
