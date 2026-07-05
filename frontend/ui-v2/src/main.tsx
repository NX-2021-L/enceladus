import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import { queryClient } from './api/queryClient'
import { projectRegistryQueryOptions } from './api/projectRegistry'
import { router } from './routes/router'
import { RealtimeFeedProvider } from './realtime/RealtimeFeedProvider'
import { CacheEngineProvider } from './sync/CacheEngineProvider'
import { AuthGate } from './auth/AuthGate'
import './styles.css'

const rootEl = document.getElementById('root')
if (!rootEl) throw new Error('Root element #root not found')

void queryClient.prefetchQuery(projectRegistryQueryOptions)

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
