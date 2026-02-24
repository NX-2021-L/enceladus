import { defineConfig, mergeConfig } from 'vitest/config'
import viteConfig from './vite.config'

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: 'jsdom',
      globals: true,
      setupFiles: ['./src/test/setup.ts'],
      coverage: {
        provider: 'v8',
        reporter: ['text', 'html'],
        include: [
          'src/api/auth.ts',
          'src/api/client.ts',
          'src/lib/authSession.ts',
          'src/hooks/useSessionLifecycle.ts',
          'src/hooks/useProjects.ts',
          'src/hooks/useTasks.ts',
          'src/components/shared/StatusChip.tsx',
          'src/components/shared/FilterBar.tsx',
          'src/components/shared/ErrorState.tsx',
        ],
      },
    },
  }),
)
