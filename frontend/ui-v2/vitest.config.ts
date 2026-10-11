import { defineConfig, mergeConfig } from 'vitest/config'
import viteConfig from './vite.config'

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: 'jsdom',
      globals: true,
      setupFiles: ['./src/test/setup.ts'],
      // DVP-TSK-995: Cloudscape ships ESM with directory imports; vite must transform it (and the kit that imports it).
      server: { deps: { inline: [/@cloudscape-design/, /@io-kit\/search-ui/] } },
    },
  }),
)
