// HBuilderX owns the compiler and its dependencies; this is mobile preview configuration only.
import { defineConfig } from 'vite'
import uni from '@dcloudio/vite-plugin-uni'

export default defineConfig({
  plugins: [
    uni(),
    {
      name: 'wrok-bot-loopback-only',
      configResolved(config) {
        if (config.command === 'serve' &&
            (config.server.host !== '127.0.0.1' || config.server.port !== 5173 || !config.server.strictPort)) {
          throw new Error('Mobile preview requires 127.0.0.1:5173 with strictPort')
        }
      },
    },
  ],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
  },
})
