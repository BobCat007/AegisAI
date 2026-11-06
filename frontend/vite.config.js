import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '..', '');
  const apiKey = (env.AEGISAI_API_KEY || '').trim();

  const proxyOptions = {
    target: 'http://127.0.0.1:8000',
    changeOrigin: true,

    configure(proxy) {
      if (apiKey) {
        proxy.on('proxyReq', (proxyReq) => {
          proxyReq.setHeader('X-AegisAI-API-Key', apiKey);
        });
      }
    },
  };

  return {
    plugins: [react()],

    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,

      proxy: {
        '/api': proxyOptions,
        '/health': proxyOptions,
      },
    },
  };
});
