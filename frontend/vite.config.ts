import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// During `npm run dev`, proxy API calls to the backend so the browser talks to
// one origin (no CORS juggling). In production the dashboard is served behind
// the same gateway as the API.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // ws: true so the /api/ws/alerts WebSocket upgrade is proxied too.
      '/api': { target: 'http://localhost:8000', ws: true, changeOrigin: true },
    },
  },
})
