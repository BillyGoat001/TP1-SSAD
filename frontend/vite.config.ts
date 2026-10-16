import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In development, the Vite dev server (:5173) proxies /api to the FastAPI
// backend (:8000), so the frontend code can just call fetch('/api/...').
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
})
