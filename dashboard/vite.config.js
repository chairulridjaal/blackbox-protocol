import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 6868,
    proxy: {
      '/api': {
        target: 'http://localhost:6767',
        changeOrigin: true,
      }
    }
  }
})
