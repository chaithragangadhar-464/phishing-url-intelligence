import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Use '/phishing-url-intelligence/' as base for GitHub Pages
// In production this is set by VITE_BASE env variable
const base = process.env.GITHUB_ACTIONS ? '/phishing-url-intelligence/' : '/'

export default defineConfig({
  plugins: [react()],
  base,
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      }
    }
  }
})
