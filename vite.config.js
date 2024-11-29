import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/mcp-security-scanner/',
  build: {
    outDir: 'dist',
  }
})