import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./vitest.setup.ts', './src/test/setup.ts'],
    css: true,
    include: ['src/**/a11y.test.{ts,tsx}'],
  },
})
