import { defineConfig } from 'vitest/config'
import react, { reactCompilerPreset } from '@vitejs/plugin-react'
import babel from '@rolldown/plugin-babel'
import type { Plugin } from 'vite'
import { createHash } from 'node:crypto'

function rndLogAnonymizerCspPlugin(): Plugin {
  return {
    name: 'rnd-log-anonymizer-csp',
    transformIndexHtml(html, ctx) {
      // Strict CSP only for production builds (ARCHITECTURE §12.1).
      if (ctx.server) return html
      if (html.includes('Content-Security-Policy')) return html

      // Allow the inline theme-flash-avoidance script via hash instead of 'unsafe-inline'.
      const inlineScript = /<script>([\s\S]*?)<\/script>/.exec(html)
      const scriptSrc = inlineScript
        ? `'self' 'sha256-${createHash('sha256').update(inlineScript[1], 'utf8').digest('base64')}'`
        : "'self'"

      const csp = [
        "default-src 'self'",
        "connect-src 'none'",
        "img-src 'self' data: blob:",
        "font-src 'self'",
        "worker-src 'self' blob:",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        // frame-ancestors has no effect via <meta> (browsers ignore it here) — enforce it via a
        // real HTTP header instead if this is ever served behind a reverse proxy.
        `script-src ${scriptSrc}`,
        "style-src 'self' 'unsafe-inline'",
      ].join('; ')

      return html.replace(
        /<head>/i,
        `<head>\n    <meta http-equiv="Content-Security-Policy" content="${csp}" />`,
      )
    },
  }
}

export default defineConfig(({ command }) => ({
  // Relative asset paths so the same build works whether served at domain root
  // (local preview/e2e) or under a subpath like /anonym (rnd-ai deploy) — an absolute
  // "/anonym/" base broke `vite preview`'s static serving for anything but the exact
  // subpath (it silently SPA-fallbacks to index.html instead of 404ing, masking the bug).
  base: command === 'build' ? './' : '/',
  plugins: [react(), babel({ presets: [reactCompilerPreset()] }), rndLogAnonymizerCspPlugin()],
  worker: {
    format: 'es',
  },
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    chunkSizeWarningLimit: 800,
    rollupOptions: {
      input: {
        // Production SPA only — gallery.html is served in `vite` / Playwright gallery suite,
        // never shipped in dist/ (Stage 8.5).
        main: 'index.html',
      },
    },
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'],
    setupFiles: ['./tests/setup.ts'],
    testTimeout: 120_000,
  },
}))
