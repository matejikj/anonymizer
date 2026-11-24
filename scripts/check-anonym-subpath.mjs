#!/usr/bin/env node
/**
 * Krok 10 — verify production dist works under /anonym/ like systemd helper.
 * Creates a temp webroot with symlink anonym -> dist, serves it, checks HTML/CSP/assets.
 *
 * Usage: npm run build && npm run check:anonym-subpath
 */

import { createServer } from 'node:http'
import { mkdtemp, readFile, readdir, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createReadStream, existsSync, statSync } from 'node:fs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const dist = path.join(root, 'dist')

function fail(msg) {
  console.error(`check:anonym-subpath FAIL: ${msg}`)
  process.exit(1)
}

function contentType(filePath) {
  if (filePath.endsWith('.html')) return 'text/html; charset=utf-8'
  if (filePath.endsWith('.js')) return 'text/javascript; charset=utf-8'
  if (filePath.endsWith('.css')) return 'text/css; charset=utf-8'
  if (filePath.endsWith('.svg')) return 'image/svg+xml'
  if (filePath.endsWith('.woff2')) return 'font/woff2'
  return 'application/octet-stream'
}

async function main() {
  if (!existsSync(path.join(dist, 'index.html'))) {
    fail('dist/index.html missing — run npm run build first')
  }

  const html = await readFile(path.join(dist, 'index.html'), 'utf8')
  if (!/Content-Security-Policy/i.test(html)) fail('CSP meta missing in dist/index.html')
  if (!/connect-src 'none'/.test(html)) fail("CSP connect-src 'none' missing")
  // Relative base for subpath deploy
  if (/src="\/assets\//.test(html) || /href="\/assets\//.test(html)) {
    fail('absolute /assets/ paths break /anonym/ deploy — expected relative ./assets/')
  }

  const webroot = await mkdtemp(path.join(tmpdir(), 'anonym-webroot-'))
  const anonymLink = path.join(webroot, 'anonym')
  try {
    await symlink(dist, anonymLink, 'dir')

    const server = createServer((req, res) => {
      const urlPath = decodeURIComponent((req.url ?? '/').split('?')[0] ?? '/')
      if (!urlPath.startsWith('/anonym')) {
        res.writeHead(404)
        res.end('not found')
        return
      }
      let rel = urlPath.slice('/anonym'.length)
      if (rel === '' || rel === '/') rel = '/index.html'
      const filePath = path.normalize(path.join(dist, rel))
      if (!filePath.startsWith(dist)) {
        res.writeHead(403)
        res.end('forbidden')
        return
      }
      if (!existsSync(filePath) || !statSync(filePath).isFile()) {
        // SPA fallback for client routes under /anonym/
        const index = path.join(dist, 'index.html')
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
        createReadStream(index).pipe(res)
        return
      }
      res.writeHead(200, { 'Content-Type': contentType(filePath) })
      createReadStream(filePath).pipe(res)
    })

    await new Promise((resolve, reject) => {
      server.listen(0, '127.0.0.1', (err) => (err ? reject(err) : resolve()))
    })
    const { port } = server.address()
    const base = `http://127.0.0.1:${port}/anonym/`

    const indexRes = await fetch(base)
    if (!indexRes.ok) fail(`GET /anonym/ -> ${indexRes.status}`)
    const body = await indexRes.text()
    if (!/Content-Security-Policy/i.test(body)) fail('served /anonym/ HTML missing CSP')

    const assetRefs = [...body.matchAll(/(?:src|href)="([^"]+\.(?:js|css))"/g)].map((m) => m[1])
    if (assetRefs.length === 0) fail('no js/css asset refs in index.html')

    for (const ref of assetRefs) {
      const url = new URL(ref, base)
      if (!url.pathname.startsWith('/anonym/')) {
        fail(`asset ${ref} resolved outside /anonym/: ${url.pathname}`)
      }
      const assetRes = await fetch(url)
      if (!assetRes.ok) fail(`GET ${url.pathname} -> ${assetRes.status}`)
      const ct = assetRes.headers.get('content-type') ?? ''
      if (ct.includes('text/html') && (ref.endsWith('.js') || ref.endsWith('.css'))) {
        fail(`asset ${url.pathname} returned HTML (broken relative path / SPA fallback)`)
      }
    }

    // Worker / lazy chunks often live as hashed assets — ensure at least one .js under dist/assets loads
    const assetsDir = path.join(dist, 'assets')
    if (existsSync(assetsDir)) {
      const files = await readdir(assetsDir)
      const sample = files.find((f) => f.endsWith('.js'))
      if (sample) {
        const r = await fetch(`${base}assets/${sample}`)
        if (!r.ok) fail(`lazy asset assets/${sample} -> ${r.status}`)
      }
    }

    server.close()
    console.log('check:anonym-subpath OK')
    console.log(`  served ${base}`)
    console.log(`  verified ${assetRefs.length} entry assets + CSP + relative base`)
  } finally {
    await rm(webroot, { recursive: true, force: true })
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
