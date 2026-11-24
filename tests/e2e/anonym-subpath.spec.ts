import { test, expect } from '@playwright/test'
import { createServer } from 'node:http'
import { createReadStream, existsSync, statSync } from 'node:fs'
import { mkdtemp, rm, symlink } from 'node:fs/promises'
import path from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const dist = path.join(root, 'dist')

function contentType(filePath: string): string {
  if (filePath.endsWith('.html')) return 'text/html; charset=utf-8'
  if (filePath.endsWith('.js')) return 'text/javascript; charset=utf-8'
  if (filePath.endsWith('.css')) return 'text/css; charset=utf-8'
  return 'application/octet-stream'
}

/**
 * Mirrors install-systemd-service.sh: webroot/anonym -> dist
 */
test('SPA loads under /anonym/ with CSP and universal entry', async ({ browser }) => {
  test.setTimeout(120_000)
  expect(existsSync(path.join(dist, 'index.html'))).toBe(true)

  const webroot = await mkdtemp(path.join(tmpdir(), 'anonym-e2e-'))
  await symlink(dist, path.join(webroot, 'anonym'), 'dir')

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
    if (!filePath.startsWith(dist) || !existsSync(filePath) || !statSync(filePath).isFile()) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      createReadStream(path.join(dist, 'index.html')).pipe(res)
      return
    }
    res.writeHead(200, { 'Content-Type': contentType(filePath) })
    createReadStream(filePath).pipe(res)
  })

  await new Promise<void>((resolve, reject) => {
    server.listen(0, '127.0.0.1', (err?: Error) => (err ? reject(err) : resolve()))
  })
  const { port } = server.address() as { port: number }
  const base = `http://127.0.0.1:${port}/anonym/`

  const context = await browser.newContext({ baseURL: base })
  const page = await context.newPage()
  const failed: string[] = []
  page.on('response', (res) => {
    if (res.url().includes('/anonym/') && res.status() >= 400) {
      failed.push(`${res.status()} ${res.url()}`)
    }
  })

  await page.goto(base)
  await expect(page.locator('meta[http-equiv="Content-Security-Policy"]')).toHaveCount(1)
  await expect(page.getByTestId('detection-settings-panel')).toBeVisible()
  await expect(page.getByTestId('multi-source-dropzone')).toBeVisible({ timeout: 15_000 })
  expect(failed, failed.join('\n')).toEqual([])

  await context.close()
  server.close()
  await rm(webroot, { recursive: true, force: true })
})
