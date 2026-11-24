#!/usr/bin/env node
/**
 * Enterprise step 14 — release integrity manifest for dist/.
 *
 * Writes:
 *   release/SHA256SUMS
 *   release/release-manifest.json
 *   release/SHA256SUMS.asc   (only when GPG_SIGN_RELEASE=1 and gpg is available)
 *
 * "Signed releases" = checksums always; detach-sign when a release key is configured.
 */
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
  unlinkSync,
} from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const distDir = path.join(root, 'dist')
const outDir = path.join(root, 'release')

const FORBIDDEN_CDN_HINTS =
  /fonts\.googleapis|fonts\.gstatic|googletagmanager|google-analytics|gtag\(|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare/i

/**
 * Only flag remote URLs that look like runtime network endpoints.
 * XML namespaces, JSON Schema $id, React error docs, and IPv6 URL templates are allowlisted.
 */
const REMOTE_URL =
  /https?:\/\/(?!localhost|127\.0\.0\.1)[^\s"'`)]+/gi

function isBenignEmbeddedUrl(url) {
  if (url.includes('${') || url.includes('[')) return true // template / IPv6 placeholders
  const allow = [
    'http://www.w3.org/',
    'https://www.w3.org/',
    'https://react.dev/errors/',
    'https://json-schema.org/',
    'http://json-schema.org/',
  ]
  return allow.some((p) => url.startsWith(p))
}

function die(msg) {
  console.error(`generate-release-manifest: ${msg}`)
  process.exit(1)
}

function walkFiles(dir, rel = '') {
  const out = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const entryRel = rel ? `${rel}/${entry.name}` : entry.name
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) out.push(...walkFiles(full, entryRel))
    else if (entry.isFile()) out.push(entryRel)
  }
  return out
}

function sha256File(full) {
  const hash = createHash('sha256')
  hash.update(readFileSync(full))
  return hash.digest('hex')
}

if (!existsSync(distDir)) {
  die('dist/ missing — run npm run build first')
}

mkdirSync(outDir, { recursive: true })

const files = walkFiles(distDir).sort()
if (files.length === 0) die('dist/ is empty')

const indexHtml = path.join(distDir, 'index.html')
if (!existsSync(indexHtml)) die('dist/index.html missing')
const html = readFileSync(indexHtml, 'utf8')
if (!/Content-Security-Policy/i.test(html)) die('dist/index.html missing CSP meta')
if (!/connect-src 'none'/.test(html)) die("dist/index.html missing connect-src 'none'")
if (FORBIDDEN_CDN_HINTS.test(html)) die('dist/index.html references forbidden CDN/analytics')

const remoteHits = []
for (const rel of files) {
  if (!/\.(html|js|css|svg|map)$/i.test(rel)) continue
  const text = readFileSync(path.join(distDir, rel), 'utf8')
  if (FORBIDDEN_CDN_HINTS.test(text)) {
    remoteHits.push(`${rel}: forbidden CDN/analytics string`)
  }
  const matches = text.match(REMOTE_URL) ?? []
  for (const m of matches) {
    if (isBenignEmbeddedUrl(m)) continue
    remoteHits.push(`${rel}: ${m}`)
  }
}
if (remoteHits.length > 0) {
  die(`remote URL(s) in dist/:\n  ${remoteHits.slice(0, 20).join('\n  ')}`)
}

const entries = files.map((rel) => {
  const full = path.join(distDir, rel)
  const st = statSync(full)
  return {
    path: rel,
    bytes: st.size,
    sha256: sha256File(full),
  }
})

const sumsLines = entries.map((e) => `${e.sha256}  dist/${e.path}`)
const sumsPath = path.join(outDir, 'SHA256SUMS')
writeFileSync(sumsPath, `${sumsLines.join('\n')}\n`, 'utf8')

const manifest = {
  format: 'rnd-log-anonymizer-release-manifest',
  schemaVersion: 1,
  builtAt: new Date().toISOString(),
  package: {
    name: 'anonymizer',
    version: JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).version,
  },
  offline: {
    cspConnectSrcNone: true,
    noRemoteUrlsInDist: true,
    noCdnFontsOrAnalytics: true,
  },
  artifacts: entries,
  checksumsFile: 'SHA256SUMS',
  signature: {
    detachedAsc: null,
    note:
      'Set GPG_SIGN_RELEASE=1 (and configured gpg key) to attach SHA256SUMS.asc before publishing.',
  },
}

let signed = false
if (process.env.GPG_SIGN_RELEASE === '1') {
  try {
    const ascPath = path.join(outDir, 'SHA256SUMS.asc')
    if (existsSync(ascPath)) unlinkSync(ascPath)
    execFileSync('gpg', ['--batch', '--yes', '--detach-sign', '--armor', '-o', ascPath, sumsPath], {
      cwd: root,
      stdio: 'inherit',
    })
    signed = existsSync(ascPath)
    manifest.signature.detachedAsc = signed ? 'SHA256SUMS.asc' : null
  } catch (err) {
    die(`GPG_SIGN_RELEASE=1 but gpg sign failed: ${err instanceof Error ? err.message : String(err)}`)
  }
}

const manifestPath = path.join(outDir, 'release-manifest.json')
writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')

console.log(`generate-release-manifest: OK → ${path.relative(root, outDir)}`)
console.log(`  ${entries.length} dist file(s), SHA256SUMS${signed ? ' + SHA256SUMS.asc' : ' (unsigned)'}`)
