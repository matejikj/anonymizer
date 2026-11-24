#!/usr/bin/env node
/**
 * Enterprise step 14 — offline release checklist (CI gate).
 * Fails when CSP / lockfile / network guards / CDN policy drift.
 *
 * When dist/ exists, also verifies production HTML CSP and scans assets for remote URLs.
 * When release/sbom.cdx.json exists, validates CycloneDX shape.
 */
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

const checks = []
function ok(name, detail = '') {
  checks.push({ name, ok: true, detail })
}
function fail(name, detail) {
  checks.push({ name, ok: false, detail })
}

function walkFiles(dir, rel = '', out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const entryRel = rel ? `${rel}/${entry.name}` : entry.name
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue
      walkFiles(full, entryRel, out)
    } else if (entry.isFile()) out.push(entryRel)
  }
  return out
}

// 1. Lockfile pinning
if (existsSync(path.join(root, 'package-lock.json'))) {
  ok('package-lock.json present (dependency pinning)')
} else {
  fail('package-lock.json present', 'missing — installs are not reproducible')
}

// 2. Network API source guard
const netScript = path.join(root, 'scripts/check-no-network-apis.mjs')
if (!existsSync(netScript)) {
  fail('check-no-network-apis.mjs', 'script missing')
} else {
  const r = spawnSync(process.execPath, [netScript], { cwd: root, encoding: 'utf8' })
  if (r.status === 0) ok('check:network', (r.stdout || '').trim().split('\n').pop() ?? '')
  else fail('check:network', (r.stderr || r.stdout || 'failed').trim())
}

// 3. Vite CSP plugin
const viteCfg = readFileSync(path.join(root, 'vite.config.ts'), 'utf8')
if (viteCfg.includes("connect-src 'none'") && viteCfg.includes('Content-Security-Policy')) {
  ok("vite CSP connect-src 'none'")
} else {
  fail("vite CSP connect-src 'none'", 'vite.config.ts missing production CSP')
}

// 4. No CDN / analytics in product sources + index.html
const FORBIDDEN =
  /fonts\.googleapis|fonts\.gstatic|googletagmanager|google-analytics|gtag\(|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare|https?:\/\/(?!localhost)/i
const scanRoots = ['index.html', 'src']
let cdnHits = []
for (const rel of scanRoots) {
  const full = path.join(root, rel)
  if (!existsSync(full)) continue
  const st = statSync(full)
  const files = st.isDirectory()
    ? walkFiles(full).filter((f) => /\.(ts|tsx|js|jsx|css|html|svg)$/.test(f)).map((f) => path.join(rel, f))
    : [rel]
  for (const f of files) {
    const text = readFileSync(path.join(root, f), 'utf8')
    // Allow https in comments inside check scripts already excluded; strip block/line comments lightly for ts/tsx
    const stripped = text
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(^|[^:])\/\/.*$/gm, '$1')
    if (FORBIDDEN.test(stripped)) cdnHits.push(f)
  }
}
if (cdnHits.length === 0) ok('no CDN/analytics/remote URLs in index.html + src/')
else fail('no CDN/analytics/remote URLs in index.html + src/', cdnHits.slice(0, 15).join(', '))

// 5. SBOM tooling present
if (existsSync(path.join(root, 'scripts/generate-sbom.mjs'))) {
  ok('generate-sbom.mjs present')
} else {
  fail('generate-sbom.mjs present', 'missing')
}

const sbomPath = path.join(root, 'release/sbom.cdx.json')
if (existsSync(sbomPath)) {
  try {
    const sbom = JSON.parse(readFileSync(sbomPath, 'utf8'))
    if (sbom.bomFormat === 'CycloneDX' || Array.isArray(sbom.components)) {
      ok('release/sbom.cdx.json CycloneDX shape')
    } else {
      fail('release/sbom.cdx.json CycloneDX shape', 'unexpected SBOM structure')
    }
  } catch (e) {
    fail('release/sbom.cdx.json CycloneDX shape', String(e))
  }
} else {
  ok('release/sbom.cdx.json (optional until npm run sbom)', 'not generated yet — run npm run sbom before publish')
}

// 6. dist/ production checks when built
const distHtml = path.join(root, 'dist/index.html')
if (existsSync(distHtml)) {
  const html = readFileSync(distHtml, 'utf8')
  if (/connect-src 'none'/.test(html) && /Content-Security-Policy/i.test(html)) {
    ok("dist/index.html CSP connect-src 'none'")
  } else {
    fail("dist/index.html CSP connect-src 'none'", 'rebuild required')
  }
  if (FORBIDDEN.test(html)) fail('dist/index.html offline', 'remote/CDN reference found')
  else ok('dist/index.html offline')
} else {
  ok('dist/ (optional until build)', 'not built — verify runs build before this check in CI')
}

// 7. Release checklist doc
if (existsSync(path.join(root, 'docs/RELEASE_CHECKLIST.md'))) {
  ok('docs/RELEASE_CHECKLIST.md present')
} else {
  fail('docs/RELEASE_CHECKLIST.md present', 'missing')
}

// 8. T70 free-text vocabulary artifact (offline allowlist)
{
  const freeTextDir = path.join(root, 'src/engine/freeText')
  const generatedPath = path.join(freeTextDir, 'vocabulary.generated.ts')
  const licensePath = path.join(freeTextDir, 'vocabulary.license.json')
  if (!existsSync(generatedPath)) {
    fail('T70 vocabulary.generated.ts', 'missing — run npm run vocab:build')
  } else if (!existsSync(licensePath)) {
    fail('T70 vocabulary.license.json', 'missing — run npm run vocab:build')
  } else {
    const gen = readFileSync(generatedPath, 'utf8')
    const hashMatch = /FREE_TEXT_VOCABULARY_HASH = "([0-9a-f]+)"/.exec(gen)
    const binMatch = /FREE_TEXT_VOCABULARY_BIN_NAME = "([^"]+)"/.exec(gen)
    const builtMatch = /FREE_TEXT_VOCABULARY_BUILT_AT = "([^"]+)"/.exec(gen)
    const maxAgeMatch = /FREE_TEXT_VOCABULARY_MAX_AGE_DAYS = (\d+)/.exec(gen)
    const hash = hashMatch?.[1]
    const binName = binMatch?.[1]
    const builtAt = builtMatch?.[1]
    const maxAgeDays = Number(maxAgeMatch?.[1] ?? 180)
    if (!hash || !binName) {
      fail('T70 vocabulary.generated.ts parse', 'hash/bin name missing')
    } else {
      const binPath = path.join(freeTextDir, binName)
      if (!existsSync(binPath)) {
        fail('T70 vocabulary.<hash>.bin', `missing ${binName} — run npm run vocab:build`)
      } else {
        const bytes = readFileSync(binPath)
        const actual = createHash('sha256').update(bytes).digest('hex').slice(0, 12)
        if (actual !== hash) {
          fail('T70 vocabulary hash match', `bin sha ${actual} != generated ${hash}`)
        } else if (bytes.length < 16 || String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]) !== 'FTV1') {
          fail('T70 vocabulary.bin magic', 'expected FTV1 header')
        } else {
          ok('T70 vocabulary.bin present + hash match', `${binName} (${bytes.length} B)`)
        }
      }
      if (builtAt) {
        const ageMs = Date.now() - Date.parse(builtAt)
        const ageDays = ageMs / (24 * 60 * 60 * 1000)
        if (!Number.isFinite(ageDays) || ageDays < 0) {
          fail('T70 vocabulary age', `invalid builtAt ${builtAt}`)
        } else if (ageDays > maxAgeDays) {
          fail(
            'T70 vocabulary age',
            `${ageDays.toFixed(0)}d old > ${maxAgeDays}d — regenerate (npm run vocab:build)`,
          )
        } else {
          ok('T70 vocabulary age', `${ageDays.toFixed(1)}d / max ${maxAgeDays}d`)
        }
      }
      try {
        const lic = JSON.parse(readFileSync(licensePath, 'utf8'))
        if (lic.license && lic.hash === hash) ok('T70 vocabulary.license.json', lic.license)
        else fail('T70 vocabulary.license.json', 'hash/license mismatch')
      } catch (e) {
        fail('T70 vocabulary.license.json', String(e))
      }
    }
  }
}

const failed = checks.filter((c) => !c.ok)
for (const c of checks) {
  const mark = c.ok ? 'OK' : 'FAIL'
  console.log(`  [${mark}] ${c.name}${c.detail ? ` — ${c.detail}` : ''}`)
}

if (failed.length > 0) {
  console.error(`check-offline-release: FAILED (${failed.length} check(s))`)
  process.exit(1)
}
console.log(`check-offline-release: OK (${checks.length} checks)`)
