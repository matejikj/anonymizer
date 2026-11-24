#!/usr/bin/env node
/**
 * Correlation release artifact packer.
 * Ships: anonymizer dist/ + non-identifying test reports.
 * FORBIDDEN: mapping bundles, passphrases, decrypted maps, large fixtures, AI reports with originals.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const outDir = path.join(root, 'tests/performance/results/correlation-release-artifact')
const resultsDir = path.join(root, 'tests/performance/results')
const distDir = path.join(root, 'dist')

const FORBIDDEN_NAME =
  /(rnd-mapping-bundle|passphrase|decrypted|maximum-90mib|maximum-100mib|\.eml$|ai-report|originals)/i

function die(msg) {
  console.error(`correlation-pack-artifact: ${msg}`)
  process.exit(1)
}

function copyFileSafe(src, dest) {
  const base = path.basename(src)
  if (FORBIDDEN_NAME.test(base)) {
    die(`refusing forbidden artifact name: ${base}`)
  }
  fs.mkdirSync(path.dirname(dest), { recursive: true })
  fs.copyFileSync(src, dest)
}

if (!fs.existsSync(distDir)) {
  die('dist/ missing — run npm run build first')
}

fs.rmSync(outDir, { recursive: true, force: true })
fs.mkdirSync(outDir, { recursive: true })

// Copy dist (build only)
const distOut = path.join(outDir, 'dist')
fs.cpSync(distDir, distOut, { recursive: true })

// Collect non-identifying JSON reports only
const reportOut = path.join(outDir, 'reports')
fs.mkdirSync(reportOut, { recursive: true })

const allowReport = (name) =>
  /^(max-size-|correlation-|pcap-capacity-|text-pipeline-|detection-worker-|baseline-).*\.json$/i.test(name) && !FORBIDDEN_NAME.test(name)

if (fs.existsSync(resultsDir)) {
  for (const name of fs.readdirSync(resultsDir)) {
    if (!allowReport(name)) continue
    copyFileSafe(path.join(resultsDir, name), path.join(reportOut, name))
  }
}

// Write sanitized summary (no originals / aliases / passphrases)
const summary = {
  format: 'rnd-log-anonymizer-correlation-release-summary',
  schemaVersion: 1,
  builtAt: new Date().toISOString(),
  includes: {
    dist: true,
    reports: fs.existsSync(reportOut) ? fs.readdirSync(reportOut) : [],
  },
  guarantees: {
    noMappingBundle: true,
    noPassphrase: true,
    noDecryptedMapping: true,
    noMaximumFixtures: true,
    noAiReportWithOriginals: true,
  },
  adapters: {
    text: true,
    pcap: true,
  },
}

fs.writeFileSync(path.join(outDir, 'correlation-summary.json'), `${JSON.stringify(summary, null, 2)}\n`)

// Final scan of packed tree
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (FORBIDDEN_NAME.test(entry.name)) {
      die(`packed tree contains forbidden name: ${path.relative(outDir, full)}`)
    }
    if (entry.isDirectory()) walk(full)
  }
}
walk(outDir)

console.log(`correlation-pack-artifact: OK → ${path.relative(root, outDir)}`)
console.log(`  dist + ${summary.includes.reports.length} report file(s) + correlation-summary.json`)
