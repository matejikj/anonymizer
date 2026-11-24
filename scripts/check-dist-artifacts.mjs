#!/usr/bin/env node
/**
 * Stage 15 — dist/ must not ship profiles, fixtures, captures, or raw inputs.
 * Usage: npm run build && npm run check:dist-artifacts
 */

import { readdir, stat } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const dist = path.join(root, 'dist')

const FORBIDDEN_SUFFIXES = [
  '.pcap',
  '.pcapng',
  '.log',
  '.rnd-log-anonymizer.json',
  '.rnd-log-anonymizer-pcap.json',
]

const FORBIDDEN_DIR_NAMES = new Set(['profiles', 'fixtures', 'fuzz-corpus', 'test-results'])

async function walk(dir, rel = '') {
  const entries = await readdir(dir, { withFileTypes: true })
  const out = []
  for (const entry of entries) {
    const entryRel = rel ? `${rel}/${entry.name}` : entry.name
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (FORBIDDEN_DIR_NAMES.has(entry.name)) {
        out.push(entryRel + '/')
      }
      out.push(...(await walk(full, entryRel)))
    } else if (entry.isFile()) {
      out.push(entryRel)
    }
  }
  return out
}

function fail(msg) {
  console.error(`check:dist-artifacts FAIL: ${msg}`)
  process.exit(1)
}

async function main() {
  try {
    await stat(dist)
  } catch {
    fail('dist/ missing — run npm run build first')
  }

  const files = await walk(dist)
  const hits = []

  for (const rel of files) {
    if (rel.endsWith('/')) {
      hits.push(rel)
      continue
    }
    const lower = rel.toLowerCase()
    if (FORBIDDEN_SUFFIXES.some((s) => lower.endsWith(s))) {
      hits.push(rel)
    }
    if (lower.includes('fixture') && !lower.endsWith('.js')) {
      hits.push(rel)
    }
  }

  if (hits.length > 0) {
    fail(`forbidden artifacts in dist/:\n  ${hits.join('\n  ')}`)
  }

  console.log('check:dist-artifacts OK')
  console.log(`  scanned ${files.filter((f) => !f.endsWith('/')).length} files under dist/`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
