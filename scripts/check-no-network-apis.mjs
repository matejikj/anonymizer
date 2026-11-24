#!/usr/bin/env node
/**
 * CI guard: forbid direct network APIs and remote URLs in product source.
 * ARCHITECTURE §12.1 — exceptions require explicit security review; v1 needs none.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const srcRoot = path.join(root, 'src')

const FORBIDDEN_PATTERNS = [
  { name: 'fetch(', re: /\bfetch\s*\(/ },
  { name: 'XMLHttpRequest', re: /\bXMLHttpRequest\b/ },
  { name: 'WebSocket', re: /\bWebSocket\b/ },
  { name: 'EventSource', re: /\bEventSource\b/ },
  { name: 'sendBeacon', re: /\.sendBeacon\s*\(/ },
  { name: 'importScripts remote', re: /\bimportScripts\s*\(\s*['`]https?:/i },
  { name: 'WebAssembly streaming remote', re: /\bWebAssembly\.(instantiateStreaming|compileStreaming)\s*\(/ },
  { name: 'remote http(s) URL', re: /https?:\/\//i },
]

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue
      walk(full, out)
    } else if (/\.(ts|tsx|js|jsx|css|html)$/.test(entry.name)) {
      out.push(full)
    }
  }
  return out
}

function stripComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
}

const files = walk(srcRoot)

const violations = []
for (const file of files) {
  const raw = fs.readFileSync(file, 'utf8')
  const code = stripComments(raw)
  for (const pattern of FORBIDDEN_PATTERNS) {
    if (pattern.re.test(code)) {
      violations.push(`${path.relative(root, file)}: forbidden ${pattern.name}`)
    }
  }
}

if (violations.length > 0) {
  console.error('Network API / remote URL guard failed:\n')
  for (const v of violations) console.error(`  - ${v}`)
  console.error('\nRemove the call or request an explicit security review exception.')
  process.exit(1)
}

console.log(`check-no-network-apis: OK (${files.length} files scanned)`)
