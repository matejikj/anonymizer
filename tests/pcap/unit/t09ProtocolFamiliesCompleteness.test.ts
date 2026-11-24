/**
 * T09 — every emitted coverage protocol id must have a non-other family
 * (except intentional generic buckets).
 */

import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'

const ROOT = join(import.meta.dirname, '../../../src/pcap')
const SCAN_DIRS = [join(ROOT, 'sanitize'), join(ROOT, 'protocols')]

/** Intentional catch-alls — must stay visible as "Other" in cs UI (Ostatní). */
const ALLOWED_OTHER = new Set(['heuristic', 'payload', 'processing-failed'])

const LITERAL_RE = /protocol:\s*'([^']+)'/g
const TEMPLATE_RE = /protocol:\s*`([^`$]+)/g

function walkTsFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    const st = statSync(path)
    if (st.isDirectory()) walkTsFiles(path, out)
    else if (name.endsWith('.ts')) out.push(path)
  }
  return out
}

function collectEmittedProtocolIds(): string[] {
  const ids = new Set<string>()
  for (const dir of SCAN_DIRS) {
    for (const file of walkTsFiles(dir)) {
      const text = readFileSync(file, 'utf8')
      for (const m of text.matchAll(LITERAL_RE)) {
        ids.add(m[1]!)
      }
      for (const m of text.matchAll(TEMPLATE_RE)) {
        // Dynamic templates: register representative samples so prefix rules stay covered.
        const tpl = m[1]!
        if (tpl.startsWith('ether-0x')) ids.add('ether-0x800')
        else if (tpl.startsWith('llc-0x')) ids.add('llc-0xaa')
        else if (tpl.startsWith('ipproto-')) ids.add('ipproto-47')
        else if (tpl.startsWith('proto-')) ids.add('proto-47')
        else if (tpl.startsWith('ipv6-routing-')) ids.add('ipv6-routing-0')
        else if (tpl.startsWith('ipv6-opt-')) ids.add('ipv6-opt-1')
        else if (tpl.startsWith('unsupported:')) ids.add('unsupported:ssdp')
      }
    }
  }
  // Engine emits unsupported:<name> dynamically — ensure catalog names are covered.
  ids.add('unsupported:mgcp')
  ids.add('unsupported:ssdp')
  ids.add('unsupported:h248')
  return [...ids].sort()
}

describe('T09 protocol family completeness', () => {
  it('assigns a non-other family to every emitted protocol id', () => {
    const ids = collectEmittedProtocolIds()
    expect(ids.length).toBeGreaterThan(50)
    const orphans: string[] = []
    for (const id of ids) {
      const family = familyForProtocol(id)
      if (family.familyId === 'other' && !ALLOWED_OTHER.has(id)) {
        orphans.push(id)
      }
    }
    expect(orphans, `Missing family mapping for: ${orphans.join(', ')}`).toEqual([])
  })

  it('keeps intentional generics in other and marks unsupported as probable', () => {
    expect(familyForProtocol('heuristic').familyId).toBe('other')
    expect(familyForProtocol('payload').familyId).toBe('other')
    expect(familyForProtocol('unsupported:ssdp')).toMatchObject({
      familyId: 'identified-unsupported',
      probable: true,
    })
    expect(familyForProtocol('sip-multipart').familyId).toBe('sip')
    expect(familyForProtocol('tls-serverhello').familyId).toBe('tls')
  })
})
