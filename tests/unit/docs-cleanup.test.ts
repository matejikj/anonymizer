import { readFileSync, readdirSync, statSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const root = join(fileURLToPath(new URL('../..', import.meta.url)))
const srcDir = join(root, 'src')

function readSrc(rel: string): string {
  return readFileSync(join(srcDir, rel), 'utf8')
}

describe('Production documentation and cleanup guards', () => {
  it('removed empty architectural PCAP directories', () => {
    for (const dir of [
      'pcap/persistence',
      'pcap/workers',
      'pcap/validation',
      'pcap/session',
    ]) {
      expect(() => statSync(join(srcDir, dir))).toThrow()
    }
    // protocols/application is a live module tree (SIP/SDP/RTP), not an empty stub.
    expect(() => statSync(join(srcDir, 'pcap/protocols/application'))).not.toThrow()
  })

  it('removed dead export hydration and deprecated session helpers', () => {
    expect(() => readFileSync(join(srcDir, 'pcap/export/exportHydration.ts'))).toThrow()
    expect(readSrc('pcap/ui/pcapSession.ts')).not.toMatch(/getPacketRowInfo/)
    expect(() => readFileSync(join(srcDir, 'features/workspace/WorkspaceToolbar.tsx'))).toThrow()
    expect(() => statSync(join(srcDir, 'features/workspace/WorkspaceCommandStrip.tsx'))).not.toThrow()
  })

  it('production PCAP load uses worker orchestration, not legacy sync analyze', () => {
    const load = readSrc('pcap/ui/pcapLoadController.ts')
    expect(load).toContain('orchestrateViaWorkers')
    expect(load).not.toMatch(/analyzePackets\s*\(/)
    expect(load).not.toMatch(/window\.confirm/)
  })

  it('production PCAP export has no sync buildCaptureFromPlan fallback in worker client', () => {
    const client = readSrc('pcap/export/incrementalExportWorkerClient.ts')
    expect(client).not.toMatch(/buildCaptureFromPlan\s*\(/)
    expect(client).toMatch(/build-incremental/)
  })

  it('PCAP profile schema no longer defines editable ruleset Zod objects', () => {
    const schema = readSrc('pcap/profile/schema.ts')
    expect(schema).not.toMatch(/PcapProfileSchema/)
    expect(schema).not.toMatch(/validatePcapRuleset/)
    expect(schema).toMatch(/DerivedPcapPolicyView/)
  })

  it('canonical levels live in pcapAnonymizationLevel — top-bar select delegates to setPcapAnonymizationLevel', () => {
    for (const rel of ['pcap/ui/PcapEmptyDropzone.tsx', 'pcap/ui/PcapInspector.tsx']) {
      const src = readSrc(rel)
      expect(src).toMatch(/activePcapLevel/)
      expect(src).not.toMatch(/applyBuiltinPcapPreset/)
      expect(src).not.toMatch(/metadataPolicy/)
      expect(src).not.toMatch(/unsupportedPolicy/)
      expect(src).not.toMatch(/payloadPolicy:\s*'truncate-unsupported'/)
    }
    const levelSelect = readSrc('pcap/ui/PcapAnonymizationLevelSelect.tsx')
    expect(levelSelect).toMatch(/setPcapAnonymizationLevel/)
    expect(levelSelect).toMatch(/aria-busy/)
    expect(levelSelect).toMatch(/aria-live/)
  })

  it('only README.md is markdown at repo root; src markdown is UI i18n only', () => {
    const rootMd = readdirSync(root).filter((name) => name.endsWith('.md'))
    expect(rootMd.sort()).toEqual(['README.md'])
    expect(() => statSync(join(root, 'ANONYMIZER.md'))).toThrow()
    expect(() => statSync(join(root, 'docs'))).toThrow()
    const allowedSrcMd = new Set(['src/i18n/anonymizationDocs.cs.md'])
    const stack = ['src']
    while (stack.length) {
      const rel = stack.pop()!
      const dir = join(root, rel)
      for (const name of readdirSync(dir)) {
        const child = `${rel}/${name}`
        const full = join(root, child)
        if (statSync(full).isDirectory()) stack.push(child)
        else if (name.endsWith('.md')) expect(allowedSrcMd.has(child)).toBe(true)
      }
    }
  })

  it('does not track generated binary fixtures under tests/', () => {
    const tracked = execSync('git ls-files tests', { cwd: root, encoding: 'utf8' })
      .split('\n')
      .filter(Boolean)
    const blocked = tracked.filter((p) => {
      if (p.startsWith('tests/e2e/fixtures/') && p !== 'tests/e2e/fixtures/.gitkeep') return true
      if (p.startsWith('tests/pcap/fixtures/fuzz-corpus/')) return true
      if (p.startsWith('tests/pcap/fixtures/generated/')) return true
      if (p.startsWith('tests/performance/fixtures/')) return true
      if (
        p.startsWith('tests/performance/results/') &&
        p !== 'tests/performance/results/.gitkeep' &&
        p !== 'tests/performance/results/max-size-baseline.json' &&
        p !== 'tests/performance/results/capacity-evidence.json'
      ) {
        return true
      }
      return false
    })
    expect(blocked).toEqual([])
  })

  it('README documents text/PCAP limits without obsolete construction docs', () => {
    const readme = readFileSync(join(root, 'README.md'), 'utf8')
    expect(readme).toMatch(/90 MiB/)
    expect(readme).toMatch(/100 MiB/)
    expect(readme).not.toMatch(/ANONYMIZER\.md/)
    expect(readme).not.toMatch(/ARCHITECTURE\.md/)
    expect(readme).not.toMatch(/PRODUCTION_PROFILE_README/)
    expect(readme).not.toMatch(/pcap-\*-example/)
    expect(readme).not.toMatch(/[áčďéěíňóřšťúůýžÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ]/)
  })

  it('dist/ contains no profiles, fixtures, or capture inputs after build', () => {
    const dist = join(root, 'dist')
    expect(() => statSync(dist)).not.toThrow()
    const forbiddenSuffixes = ['.pcap', '.pcapng', '.rnd-log-anonymizer-pcap.json']
    const stack = ['']
    while (stack.length) {
      const rel = stack.pop()!
      const dir = rel ? join(dist, rel) : dist
      for (const name of readdirSync(dir)) {
        const child = rel ? `${rel}/${name}` : name
        const full = join(dist, child)
        if (statSync(full).isDirectory()) {
          expect(name).not.toBe('profiles')
          expect(name).not.toBe('fixtures')
          stack.push(child)
        } else {
          for (const suffix of forbiddenSuffixes) {
            expect(child.toLowerCase().endsWith(suffix)).toBe(false)
          }
        }
      }
    }
  })
})
