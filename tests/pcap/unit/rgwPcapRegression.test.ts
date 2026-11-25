/** Local customer captures stay in gitignored logs; no original values in assertions/output. */
import { existsSync, readFileSync } from 'node:fs'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { gunzipSync } from 'node:zlib'
import { describe, expect, it } from 'vitest'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { scanBytesForLeaks } from '../../../src/pcap/trust/leakScanner'
import { buildAnonymizationOutcome, coverageRowsFromProtocolSummaries } from '../../../src/pcap/coverage/anonymizationOutcome'
import { expandIpv6Canonical, isPreservedIpv6Multicast } from '../../../src/mapping/ipv6Semantics'

const execFileAsync = promisify(execFile)
async function malformedPacketNumbers(path: string): Promise<number[]> {
  const { stdout } = await execFileAsync('tshark', ['-r', path, '-Y', '_ws.malformed', '-T', 'fields', '-e', 'frame.number'])
  return stdout.trim().split(/\s+/).map(Number).filter(number => number > 0)
}

function isProtocolAddressConstant(category: string, value: string): boolean {
  if (category === 'ipv4') {
    const first = Number(value.split('.')[0])
    return value === '0.0.0.0' || value === '255.255.255.255' || (first >= 224 && first <= 239)
  }
  if (category === 'ipv6') {
    const expanded = expandIpv6Canonical(value)
    return expanded === '0:0:0:0:0:0:0:0' || (expanded != null && isPreservedIpv6Multicast(expanded))
  }
  if (category === 'mac') {
    const normalized = value.toLowerCase()
    // IPv6 multicast MACs (33:33) are mapped, including solicited-node identities.
    return normalized === '00:00:00:00:00:00'
      || (!normalized.startsWith('33:33:') && (Number.parseInt(normalized.slice(0, 2), 16) & 1) !== 0)
  }
  return false
}

for (const [name, count] of [
  ['MP_Pro_RGW_test_20261120a.pcap.gz', 32621],
  ['MP_Pro_RGW_test_20261120b.pcap.gz', 90255],
] as const) {
  const path = new URL(`../../../logs/${name}`, import.meta.url)
  describe.skipIf(!existsSync(path))(`${name} local regression`, () => {
    for (const level of ['diagnostic', 'high-privacy'] as const) {
      it(`${level}: valid export, no known identity leaks, informational outcome`, { timeout: 240_000 }, async () => {
        const raw = gunzipSync(readFileSync(path))
        const buffer = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength)
        const { packets } = readClassicPcap(buffer)
        expect(packets.length).toBe(count)
        const result = runExportPipeline(packets, level, name.slice(0, -3), `rgw-${level}`, {
          mappingSeed: 'rgw-local-regression', verifyLeaks: true,
          onStage: stage => console.info(JSON.stringify({ file: name, level, stage })),
        })
        const { built, plan, discovery } = result
        expect(built.validationValid).toBe(true)
        expect(built.validationIssueCount).toBe(0)
        expect(built.packets.length).toBe(count - plan.droppedPacketNumbers.length)
        if (level === 'diagnostic') {
          expect(built.packets.length).toBe(count)
          expect(built.packets.every((packet, index) => packet.capturedLength === packets[index]!.capturedLength)).toBe(true)
        }
        const leakScan = scanBytesForLeaks({
          packets: built.packets.map((packet, index) => ({ packetIndex: index, packetNumber: packet.packetNumber, bytes: packet.data })),
          // Empty/broadcast and policy-preserved multicast are protocol constants.
          // Scan every other discovered identity independently of the plan's patches.
          originals: discovery.analysis.entities
            .filter(entity => !isProtocolAddressConstant(entity.category, entity.value))
            .map((entity) => ({ category: entity.category, value: entity.value, packetNumber: 0 })),
        })
        // Length-preserving patches/truncation do not relocate source bytes. Binary
        // patterns can coincide in new aliases/checksums; a surviving source value
        // must still match its original location. Text matches are always failures.
        const retainedLeaks = (leakScan.positions ?? []).filter(hit => {
          if (hit.kind === 'text') return true
          const output = built.packets[hit.packetIndex]!.data
          const original = packets[built.packets[hit.packetIndex]!.packetNumber - 1]!.data
          return output.subarray(hit.offset, hit.offset + hit.length)
            .every((byte, index) => original[hit.offset + index] === byte)
        })
        expect(retainedLeaks.length).toBe(0)
        expect(plan.leakRemediation?.residualLeakHits).toBe(0)
        const report = JSON.parse(result.reportJson)
        expect(report.gate).not.toBe('NOT_AI_READY')
        const outcome = buildAnonymizationOutcome({
          protocols: coverageRowsFromProtocolSummaries(discovery.unifiedCoverage.byProtocol, level),
          gate: report.gate, plan, preset: level,
        })
        expect(outcome.diagnosticImpact.needsAttentionFamilyCount).toBe(0)
        const text = [outcome.summarySentence, outcome.assuranceNote, ...outcome.families.flatMap(family => [
          family.stateLabel, family.explanation, family.recommendation,
          ...family.protocols.flatMap(protocol => [protocol.method, protocol.check]),
        ])].join(' ')
        expect(text).not.toMatch(/ověřte|zkontrol|vyžaduje kontrolu|k prověření|NOT AI READY|Před předáním AI je potřeba kontrola/i)
        // Independently open the whole export with Wireshark's reader. Redacted
        // application messages may be undecodable; record that diagnostic impact
        // separately from the PCAP container validity checked above.
        const directory = await mkdtemp(join(tmpdir(), 'rgw-pcap-'))
        let newlyUndecodablePackets = 0
        try {
          const outputPath = join(directory, 'anonymized.pcap')
          await writeFile(outputPath, new Uint8Array(built.buffer))
          const before = new Set(await malformedPacketNumbers(path.pathname))
          const after = await malformedPacketNumbers(outputPath)
          const newlyMalformed = after.map(number => built.packets[number - 1]!.packetNumber)
            .filter(number => !before.has(number))
          newlyUndecodablePackets = newlyMalformed.length
        } finally {
          await rm(directory, { recursive: true, force: true })
        }
        console.info(JSON.stringify({ file: name, level, inputPackets: count, outputPackets: built.packets.length,
          gate: report.gate, retainedLeakHits: retainedLeaks.length,
          coincidentalBinaryMatches: leakScan.leakHits - retainedLeaks.length, changedPackets: built.changedPackets,
          maskedBytes: plan.maskedByteCount, droppedPackets: plan.droppedPacketNumbers.length,
          newlyUndecodablePackets,
        }))
      })
    }
  })
}
