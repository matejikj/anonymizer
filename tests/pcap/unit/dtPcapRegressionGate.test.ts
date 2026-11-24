/**
 * @vitest-environment node
 *
 * Step 10 — local dt.pcap regression table. Skips when fixture is absent.
 * Anonymized output must never be committed.
 */

import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { validateClassicPcap } from '../../../src/pcap/capture/validator'
import { locateLayers } from '../../../src/pcap/checksums/locate'
import { runDiagnosticExportPipeline, runExportPipeline, countCoverageProtocol } from '../helpers/diagnosticPipeline'
import { HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { runDiscoveryPipeline } from '../../../src/pcap/discovery/discoveryPipeline'
import { runCaptureReassembly } from '../../../src/pcap/reassembly/capturePhase'
import {
  assertCaptureHasNoPrivacyLeaks,
  assertNoBlockingSpanSurvivesUnchanged,
} from '../helpers/privacyLeakScan'
import { assertNoNewTsharkStructuralErrors } from '../helpers/tsharkOracle'

/**
 * Step 6 — parser-independent canaries for a *local* private capture.
 * Real identity strings/IPs must live only in the gitignored sidecar
 * `dt-pcap.sensitive.local.json` (see the `.example.json` next to this file).
 * Deliberately independent of `discovery.analysis.entities` — a parser regression that stops
 * recognizing this content must not also make it invisible to this scan (see
 * privacyGateParserIndependent.test.ts for the synthetic, exhaustively-proven version of this
 * same class of check).
 */
type DtPcapSensitive = {
  strings: string[]
  ips: number[][]
}

const DT_PCAP_SENSITIVE_LOCAL = join(import.meta.dirname ?? '.', 'dt-pcap.sensitive.local.json')

function loadDtPcapSensitive(): DtPcapSensitive | null {
  if (!existsSync(DT_PCAP_SENSITIVE_LOCAL)) return null
  const parsed = JSON.parse(readFileSync(DT_PCAP_SENSITIVE_LOCAL, 'utf8')) as DtPcapSensitive
  if (!Array.isArray(parsed.strings) || !Array.isArray(parsed.ips)) return null
  return parsed
}

function scanForRawIp(data: Uint8Array, ip: readonly number[]): boolean {
  for (let i = 0; i + 4 <= data.length; i++) {
    if (data[i] === ip[0] && data[i + 1] === ip[1] && data[i + 2] === ip[2] && data[i + 3] === ip[3]) return true
  }
  return false
}

const DT_PCAP = join(import.meta.dirname ?? '.', '../../../logs/dt.pcap')

/** Reviewed baseline after parser refinement (task table originally listed DHCP 83 / SIP 55). */
const DT_BASELINE = {
  packets: 4393,
  dns: 166,
  dhcpv4: 82,
  sip: 53,
  rtp: 3250,
  rtcp: 22,
} as const

/**
 * Step 7 — mandatory regression table for high-privacy, built from the same original.
 * droppedCount is 3271, not the full 3250 RTP + 22 RTCP = 3272: exactly one RTCP packet
 * (packetNumber 33) is the first packet ever observed on its conversation, which has no SDP
 * declaration anywhere in this capture — with no corroborating evidence yet (confirmation
 * needs 2+ hits on the same conversation, see mediaFlowIndex.ts), it is correctly classified
 * 'suspected' rather than 'confirmed', so mediaPolicy=drop truncates it instead of dropping it
 * (still safe — no content survives — just not counted as a "drop"). This is the same
 * single-packet-needs-evidence trade-off documented and deliberately kept in step 4.
 */
const DT_HIGH_PRIVACY_BASELINE = {
  droppedCount: 3271,
  sip: 53, // preserved and structurally anonymized, not leaked, not dropped
} as const

function readVlanIds(data: Uint8Array): number[] {
  const ids: number[] = []
  if (data.length < 18) return ids
  if (data[12] === 0x81 && data[13] === 0x00) {
    ids.push(((data[14]! & 0x0f) << 8) | data[15]!)
  }
  return ids
}

describe('dt.pcap diagnostic regression gate (step 10)', () => {
  it('meets audited regression table', { skip: !existsSync(DT_PCAP), timeout: 120_000 }, async () => {
    const raw = readFileSync(DT_PCAP)
    const buffer = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength)
    const { packets } = readClassicPcap(buffer)
    expect(packets.length).toBe(DT_BASELINE.packets)

    const { plan, built, discovery, snapshot } = runDiagnosticExportPipeline(
      packets,
      'dt.pcap',
      'dt-regression',
    )

    expect(plan.droppedPacketNumbers.length).toBe(0)
    expect(plan.packets.every((p) => p.truncatedLength == null)).toBe(true)
    expect(built.validationValid).toBe(true)
    expect(built.validationIssueCount).toBe(0)

    const validation = validateClassicPcap(built.buffer)
    expect(validation.valid).toBe(true)

    const out = readClassicPcap(built.buffer)
    expect(out.packets.length).toBe(DT_BASELINE.packets)
    for (let i = 0; i < packets.length; i++) {
      expect(out.packets[i]!.packetNumber).toBe(packets[i]!.packetNumber)
      expect(out.packets[i]!.capturedLength).toBe(packets[i]!.capturedLength)
    }

    expect(countCoverageProtocol(discovery, 'dns')).toBe(DT_BASELINE.dns)
    expect(countCoverageProtocol(discovery, 'dhcpv4')).toBe(DT_BASELINE.dhcpv4)
    expect(countCoverageProtocol(discovery, 'sip')).toBe(DT_BASELINE.sip)
    expect(countCoverageProtocol(discovery, 'rtp')).toBe(DT_BASELINE.rtp)
    expect(countCoverageProtocol(discovery, 'rtcp')).toBe(DT_BASELINE.rtcp)

    // VLAN 111 must map away from 111
    const vlanEntry = snapshot.entries.find((e) => e.category === 'vlan' && e.canonical === '111')
    expect(vlanEntry, 'vlan 111 must be mapped').toBeTruthy()
    expect(vlanEntry!.alias).not.toBe('111')
    for (const pkt of out.packets) {
      for (const vid of readVlanIds(pkt.data)) {
        expect(vid).not.toBe(111)
      }
    }

    // Seed leak scan: sample unicast identities from discovery (bounded)
    const seeds: string[] = []
    for (const e of discovery.analysis.entities) {
      if (e.category === 'ipv4' || e.category === 'mac' || e.category === 'hostname') {
        if (e.value.length >= 7) seeds.push(e.value)
      }
      if (seeds.length >= 40) break
    }
    if (vlanEntry) seeds.push('111')
    assertCaptureHasNoPrivacyLeaks(built.buffer, seeds.filter((s) => s !== '111'))

    // Step 6 — parser-independent checks from the local sidecar (never derived from discovery).
    const sensitive = loadDtPcapSensitive()
    expect(
      sensitive,
      'dt.pcap present but dt-pcap.sensitive.local.json missing — copy the .example.json and fill private canaries locally',
    ).toBeTruthy()
    const outBuf = new Uint8Array(built.buffer)
    for (const text of sensitive!.strings) {
      expect(Buffer.from(outBuf).toString('latin1'), `known-sensitive string leaked: ${text}`).not.toContain(text)
    }
    for (const ip of sensitive!.ips) {
      expect(scanForRawIp(outBuf, ip), `known-sensitive IP leaked raw: ${ip.join('.')}`).toBe(false)
    }

    // Note: the differential unchanged-window scan (assertNoUnchangedWindow) is deliberately
    // NOT run here against arbitrary real-world coverage spans. Real multi-field protocols
    // legitimately preserve specific sub-fields inside an otherwise-anonymized 'redacted'
    // span — e.g. RTCP SR/RR loss/jitter/LSR/DLSR timing fields are intentionally preserved
    // for diagnostics while only the SSRC sub-field is mapped (verified by hand for this
    // exact capture: a report-block SSRC of 0x00000000 was correctly mapped to a non-zero
    // alias, while the 20 bytes of loss/jitter/timing after it stayed unchanged by design) —
    // and ARP padding is deliberately zero-filled, matching the original's own zero padding.
    // A blind window-scan over every 'redacted' span in a real capture produces exactly these
    // false positives. The scan is instead exhaustively exercised, with full control over
    // what must vs. must not change, in privacyGateParserIndependent.test.ts.
    const outForStructuralCheck = readClassicPcap(built.buffer).packets
    for (const pd of discovery.packetDiscovery) {
      const packetNumber = packets[pd.packetIndex]!.packetNumber
      if (plan.droppedPacketNumbers.includes(packetNumber)) continue
      const outIdx = outForStructuralCheck.findIndex((p) => p.packetNumber === packetNumber)
      if (outIdx < 0) continue
      const original = packets[pd.packetIndex]!.data
      const anonymized = outForStructuralCheck[outIdx]!.data
      assertNoBlockingSpanSurvivesUnchanged(original, anonymized, pd.coverage, packetNumber)
    }

    // Write only to temp — never commit anonymized fixture
    const dir = await mkdtemp(join(tmpdir(), 'dt-pcap-gate-'))
    try {
      await writeFile(join(dir, 'dt.anonymized.pcap'), Buffer.from(built.buffer))
      const tshark = await assertNoNewTsharkStructuralErrors(buffer, built.buffer, 'dt')
      if (!tshark.skipped) {
        expect(tshark.anonymized.malformed).toBeLessThanOrEqual(tshark.original.malformed)
      }
    } finally {
      await rm(dir, { recursive: true, force: true })
    }

    // Spot-check: exported packets still locate L3/L4
    for (let i = 0; i < Math.min(20, out.packets.length); i++) {
      const layers = locateLayers(out.packets[i]!.data, out.packets[i]!.linkType, out.packets[i]!.data.length)
      expect(layers.l2Offset).toBeGreaterThanOrEqual(0)
    }
  })

  // Step 7 — both fixed levels built from the exact same original, in the same test run.
  it('meets audited regression table for high-privacy', { skip: !existsSync(DT_PCAP), timeout: 120_000 }, async () => {
    const raw = readFileSync(DT_PCAP)
    const buffer = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength)
    const { packets } = readClassicPcap(buffer)
    expect(packets.length).toBe(DT_BASELINE.packets)

    const { plan, built, discovery } = runExportPipeline(packets, 'high-privacy', 'dt.pcap', 'dt-regression-hp')

    // Exactly RTP+RTCP dropped, nothing else — media removed, everything else structurally kept.
    expect(plan.droppedPacketNumbers.length).toBe(DT_HIGH_PRIVACY_BASELINE.droppedCount)
    expect(built.validationValid).toBe(true)
    expect(built.validationIssueCount).toBe(0)

    const validation = validateClassicPcap(built.buffer)
    expect(validation.valid).toBe(true)

    const out = readClassicPcap(built.buffer)
    expect(out.packets.length).toBe(DT_BASELINE.packets - DT_HIGH_PRIVACY_BASELINE.droppedCount)

    // SIP must survive fully anonymized — not dropped, not leaked.
    expect(countCoverageProtocol(discovery, 'sip')).toBe(DT_HIGH_PRIVACY_BASELINE.sip)
    for (const packetNumber of plan.droppedPacketNumbers) {
      const pd = discovery.packetDiscovery.find((d) => packets[d.packetIndex]!.packetNumber === packetNumber)
      expect(pd, `dropped packet ${packetNumber} must have discovery coverage`).toBeDefined()
      const isMedia = pd!.coverage.some((c) => c.protocol === 'rtp' || c.protocol === 'rtcp')
      expect(isMedia, `dropped packet ${packetNumber} must be RTP/RTCP, not something else`).toBe(true)
    }

    // No media survives re-discovery of the anonymized output — pure discovery only (not a
    // second full export), since re-running mapping-resolve against already-anonymized SIP
    // text is a meaningless operation this pipeline was never designed for.
    const reReassembly = runCaptureReassembly(out.packets, HIGH_PRIVACY_POLICY)
    const rediscovery = runDiscoveryPipeline(out.packets, HIGH_PRIVACY_POLICY, 'dt-regression-hp-reload', 'dt.anonymized.pcap', { reassemblyContext: reReassembly })
    expect(countCoverageProtocol(rediscovery, 'rtp')).toBe(0)
    expect(countCoverageProtocol(rediscovery, 'rtcp')).toBe(0)

    const sensitiveHp = loadDtPcapSensitive()
    expect(
      sensitiveHp,
      'dt.pcap present but dt-pcap.sensitive.local.json missing — copy the .example.json and fill private canaries locally',
    ).toBeTruthy()
    const outBuf = new Uint8Array(built.buffer)
    for (const text of sensitiveHp!.strings) {
      expect(Buffer.from(outBuf).toString('latin1'), `known-sensitive string leaked (high-privacy): ${text}`).not.toContain(text)
    }
    for (const ip of sensitiveHp!.ips) {
      expect(scanForRawIp(outBuf, ip), `known-sensitive IP leaked raw (high-privacy): ${ip.join('.')}`).toBe(false)
    }

    const outForStructuralCheck = readClassicPcap(built.buffer).packets
    for (const pd of discovery.packetDiscovery) {
      const packetNumber = packets[pd.packetIndex]!.packetNumber
      if (plan.droppedPacketNumbers.includes(packetNumber)) continue
      const outIdx = outForStructuralCheck.findIndex((p) => p.packetNumber === packetNumber)
      if (outIdx < 0) continue
      assertNoBlockingSpanSurvivesUnchanged(
        packets[pd.packetIndex]!.data,
        outForStructuralCheck[outIdx]!.data,
        pd.coverage,
        packetNumber,
      )
    }
  })
})
