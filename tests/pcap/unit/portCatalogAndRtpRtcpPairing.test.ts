/**
 * T06 — semantic port catalog, content signaling hints, RTP/RTCP pair permute.
 */

import { describe, expect, it } from 'vitest'
import {
  SessionMapping,
  DEFAULT_MAPPING_CONFIG,
} from '../../../src/pcap/anonymization/mapping'
import {
  DYNAMIC_PORT_MIN,
  isPreservedServicePort,
  shouldPreservePort,
  SEMANTIC_SERVICE_PORTS,
} from '../../../src/pcap/anonymization/portPolicy'
import { levelToMappingConfig } from '../../../src/pcap/profile/pcapAnonymizationLevel'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import {
  buildEthIpUdp,
  buildSipInviteWithSdp,
  envelope,
} from '../fixtures/voipCorpus'

function udpPortBytes(buffer: Uint8Array, port: number): boolean {
  const hi = (port >> 8) & 0xff
  const lo = port & 0xff
  for (let i = 0; i < buffer.length - 1; i++) {
    if (buffer[i] === hi && buffer[i + 1] === lo) return true
  }
  return false
}

describe('T06 semantic service catalog', () => {
  it('preserves telecom catalog ports under permute', () => {
    const mapping = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ephemeralPorts: 'permute' })
    for (const port of [2427, 2727, 2944, 2000, 4569, 1900, 3868, 1812, 2905, 5070]) {
      // 5070 is not in catalog — only via content hint below.
      if (port === 5070) continue
      expect(isPreservedServicePort(port)).toBe(true)
      expect(mapping.map('port', `udp/${port}`)).toBe(`udp/${port}`)
    }
    expect(SEMANTIC_SERVICE_PORTS.has(5060)).toBe(true)
  })

  it('preserves content-hinted SIP on 5070 in diagnostic policy', () => {
    const mapping = new SessionMapping(levelToMappingConfig('diagnostic'))
    mapping.notePortFlowHint('udp/5070', 'sip')
    expect(mapping.map('port', 'udp/5070')).toBe('udp/5070')
    expect(
      shouldPreservePort(5070, { flow: 'sip', preserveContentSignaling: true }),
    ).toBe(true)
  })

  it('permutes content-hinted SIP on 5070 in high-privacy policy', () => {
    const mapping = new SessionMapping(levelToMappingConfig('high-privacy'))
    mapping.notePortFlowHint('udp/5070', 'sip')
    const mapped = mapping.map('port', 'udp/5070')
    expect(mapped).not.toBe('udp/5070')
    const port = Number(mapped.split('/')[1])
    // 5070 is user-registered → pair-permute stays in 1024–49151.
    expect(port).toBeGreaterThanOrEqual(1024)
    expect(port).toBeLessThan(DYNAMIC_PORT_MIN)
    expect(isPreservedServicePort(port)).toBe(false)
  })

  it('discovery→mapping preserves SIP on 5070 in diagnostic export', () => {
    const payload = buildSipInviteWithSdp()
    const frame = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5070, 5070, payload)
    const result = runExportPipeline(
      [envelope(frame, 0)],
      'diagnostic',
      't06-sip-5070.pcap',
      't06-sip-5070',
      { mappingSeed: 't06-sip-5070-export' },
    )
    expect(result.discovery.portFlowHints.get('udp/5070')).toBe('sip')
    const portEntry = result.snapshot.entries.find(
      (e) => e.category === 'port' && e.canonical === 'udp/5070',
    )
    expect(portEntry?.aliases[0]?.alias).toBe('udp/5070')
    expect(udpPortBytes(new Uint8Array(result.built.buffer), 5070)).toBe(true)
  })
})

describe('T06 RTP/RTCP pair permutation', () => {
  it('preserves RTCP = RTP+1 and even RTP parity for 200 media-hinted pairs', () => {
    const mapping = new SessionMapping({
      ...DEFAULT_MAPPING_CONFIG,
      ephemeralPorts: 'permute',
    })
    const pairs: Array<{ rtp: number; rtcp: number }> = []
    for (let i = 0; i < 200; i++) {
      const rtp = DYNAMIC_PORT_MIN + i * 2
      const rtcp = rtp + 1
      mapping.notePortFlowHint(`udp/${rtp}`, 'rtp')
      mapping.notePortFlowHint(`udp/${rtcp}`, 'rtcp')
      const mappedRtp = mapping.map('port', `udp/${rtp}`)
      const mappedRtcp = mapping.map('port', `udp/${rtcp}`)
      const a = Number(mappedRtp.split('/')[1])
      const b = Number(mappedRtcp.split('/')[1])
      expect(b).toBe(a + 1)
      expect(a % 2).toBe(0)
      expect(a).not.toBe(rtp)
      expect(isPreservedServicePort(a)).toBe(false)
      pairs.push({ rtp: a, rtcp: b })
    }
    expect(new Set(pairs.map((p) => p.rtp)).size).toBe(200)
  })

  it('does not force +1 on unrelated unhinted UDP neighbors', () => {
    const mapping = new SessionMapping({
      ...DEFAULT_MAPPING_CONFIG,
      ephemeralPorts: 'permute',
    }, { seed: 't06-neighbors-solo' })
    const a = Number(mapping.map('port', `udp/${DYNAMIC_PORT_MIN}`).split('/')[1])
    const b = Number(mapping.map('port', `udp/${DYNAMIC_PORT_MIN + 1}`).split('/')[1])
    expect(b).not.toBe(a + 1)
    expect(a).not.toBe(DYNAMIC_PORT_MIN)
    expect(b).not.toBe(DYNAMIC_PORT_MIN + 1)
  })

  it('keeps explicit non-+1 a=rtcp mates session-linked', () => {
    const mapping = new SessionMapping({
      ...DEFAULT_MAPPING_CONFIG,
      ephemeralPorts: 'permute',
    }, { seed: 't06-explicit-rtcp' })
    mapping.noteMediaPortPair('udp/5004', 'udp/5006')
    const rtp = Number(mapping.map('port', 'udp/5004').split('/')[1])
    const rtcp = Number(mapping.map('port', 'udp/5006').split('/')[1])
    expect(rtp).not.toBe(5004)
    expect(rtcp).not.toBe(5006)
    expect(rtcp).not.toBe(rtp + 1)
    // Remap is stable for the session.
    expect(mapping.map('port', 'udp/5004')).toBe(`udp/${rtp}`)
    expect(mapping.map('port', 'udp/5006')).toBe(`udp/${rtcp}`)
  })

  it('is bijective for media-hinted dynamic pairs and has no fixed points', () => {
    const mapping = new SessionMapping({
      ...DEFAULT_MAPPING_CONFIG,
      ephemeralPorts: 'permute',
    })
    const seen = new Map<number, number>()
    for (let port = DYNAMIC_PORT_MIN; port < DYNAMIC_PORT_MIN + 400; port++) {
      mapping.notePortFlowHint(`udp/${port}`, port % 2 === 0 ? 'rtp' : 'rtcp')
      const mapped = Number(mapping.map('port', `udp/${port}`).split('/')[1])
      expect(mapped).not.toBe(port)
      expect(seen.has(mapped)).toBe(false)
      seen.set(mapped, port)
    }
    expect(seen.size).toBe(400)
  })
})
