/**
 * T-01.B journal map ops: port aliases are transport-qualified (`udp/49154`). The u16 encoder
 * once ran `Number(alias)` on them, so every permuted UDP/TCP port was silently written as 0
 * (no incident). Synthetic packets only.
 */

import { describe, expect, it } from 'vitest'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { buildEthIpUdp, envelope } from '../fixtures/voipCorpus'

const SRC_PORT = 40000
const DST_PORT = 12345

describe('journal port encoding', () => {
  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`${level}: permuted UDP ports are written as real port numbers, never 0`, () => {
      const pkt = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], SRC_PORT, DST_PORT, new TextEncoder().encode('ping'))
      const result = runExportPipeline([envelope(pkt, 0)], level, 'ports.pcap', `ports-${level}`, {
        mappingSeed: `journal-port-encoding-${level}`,
      })
      expect(result.plan.incidents?.totalFailures ?? 0).toBe(0)

      const out = readClassicPcap(result.built.buffer).packets[0]!.data
      const src = (out[34]! << 8) | out[35]!
      const dst = (out[36]! << 8) | out[37]!
      for (const [mapped, original] of [[src, SRC_PORT], [dst, DST_PORT]] as const) {
        expect(mapped).not.toBe(0)
        expect(mapped).not.toBe(original)
        expect(mapped).toBeGreaterThanOrEqual(1024)
      }
      expect(src).not.toBe(dst)
    })
  }
})
