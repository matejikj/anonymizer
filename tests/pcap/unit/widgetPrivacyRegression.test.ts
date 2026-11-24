import { describe, expect, it } from 'vitest'
import { MappingAuthority } from '../../../src/mapping/mappingAuthority'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { processCapture, buildPlanFromSession, identitiesFromDiscovery } from '../../../src/pcap/processing/processingPipeline'
import { createPresetProfile, profileToSanitizationPolicy } from '../../../src/pcap/profile/presets'
import { resolveSnapshotWithMappingClosure } from '../../../src/pcap/plan/mappingClosureValidation'
import { runIncrementalExport } from '../../../src/pcap/export/incremental/incrementalExportEngine'
import { buildEthIpUdp, buildEthIpTcp, envelope } from '../fixtures/voipCorpus'
import { classicHeader } from '../helpers/diagnosticPipeline'
import { recomputeChecksums } from '../../../src/pcap/checksums/engine'
import { computeChecksum, onesComplementSum, writeChecksum } from '../../../src/pcap/checksums/onesComplement'
import { encodeNetbiosFirstLevel, joinNetbiosName, decodeNetbiosFirstLevel } from '../../../src/pcap/sanitize/netbiosNameCodec'

const ascii = (s: string) => new TextEncoder().encode(s)
const text = (b: Uint8Array) => new TextDecoder('latin1').decode(b)
const src = [10, 20, 30, 40]
const dst = [10, 20, 30, 41]

async function exportFrames(frames: Uint8Array[], level: 'diagnostic' | 'high-privacy') {
  const blob = new Blob([writeClassicPcap({ header: classicHeader(), packets: frames.map((f, i) => envelope(f, i)) })])
  const profile = createPresetProfile(level)
  const generationId = 'widget-regression'
  const sourceId = 'synthetic'
  const session = await processCapture({ blob, fileName: 'synthetic.pcap', format: CaptureFormat.ClassicPcap,
    policy: profileToSanitizationPolicy(profile), generationId, sourceId })
  const authority = new MappingAuthority(profile.mapping)
  const { snapshot, unresolvedFailures } = await resolveSnapshotWithMappingClosure({
    generationId, sourceId, identities: identitiesFromDiscovery(session.discovery), intents: session.discovery.intents,
    resolve: async identities => {
      const resolved = authority.resolve({ generationId, sourceId, identities })
      if (!resolved.ok) throw new Error(resolved.code)
      return resolved.snapshot
    },
  })
  expect(unresolvedFailures).toEqual([])
  const plan = buildPlanFromSession(session, snapshot, profile)
  const built = await runIncrementalExport({ plan, descriptors: session.descriptors, sourceBlob: blob })
  expect(built.validationValid).toBe(true)
  const exported = readClassicPcap(await new Blob([...built.chunks]).arrayBuffer())
  return { packets: exported.packets, plan, session }
}

describe('widget capture privacy regressions', () => {
  it.each(['diagnostic', 'high-privacy'] as const)('%s maps the NetBIOS datagram source at RFC 1002 offset 4', async level => {
    const payload = new Uint8Array(14 + 34 * 2 + 10)
    payload.set([0x11, 0x02, 0x12, 0x34, ...src, 0, 138, 0, payload.length - 14, 0, 0])
    for (const pos of [14, 48]) {
      payload[pos] = 32
      payload.set(encodeNetbiosFirstLevel(joinNetbiosName('WORKSTATION', 0x00)!)!, pos + 1)
    }
    payload.fill(0x61, 82)
    const { packets } = await exportFrames([buildEthIpUdp(src, dst, 138, 138, payload)], level)
    expect(packets).toHaveLength(1)
    const out = packets[0]!.data
    expect(out.subarray(46, 50)).toEqual(out.subarray(26, 30))
    expect(out.subarray(46, 50)).not.toEqual(new Uint8Array(src))
    expect(out.subarray(50, 56)).toEqual(payload.subarray(8, 14))
    expect(decodeNetbiosFirstLevel(out.subarray(57, 89))).not.toBeNull()
    expect(out[89]).toBe(0)
    expect(out.subarray(124)).not.toEqual(payload.subarray(82))
  })

  it.each([20, 24])('finalizes the quoted IPv4 header (%i bytes) before the enclosing ICMP checksum', ihl => {
    const quoted = new Uint8Array(ihl + 8)
    quoted[0] = 0x40 | (ihl / 4)
    quoted[3] = quoted.length
    quoted[8] = 64
    quoted[9] = 17
    quoted.set(src, 12)
    quoted.set(dst, 16)
    if (ihl > 20) quoted.set([1, 1, 1, 1], 20)
    writeChecksum(quoted, 10, computeChecksum(quoted, 0, ihl, 10))
    const icmp = new Uint8Array(8 + quoted.length)
    icmp[0] = 3
    icmp[1] = 3
    icmp.set(quoted, 8)
    writeChecksum(icmp, 2, computeChecksum(icmp, 0, icmp.length, 2))
    const frame = buildEthIpUdp(src, dst, 1, 2, new Uint8Array(icmp.length - 8))
    frame[23] = 1
    frame.set(icmp, 34)
    const originalData = frame.slice()
    const patches = [{ offset: 54, data: new Uint8Array([10, 50, 60, 70]) }]
    frame.set(patches[0]!.data, 54)
    recomputeChecksums(frame, { linkType: 1, capturedLen: frame.length, originalLen: frame.length, patches, originalData })
    expect(onesComplementSum(frame, 42, 42 + ihl)).toBe(0xffff)
    expect(onesComplementSum(frame, 34, frame.length)).toBe(0xffff)
  })

  it('keeps fail-closed TCP overlap drops in the frozen production plan', async () => {
    const request = 'GET /customer/alice HTTP/1.1\r\nHost: private.example\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n'
    const frames = [request, request.replace('alice', 'bobby')].map(s => buildEthIpTcp(src, dst, 40000, 8000, 1000, ascii(s)))
    const { packets, plan, session } = await exportFrames(frames, 'high-privacy')
    expect(session.reassembly.overlays.size).toBe(2)
    expect(plan.packets.every(p => p.drop)).toBe(true)
    expect(packets).toHaveLength(0)
  })

  it.each(['diagnostic', 'high-privacy'] as const)('%s redacts HTML identities and fingerprints across TCP segments', async level => {
    const body = '<html>&quot;420777123456&quot; &lt;sip:420777123456@private.example&gt; Version: PRIVATE-BUILD-2026</html>'
    const message = `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ${body.length}\r\n\r\n${body}`
    const split = message.indexOf('&lt;') + 4
    const frames = [buildEthIpTcp(src, dst, 8000, 40000, 1000, ascii(message.slice(0, split))),
      buildEthIpTcp(src, dst, 8000, 40000, 1000 + split, ascii(message.slice(split)))]
    const { packets } = await exportFrames(frames, level)
    expect(packets).toHaveLength(2)
    const output = packets.map(p => text(p.data.subarray(54))).join('')
    expect(output).toContain(`Content-Length: ${body.length}`)
    expect(output.length).toBe(message.length)
    for (const value of ['420777123456', 'private.example', 'PRIVATE-BUILD-2026']) expect(output).not.toContain(value)
  })

  it('uses the high-privacy policy for reassembled text/plain bodies', async () => {
    const body = 'private free text with unrecognized customer name'
    const message = `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\n\r\n${body}`
    const { packets } = await exportFrames([buildEthIpTcp(src, dst, 8000, 40000, 1000, ascii(message))], 'high-privacy')
    expect(text(packets[0]!.data)).not.toContain(body)
  })

  it('redacts SIP display names in diagnostic log messages as well as URI users', async () => {
    const message = '<158>Jul  7 12:30:45 host1 app remoteParty="420777123456" <sip:420777123456@10.20.30.40>\r\n'
    const { packets } = await exportFrames([buildEthIpTcp(src, dst, 40000, 514, 1000, ascii(message))], 'diagnostic')
    expect(text(packets[0]!.data)).not.toContain('420777123456')
    expect(text(packets[0]!.data)).not.toContain('10.20.30.40')
  })

  it.each(['"Alice \\"Private\\" Smith"', 'Alice Smith'])('redacts complete embedded SIP display name %s', async display => {
    const message = `<158>Jul  7 12:30:45 host1 app remoteParty=${display} <sip:12345@example.test>\r\n`
    const { packets } = await exportFrames([buildEthIpTcp(src, dst, 40000, 514, 1000, ascii(message))], 'diagnostic')
    const out = text(packets[0]!.data.subarray(54))
    expect(out).not.toMatch(/Alice|Private|Smith/)
    expect(out.length).toBe(message.length)
  })

  it.each(['diagnostic', 'high-privacy'] as const)('%s redacts undecodable NetBIOS names', async level => {
    for (const invalidAlphabet of [false, true]) {
      const raw = joinNetbiosName('ALICE', 0)!
      raw[4] = 0xc9
      const encoded = encodeNetbiosFirstLevel(raw)!
      if (invalidAlphabet) encoded[0] = 0x5a
      const payload = new Uint8Array(92)
      payload.set([0x11, 0x02, 0x12, 0x34, ...src, 0, 138, 0, 78, 0, 0])
      for (const pos of [14, 48]) {
        payload[pos] = 32
        payload.set(encoded, pos + 1)
      }
      const { packets } = await exportFrames([buildEthIpUdp(src, dst, 138, 138, payload)], level)
      const out = packets[0]!.data
      for (const pos of [57, 91]) {
        expect(out.subarray(pos, pos + 32)).not.toEqual(encoded)
        expect(decodeNetbiosFirstLevel(out.subarray(pos, pos + 32))).not.toBeNull()
      }
    }
  })

  it.each(['diagnostic', 'high-privacy'] as const)('%s redacts identifying HTTP targets and Referer values', async level => {
    const message = 'GET /customers/alice@sensitive.example HTTP/1.1\r\nHost: sensitive.example\r\nReferer: http://sensitive.example/users/alice\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n'
    const { packets } = await exportFrames([buildEthIpTcp(src, dst, 40000, 8000, 1000, ascii(message))], level)
    const out = text(packets[0]!.data.subarray(54))
    expect(out.length).toBe(message.length)
    expect(out).not.toContain('alice')
    expect(out).not.toContain('sensitive.example')
    expect(out).not.toContain('YWxpY2U6c2VjcmV0')
    expect(out).toMatch(/^GET \S+ HTTP\/1.1\r\n/)
  })
})
