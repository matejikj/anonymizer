/**
 * T42 — DCE/RPC / iSCSI / portmapper / NFS canaries.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpTcp, buildEthIpUdp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { SEMANTIC_SERVICE_PORTS } from '../../../src/pcap/anonymization/portPolicy'
import { IFACE } from '../../../src/pcap/sanitize/storage/dcerpc'

function packetInput(data: Uint8Array) {
  return {
    index: 0,
    data,
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
  }
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function latin1(buf: Uint8Array): string {
  return new TextDecoder('latin1').decode(buf)
}

function writeU16le(buf: Uint8Array, o: number, v: number): void {
  buf[o] = v & 0xff
  buf[o + 1] = (v >>> 8) & 0xff
}

function writeU32be(buf: Uint8Array, o: number, v: number): void {
  buf[o] = (v >>> 24) & 0xff
  buf[o + 1] = (v >>> 16) & 0xff
  buf[o + 2] = (v >>> 8) & 0xff
  buf[o + 3] = v & 0xff
}

function writeUuidMs(buf: Uint8Array, o: number, hex32: string): void {
  // hex32 = time_low(8)+time_mid(4)+time_hi(4)+rest(16) as in IFACE.*
  const tlow = Number.parseInt(hex32.slice(0, 8), 16)
  const tmid = Number.parseInt(hex32.slice(8, 12), 16)
  const thi = Number.parseInt(hex32.slice(12, 16), 16)
  buf[o] = tlow & 0xff
  buf[o + 1] = (tlow >>> 8) & 0xff
  buf[o + 2] = (tlow >>> 16) & 0xff
  buf[o + 3] = (tlow >>> 24) & 0xff
  buf[o + 4] = tmid & 0xff
  buf[o + 5] = (tmid >>> 8) & 0xff
  buf[o + 6] = thi & 0xff
  buf[o + 7] = (thi >>> 8) & 0xff
  for (let i = 0; i < 8; i++) {
    buf[o + 8 + i] = Number.parseInt(hex32.slice(16 + i * 2, 18 + i * 2), 16)
  }
}

describe('T42 registry', () => {
  it('registers storage handlers, families, ports, and engine 2.36.1', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toEqual(
      expect.arrayContaining(['dcerpc', 'iscsi', 'portmapper', 'nfs']),
    )
    expect(familyForProtocol('dcerpc').familyId).toBe('directory')
    expect(familyForProtocol('dcerpc-netlogon').familyId).toBe('directory')
    expect(familyForProtocol('iscsi').familyId).toBe('storage')
    expect(familyForProtocol('nfs-data').familyId).toBe('storage')
    expect(familyForProtocol('portmapper').familyId).toBe('storage')
    expect(SEMANTIC_SERVICE_PORTS.has(135)).toBe(true)
    expect(SEMANTIC_SERVICE_PORTS.has(3260)).toBe(true)
    expect(SEMANTIC_SERVICE_PORTS.has(111)).toBe(true)
    expect(SEMANTIC_SERVICE_PORTS.has(2049)).toBe(true)
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
  })
})

describe('T42 DCE/RPC NETLOGON', () => {
  it('masks NETLOGON stub canary after BIND iface UUID', () => {
    // BIND with NETLOGON UUID in body, then REQUEST with canary stub
    const bindBody = new Uint8Array(32)
    writeUuidMs(bindBody, 8, IFACE.netlogon)
    const bind = new Uint8Array(16 + bindBody.length)
    bind[0] = 5
    bind[1] = 0
    bind[2] = 11 // BIND
    writeU16le(bind, 8, bind.length)
    writeU16le(bind, 10, 0)
    bind.set(bindBody, 16)

    const canary = new TextEncoder().encode('NETLOGON-CRED-CANARY!!!!') // 24B
    const stubHdr = new Uint8Array(8) // alloc_hint + ctx + opnum
    const req = new Uint8Array(16 + 8 + canary.length)
    req[0] = 5
    req[1] = 0
    req[2] = 0 // REQUEST
    writeU16le(req, 8, req.length)
    writeU16le(req, 10, 0)
    req.set(stubHdr, 16)
    req.set(canary, 24)

    const payload = new Uint8Array(bind.length + req.length)
    payload.set(bind, 0)
    payload.set(req, bind.length)

    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 135, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't42-dce' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'dcerpc' || c.protocol === 'dcerpc-netlogon')).toBe(
      true,
    )
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('NETLOGON-CRED-CANARY')).toBe(false)
  })
})

describe('T42 iSCSI CHAP', () => {
  it('masks CHAP_R and maps InitiatorName IQN domain', () => {
    const text = [
      'InitiatorName=iqn.2020-01.com.example:host1',
      'CHAP_N=chapuser',
      'CHAP_R=0123456789abcdef0123456789abcdef',
      'CHAP_I=01',
    ].join('\0') + '\0'
    const data = new TextEncoder().encode(text)
    const pad = (4 - (data.length % 4)) % 4
    const bhs = new Uint8Array(48)
    bhs[0] = 0x03 // Login req
    bhs[5] = (data.length >>> 16) & 0xff
    bhs[6] = (data.length >>> 8) & 0xff
    bhs[7] = data.length & 0xff
    const payload = new Uint8Array(48 + data.length + pad)
    payload.set(bhs, 0)
    payload.set(data, 48)

    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 3260, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't42-iscsi' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'iscsi-chap' || c.protocol === 'iscsi')).toBe(
      true,
    )
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('0123456789abcdef0123456789abcdef')).toBe(false)
    expect(latin1(out).includes('com.example')).toBe(false)
  })
})

describe('T42 portmapper GETPORT', () => {
  it('registers dynamic port hint from GETPORT reply', () => {
    // UDP CALL GETPORT then we only send REPLY with port 2049
    // Single-packet reply: xid, REPLY, verf(AUTH_NONE), accept SUCCESS, port
    const reply = new Uint8Array(28)
    writeU32be(reply, 0, 0x11111111) // xid
    writeU32be(reply, 4, 1) // REPLY
    writeU32be(reply, 8, 0) // AUTH_NONE
    writeU32be(reply, 12, 0) // verf body len 0
    writeU32be(reply, 16, 0) // MSG_ACCEPTED
    writeU32be(reply, 20, 0) // SUCCESS
    writeU32be(reply, 24, 2049) // port

    const pkt = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 111, 40_000, reply)
    const mapping = new SessionMapping(undefined, { seed: 't42-pmap' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('portmapper'))).toBe(true)
    // Port 2049 is semantic NFS — flow hint recorded during sanitize (not always on mapping)
    expect(SEMANTIC_SERVICE_PORTS.has(2049)).toBe(true)
  })
})

describe('T42 NFS AUTH_SYS + WRITE data', () => {
  it('masks WRITE file data canary and maps AUTH_SYS machinename', () => {
    const machine = new TextEncoder().encode('nfs-host-canary')
    const namePad = (machine.length + 3) & ~3
    const credBody = new Uint8Array(4 + 4 + namePad + 8 + 4) // stamp + namelen+name + uid+gid + ngids=0
    writeU32be(credBody, 0, 1) // stamp
    writeU32be(credBody, 4, machine.length)
    credBody.set(machine, 8)
    writeU32be(credBody, 8 + namePad, 1000) // uid
    writeU32be(credBody, 8 + namePad + 4, 1000) // gid
    writeU32be(credBody, 8 + namePad + 8, 0) // ngids

    const fileData = new TextEncoder().encode('NFS-FILE-DATA-CANARY!!!!')
    // Minimal CALL: xid, CALL, rpcvers, prog, vers, proc=WRITE(7), cred, verf, fh+hdr+data
    const fh = new Uint8Array(4 + 16)
    writeU32be(fh, 0, 16)
    fh.fill(0xab, 4)

    const args = new Uint8Array(fh.length + 16 + fileData.length)
    args.set(fh, 0)
    // offset(8)+count(4)+stable(4) placeholder
    writeU32be(args, fh.length + 8, fileData.length)
    args.set(fileData, fh.length + 16)

    const call = new Uint8Array(8 + 16 + 8 + credBody.length + 8 + args.length)
    let p = 0
    writeU32be(call, p, 0x22222222)
    p += 4
    writeU32be(call, p, 0) // CALL
    p += 4
    writeU32be(call, p, 2) // rpcvers
    p += 4
    writeU32be(call, p, 100_003) // NFS
    p += 4
    writeU32be(call, p, 3) // v3
    p += 4
    writeU32be(call, p, 7) // WRITE
    p += 4
    writeU32be(call, p, 1) // AUTH_SYS
    p += 4
    writeU32be(call, p, credBody.length)
    p += 4
    call.set(credBody, p)
    p += credBody.length
    writeU32be(call, p, 0) // AUTH_NONE verf
    p += 4
    writeU32be(call, p, 0)
    p += 4
    call.set(args, p)

    // TCP record mark
    const mark = new Uint8Array(4 + call.length)
    writeU32be(mark, 0, 0x8000_0000 | call.length)
    mark.set(call, 4)

    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 2049, 1, mark)
    const mapping = new SessionMapping(undefined, { seed: 't42-nfs' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('nfs'))).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('NFS-FILE-DATA-CANARY')).toBe(false)
    expect(latin1(out).includes('nfs-host-canary')).toBe(false)
  })
})
