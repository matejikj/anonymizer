/**
 * SCTP decoder (RFC 9260) — common header + bounded chunk walk for analytics.
 */

import type { DecodeContext, DecodedNode, DecodedField, EntityCollector, ProtocolModule } from '../types'

export const IPPROTO_SCTP = 132

const CHUNK_DATA = 0
const CHUNK_INIT = 1
const CHUNK_INIT_ACK = 2
const CHUNK_SACK = 3
const CHUNK_HEARTBEAT = 4
const CHUNK_ABORT = 6
const CHUNK_COOKIE_ECHO = 10
const CHUNK_I_DATA = 64

export const sctpModule: ProtocolModule = {
  id: 'sctp',

  probe(data: Uint8Array): boolean {
    return data.length >= 12
  },

  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const fields: DecodedField[] = []
    const children: DecodedNode[] = []
    const issues: string[] = []
    const bo = ctx.baseOffset

    if (data.length < 12) {
      return {
        protocolId: 'sctp',
        range: { start: bo, end: bo + data.length },
        fields,
        children,
        issues: ['sctp-trunc'],
      }
    }

    const srcPort = (data[0]! << 8) | data[1]!
    const dstPort = (data[2]! << 8) | data[3]!
    const vtag =
      ((data[4]! << 24) | (data[5]! << 16) | (data[6]! << 8) | data[7]!) >>> 0
    const checksum =
      (data[8]! | (data[9]! << 8) | (data[10]! << 16) | (data[11]! << 24)) >>> 0

    fields.push(
      { name: 'srcPort', range: { start: bo, end: bo + 2 }, value: srcPort },
      { name: 'dstPort', range: { start: bo + 2, end: bo + 4 }, value: dstPort },
      { name: 'verificationTag', range: { start: bo + 4, end: bo + 8 }, value: vtag },
      { name: 'checksum', range: { start: bo + 8, end: bo + 12 }, value: checksum },
    )

    let pos = 12
    let chunkCount = 0
    const MAX_CHUNKS = 64
    while (pos + 4 <= data.length && chunkCount < MAX_CHUNKS) {
      const type = data[pos]!
      const flags = data[pos + 1]!
      const length = (data[pos + 2]! << 8) | data[pos + 3]!
      if (length < 4 || pos + length > data.length) {
        issues.push('sctp-chunk-trunc')
        break
      }
      fields.push({
        name: `chunk-${chunkCount}`,
        range: { start: bo + pos, end: bo + pos + length },
        value: type,
        display: `type=${type} flags=0x${flags.toString(16)} len=${length}`,
      })
      if (type === CHUNK_DATA && length >= 16) {
        const ppid =
          ((data[pos + 12]! << 24)
            | (data[pos + 13]! << 16)
            | (data[pos + 14]! << 8)
            | data[pos + 15]!)
          >>> 0
        fields.push({
          name: `chunk-${chunkCount}-ppid`,
          range: { start: bo + pos + 12, end: bo + pos + 16 },
          value: ppid,
        })
      }
      if (type === CHUNK_I_DATA && length >= 20) {
        const ppid =
          ((data[pos + 16]! << 24)
            | (data[pos + 17]! << 16)
            | (data[pos + 18]! << 8)
            | data[pos + 19]!)
          >>> 0
        fields.push({
          name: `chunk-${chunkCount}-ppid`,
          range: { start: bo + pos + 16, end: bo + pos + 20 },
          value: ppid,
        })
      }
      if (type === CHUNK_INIT || type === CHUNK_INIT_ACK) {
        // ok — sanitizer maps address params
      }
      if (type === CHUNK_HEARTBEAT || type === CHUNK_COOKIE_ECHO || type === CHUNK_ABORT) {
        // opaque / cause regions handled in sanitize
      }
      if (type === CHUNK_SACK) {
        // preserve mechanics
      }
      // Action bits: top 2 bits of type — stop processing remainder if 00/01
      const action = type >> 6
      const padded = (length + 3) & ~3
      pos += padded
      chunkCount++
      if (action === 0 || action === 1) {
        if (pos < data.length) issues.push('sctp-unknown-chunk-stop')
        break
      }
    }
    if (chunkCount >= MAX_CHUNKS) issues.push('sctp-chunk-budget')

    return {
      protocolId: 'sctp',
      range: { start: bo, end: bo + data.length },
      fields,
      children,
      issues,
    }
  },

  collect(node: DecodedNode, out: EntityCollector, packetNumber: number): void {
    for (const f of node.fields) {
      if (f.name === 'srcPort' || f.name === 'dstPort') {
        out.addPort(f.value as number, 'sctp', packetNumber)
      }
    }
  },
}
