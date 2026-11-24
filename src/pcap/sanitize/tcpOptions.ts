/**
 * TCP option walk for step 7 — adjust SACK edges with the peer SEQ offset.
 */

const TCPOPT_EOL = 0
const TCPOPT_NOP = 1
const TCPOPT_MSS = 2
const TCPOPT_WSCALE = 3
const TCPOPT_SACK = 5
const TCPOPT_TIMESTAMP = 8

/**
 * Locate SACK left/right edges and TCP timestamp fields within a TCP options region.
 * Pure structural walk — independent of the fingerprint session, so it can run once and
 * have each found offset's *value* computed later (PF-06) without re-walking.
 */
export interface TcpOptionsSeqField {
  readonly offset: number
  readonly kind: 'sack-left' | 'sack-right' | 'ts-val' | 'ts-ecr'
}

export function findTcpOptionsSeqFields(
  data: Uint8Array,
  optionsOffset: number,
  optionsLength: number,
  hasTsOffsets: boolean,
): TcpOptionsSeqField[] {
  const fields: TcpOptionsSeqField[] = []
  let pos = optionsOffset
  const end = optionsOffset + optionsLength
  while (pos < end) {
    const kind = data[pos]!
    if (kind === TCPOPT_EOL) break
    if (kind === TCPOPT_NOP) {
      pos++
      continue
    }
    if (pos + 1 >= end) break
    const len = data[pos + 1]!
    if (len < 2 || pos + len > end) break

    if (kind === TCPOPT_SACK && len >= 10 && (len - 2) % 8 === 0) {
      for (let off = pos + 2; off + 8 <= pos + len; off += 8) {
        fields.push({ offset: off, kind: 'sack-left' })
        fields.push({ offset: off + 4, kind: 'sack-right' })
      }
    } else if (kind === TCPOPT_TIMESTAMP && len === 10 && hasTsOffsets) {
      fields.push({ offset: pos + 2, kind: 'ts-val' })
      fields.push({ offset: pos + 6, kind: 'ts-ecr' })
    }

    pos += len
  }
  return fields
}

/** MSS value / Window Scale factor fields — a p0f-style OS/stack fingerprint when preserved. */
export interface TcpOptionsNormalizeField {
  readonly offset: number
  readonly kind: 'mss' | 'wscale'
}

/**
 * Locate the TCP MSS and Window Scale option VALUE bytes within a TCP options region.
 * Only the value is ever touched — option kind/length bytes, NOP padding, and every other
 * option's presence/order are left exactly as captured (that structure isn't itself a
 * meaningful fingerprint the way the specific negotiated MSS/WScale numbers are).
 */
export function findTcpOptionsNormalizeFields(
  data: Uint8Array,
  optionsOffset: number,
  optionsLength: number,
): TcpOptionsNormalizeField[] {
  const fields: TcpOptionsNormalizeField[] = []
  let pos = optionsOffset
  const end = optionsOffset + optionsLength
  while (pos < end) {
    const kind = data[pos]!
    if (kind === TCPOPT_EOL) break
    if (kind === TCPOPT_NOP) {
      pos++
      continue
    }
    if (pos + 1 >= end) break
    const len = data[pos + 1]!
    if (len < 2 || pos + len > end) break

    if (kind === TCPOPT_MSS && len === 4) {
      fields.push({ offset: pos + 2, kind: 'mss' })
    } else if (kind === TCPOPT_WSCALE && len === 3) {
      fields.push({ offset: pos + 2, kind: 'wscale' })
    }

    pos += len
  }
  return fields
}
