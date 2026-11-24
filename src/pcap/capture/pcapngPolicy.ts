/**
 * PCAPNG block/option allowlist (enterprise step 9).
 *
 * Only structural blocks are kept; DSB is always dropped in every profile.
 * NRB / ISB / comments / custom blocks are never re-emitted by the writer.
 */

/** Block types that may appear in anonymized output. */
export const PCAPNG_ALLOWED_BLOCK_TYPES = {
  SHB: 0x0a0d0d0a,
  IDB: 0x00000001,
  EPB: 0x00000006,
  SPB: 0x00000003,
  OPB: 0x00000002,
} as const

/** Blocks that must never leave the anonymizer (secrets / PII sidecars). */
export const PCAPNG_PROHIBITED_BLOCK_TYPES = {
  NRB: 0x00000004,
  ISB: 0x00000005,
  DSB: 0x0000000a,
} as const

/** IDB options that may be rewritten (structural only). */
export const PCAPNG_ALLOWED_IDB_OPTIONS = {
  ENDOFOPT: 0,
  IF_TSRESOL: 9,
  IF_TSOFFSET: 14,
} as const

/** Common options that must be stripped (comments / custom). */
export const PCAPNG_STRIPPED_OPTIONS = {
  COMMENT: 1,
  CUSTOM_UTF8: 2988,
  CUSTOM_BINARY: 2989,
  CUSTOM_UTF8_COPY: 19372,
  CUSTOM_BINARY_COPY: 19373,
} as const

export type PcapngBlockDisposition = 'keep' | 'drop-prohibited' | 'drop-unknown'

export function classifyPcapngBlock(blockType: number): PcapngBlockDisposition {
  if (
    blockType === PCAPNG_ALLOWED_BLOCK_TYPES.SHB
    || blockType === PCAPNG_ALLOWED_BLOCK_TYPES.IDB
    || blockType === PCAPNG_ALLOWED_BLOCK_TYPES.EPB
    || blockType === PCAPNG_ALLOWED_BLOCK_TYPES.SPB
    || blockType === PCAPNG_ALLOWED_BLOCK_TYPES.OPB
  ) {
    return 'keep'
  }
  if (
    blockType === PCAPNG_PROHIBITED_BLOCK_TYPES.DSB
    || blockType === PCAPNG_PROHIBITED_BLOCK_TYPES.NRB
    || blockType === PCAPNG_PROHIBITED_BLOCK_TYPES.ISB
  ) {
    return 'drop-prohibited'
  }
  return 'drop-unknown'
}

export function isDsbBlock(blockType: number): boolean {
  return blockType === PCAPNG_PROHIBITED_BLOCK_TYPES.DSB
}

export function isNrbBlock(blockType: number): boolean {
  return blockType === PCAPNG_PROHIBITED_BLOCK_TYPES.NRB
}

export function isAllowedIdbOption(optCode: number): boolean {
  return (
    optCode === PCAPNG_ALLOWED_IDB_OPTIONS.ENDOFOPT
    || optCode === PCAPNG_ALLOWED_IDB_OPTIONS.IF_TSRESOL
    || optCode === PCAPNG_ALLOWED_IDB_OPTIONS.IF_TSOFFSET
  )
}

/**
 * Scan exported PCAPNG bytes for prohibited block types (DSB/NRB/ISB).
 * Returns counts; used by golden / leak acceptance tests.
 */
export function scanPcapngForProhibitedBlocks(bytes: Uint8Array): {
  readonly dsb: number
  readonly nrb: number
  readonly isb: number
  readonly unknownNonPacket: number
} {
  let dsb = 0
  let nrb = 0
  let isb = 0
  let unknownNonPacket = 0
  if (bytes.length < 12) return { dsb, nrb, isb, unknownNonPacket }

  // Assume little-endian SHB (writer always uses section endian; tests use LE).
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  let off = 0
  let le = true
  while (off + 12 <= bytes.length) {
    const type = view.getUint32(off, le)
    let totalLen = view.getUint32(off + 4, le)
    if (type === PCAPNG_ALLOWED_BLOCK_TYPES.SHB && off === 0) {
      const bom = view.getUint32(off + 8, true)
      le = bom === 0x1a2b3c4d
      if (!le) {
        totalLen = view.getUint32(off + 4, false)
      }
    }
    if (totalLen < 12 || off + totalLen > bytes.length || (totalLen & 3) !== 0) break

    if (type === PCAPNG_PROHIBITED_BLOCK_TYPES.DSB) dsb++
    else if (type === PCAPNG_PROHIBITED_BLOCK_TYPES.NRB) nrb++
    else if (type === PCAPNG_PROHIBITED_BLOCK_TYPES.ISB) isb++
    else if (classifyPcapngBlock(type) === 'drop-unknown') unknownNonPacket++

    off += totalLen
  }
  return { dsb, nrb, isb, unknownNonPacket }
}
