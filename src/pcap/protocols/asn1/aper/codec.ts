/**
 * T56 — schema-driven APER decode / encode (aligned BASIC-PER subset).
 * Unknown / unencodable → explicit issue; never whole-payload “structured” claim.
 */

import { BitCursor, type BitSpan } from './bitCursor.ts'
import {
  readBoolean,
  readConstrainedInteger,
  readConstrainedWholeNumber,
  readEnumerated,
  writeBoolean,
  writeConstrainedInteger,
  writeConstrainedWholeNumber,
  writeEnumerated,
  constrainedIntegerFieldBitLength,
} from './integers.ts'
import {
  readUnconstrainedLength,
  writeUnconstrainedLength,
} from './lengthDeterminant.ts'
import type {
  AperFieldDesc,
  AperFieldRole,
  AperTypeDesc,
  DecodeResult,
  DecodedLeaf,
} from './schemaTypes.ts'

const MAX_DEPTH = 32
const MAX_SEQ_OF = 256
const MAX_OPEN = 4096

export function decodeAper(
  buffer: Uint8Array,
  byteOffset: number,
  byteLength: number,
  type: AperTypeDesc,
): DecodeResult {
  const cur = new BitCursor(buffer, byteOffset, byteOffset + byteLength)
  const leaves: DecodedLeaf[] = []
  const issues: { code: string; bitOffset: number }[] = []
  const start = cur.absoluteBitOffset
  const ok = decodeType(cur, type, '', 'preserve', null, leaves, issues, 0)
  return {
    ok: ok && issues.length === 0,
    leaves,
    issues,
    bitLength: cur.absoluteBitOffset - start,
  }
}

export function encodeAper(
  type: AperTypeDesc,
  value: unknown,
  maxBytes = 256,
): Uint8Array | null {
  const buf = new Uint8Array(maxBytes)
  const cur = new BitCursor(buf)
  if (!encodeType(cur, type, value, 0)) return null
  if (!cur.align()) return null
  return buf.subarray(0, (cur.bitOffset + 7) >> 3)
}

/**
 * Length-preserving rewrite of a constrained integer leaf at `span`.
 * Verifies encode width matches; returns byte patches for PatchCompiler.
 */
export function rewriteConstrainedIntegerLeaf(
  buffer: Uint8Array,
  span: BitSpan,
  lower: number,
  upper: number,
  newValue: number,
): { ok: true; bitPatches: BitPatch[] } | { ok: false; reason: string } {
  if (newValue < lower || newValue > upper) {
    return { ok: false, reason: 'out-of-range' }
  }
  const expectedBits = constrainedIntegerFieldBitLength(lower, upper, newValue)
  if (expectedBits === null || expectedBits !== span.bitLength) {
    return { ok: false, reason: 'width-mismatch' }
  }
  const scratch = buffer.slice()
  const absByteStart = 0
  const cur = new BitCursor(scratch, absByteStart, scratch.length)
  if (!cur.seekBit(span.bitOffset)) {
    return { ok: false, reason: 'seek' }
  }
  if (!writeConstrainedInteger(cur, lower, upper, newValue)) {
    return { ok: false, reason: 'encode' }
  }
  // Independent decode check
  const check = new BitCursor(scratch)
  if (!check.seekBit(span.bitOffset)) return { ok: false, reason: 'reseek' }
  const got = readConstrainedInteger(check, lower, upper)
  if (!got || got.value !== newValue) {
    return { ok: false, reason: 'roundtrip' }
  }
  return {
    ok: true,
    bitPatches: [{ bitOffset: span.bitOffset, bitLength: span.bitLength, buffer: scratch }],
  }
}

export interface BitPatch {
  /** Absolute bit offset into original buffer. */
  readonly bitOffset: number
  readonly bitLength: number
  /** Full buffer copy with only the patch region written (or use writeBitsInto). */
  readonly buffer: Uint8Array
}

function decodeType(
  cur: BitCursor,
  type: AperTypeDesc,
  path: string,
  role: AperFieldRole,
  mappingCategory: string | null,
  leaves: DecodedLeaf[],
  issues: { code: string; bitOffset: number }[],
  depth: number,
): boolean {
  if (depth > MAX_DEPTH) {
    issues.push({ code: 'depth-overflow', bitOffset: cur.absoluteBitOffset })
    return false
  }
  switch (type.kind) {
    case 'boolean': {
      const r = readBoolean(cur)
      if (!r) {
        issues.push({ code: 'boolean', bitOffset: cur.absoluteBitOffset })
        return false
      }
      leaves.push({ path, role, mappingCategory, span: r.span, value: r.value })
      return true
    }
    case 'integer': {
      const r = readConstrainedInteger(cur, type.lower, type.upper)
      if (!r) {
        issues.push({ code: 'integer', bitOffset: cur.absoluteBitOffset })
        return false
      }
      leaves.push({ path, role, mappingCategory, span: r.span, value: r.value })
      return true
    }
    case 'enumerated': {
      const r = readEnumerated(cur, type.names.length, type.extensible === true)
      if (!r) {
        issues.push({ code: 'enumerated', bitOffset: cur.absoluteBitOffset })
        return false
      }
      const name = type.names[r.value] ?? String(r.value)
      leaves.push({ path, role, mappingCategory, span: r.span, value: name })
      return true
    }
    case 'octet-string': {
      return decodeOctetString(cur, type, path, role, mappingCategory, leaves, issues)
    }
    case 'bit-string': {
      return decodeBitString(cur, type, path, role, mappingCategory, leaves, issues)
    }
    case 'sequence': {
      return decodeSequence(cur, type.fields, type.extensible === true, path, leaves, issues, depth)
    }
    case 'choice': {
      return decodeChoice(cur, type.alts, type.extensible === true, path, leaves, issues, depth)
    }
    case 'sequence-of': {
      return decodeSequenceOf(cur, type, path, leaves, issues, depth)
    }
    case 'open-type': {
      return decodeOpenType(cur, type, path, role, mappingCategory, leaves, issues, depth)
    }
    default: {
      issues.push({ code: 'unknown-type', bitOffset: cur.absoluteBitOffset })
      return false
    }
  }
}

function decodeOctetString(
  cur: BitCursor,
  type: Extract<AperTypeDesc, { kind: 'octet-string' }>,
  path: string,
  role: AperFieldRole,
  mappingCategory: string | null,
  leaves: DecodedLeaf[],
  issues: { code: string; bitOffset: number }[],
): boolean {
  const fixed = type.sizeLower === type.sizeUpper
  let len = type.sizeLower
  const start = cur.absoluteBitOffset
  if (!fixed) {
    if (type.sizeUpper < 65536) {
      const r = readConstrainedWholeNumber(cur, type.sizeLower, type.sizeUpper)
      if (!r) {
        issues.push({ code: 'octet-len', bitOffset: cur.absoluteBitOffset })
        return false
      }
      len = r.value
    } else {
      if (!cur.align()) {
        issues.push({ code: 'octet-align', bitOffset: cur.absoluteBitOffset })
        return false
      }
      const ld = readUnconstrainedLength(cur)
      if (!ld || ld.length > MAX_OPEN) {
        issues.push({ code: 'octet-unconst', bitOffset: cur.absoluteBitOffset })
        return false
      }
      len = ld.length
    }
  }
  if (!cur.align()) {
    issues.push({ code: 'octet-align', bitOffset: cur.absoluteBitOffset })
    return false
  }
  const bits = len * 8
  if (bits > cur.remainingBits) {
    issues.push({ code: 'octet-oob', bitOffset: cur.absoluteBitOffset })
    return false
  }
  const dataStart = cur.absoluteBitOffset
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    const b = cur.readBits(8)
    if (b === null) {
      issues.push({ code: 'octet-read', bitOffset: cur.absoluteBitOffset })
      return false
    }
    bytes[i] = b
  }
  leaves.push({
    path,
    role,
    mappingCategory,
    span: { bitOffset: dataStart, bitLength: bits },
    value: bytes,
  })
  void start
  return true
}

function decodeBitString(
  cur: BitCursor,
  type: Extract<AperTypeDesc, { kind: 'bit-string' }>,
  path: string,
  role: AperFieldRole,
  mappingCategory: string | null,
  leaves: DecodedLeaf[],
  issues: { code: string; bitOffset: number }[],
): boolean {
  let len = type.sizeLower
  if (type.sizeLower !== type.sizeUpper) {
    const r = readConstrainedWholeNumber(cur, type.sizeLower, type.sizeUpper)
    if (!r) {
      issues.push({ code: 'bitstring-len', bitOffset: cur.absoluteBitOffset })
      return false
    }
    len = r.value
  }
  const start = cur.absoluteBitOffset
  if (len > cur.remainingBits) {
    issues.push({ code: 'bitstring-oob', bitOffset: start })
    return false
  }
  const v = cur.readBits(Math.min(len, 32))
  if (v === null && len > 0) {
    issues.push({ code: 'bitstring-read', bitOffset: start })
    return false
  }
  if (len > 32) {
    if (!cur.skipBits(len - 32)) {
      issues.push({ code: 'bitstring-skip', bitOffset: cur.absoluteBitOffset })
      return false
    }
  }
  leaves.push({
    path,
    role,
    mappingCategory,
    span: { bitOffset: start, bitLength: len },
    value: v ?? 0,
  })
  return true
}

function decodeSequence(
  cur: BitCursor,
  fields: readonly AperFieldDesc[],
  extensible: boolean,
  path: string,
  leaves: DecodedLeaf[],
  issues: { code: string; bitOffset: number }[],
  depth: number,
): boolean {
  if (extensible) {
    const ext = cur.readBits(1)
    if (ext === null) {
      issues.push({ code: 'seq-ext', bitOffset: cur.absoluteBitOffset })
      return false
    }
    if (ext === 1) {
      // Extension additions present — baseline: skip unknown with normally-small count then mask
      issues.push({ code: 'seq-extension-unsupported', bitOffset: cur.absoluteBitOffset })
      return false
    }
  }
  const optionals = fields.filter((f) => f.optional)
  const present: boolean[] = []
  if (optionals.length > 0) {
    for (let i = 0; i < optionals.length; i++) {
      const b = cur.readBits(1)
      if (b === null) {
        issues.push({ code: 'seq-optional', bitOffset: cur.absoluteBitOffset })
        return false
      }
      present.push(b === 1)
    }
  }
  let optIdx = 0
  for (const f of fields) {
    if (f.optional) {
      const isPresent = present[optIdx++]
      if (!isPresent) continue
    }
    const childPath = path ? `${path}.${f.name}` : f.name
    if (
      !decodeType(
        cur,
        f.type,
        childPath,
        f.role ?? 'preserve',
        f.mappingCategory ?? null,
        leaves,
        issues,
        depth + 1,
      )
    ) {
      return false
    }
  }
  return true
}

function decodeChoice(
  cur: BitCursor,
  alts: readonly AperFieldDesc[],
  extensible: boolean,
  path: string,
  leaves: DecodedLeaf[],
  issues: { code: string; bitOffset: number }[],
  depth: number,
): boolean {
  if (alts.length === 0) {
    issues.push({ code: 'choice-empty', bitOffset: cur.absoluteBitOffset })
    return false
  }
  const idx = readEnumerated(cur, alts.length, extensible)
  if (!idx) {
    issues.push({ code: 'choice-index', bitOffset: cur.absoluteBitOffset })
    return false
  }
  const alt = alts[idx.value]!
  const childPath = path ? `${path}.${alt.name}` : alt.name
  leaves.push({
    path: `${childPath}#choice`,
    role: 'preserve',
    mappingCategory: null,
    span: idx.span,
    value: alt.name,
  })
  return decodeType(
    cur,
    alt.type,
    childPath,
    alt.role ?? 'preserve',
    alt.mappingCategory ?? null,
    leaves,
    issues,
    depth + 1,
  )
}

function decodeSequenceOf(
  cur: BitCursor,
  type: Extract<AperTypeDesc, { kind: 'sequence-of' }>,
  path: string,
  leaves: DecodedLeaf[],
  issues: { code: string; bitOffset: number }[],
  depth: number,
): boolean {
  const r = readConstrainedWholeNumber(cur, type.sizeLower, type.sizeUpper)
  if (!r) {
    issues.push({ code: 'seqof-len', bitOffset: cur.absoluteBitOffset })
    return false
  }
  if (r.value > MAX_SEQ_OF) {
    issues.push({ code: 'seqof-cap', bitOffset: cur.absoluteBitOffset })
    return false
  }
  leaves.push({
    path: `${path}#count`,
    role: 'preserve',
    mappingCategory: null,
    span: r.span,
    value: r.value,
  })
  for (let i = 0; i < r.value; i++) {
    if (!decodeType(cur, type.element, `${path}[${i}]`, 'preserve', null, leaves, issues, depth + 1)) {
      return false
    }
  }
  return true
}

function decodeOpenType(
  cur: BitCursor,
  type: Extract<AperTypeDesc, { kind: 'open-type' }>,
  path: string,
  role: AperFieldRole,
  mappingCategory: string | null,
  leaves: DecodedLeaf[],
  issues: { code: string; bitOffset: number }[],
  depth: number,
): boolean {
  if (!cur.align()) {
    issues.push({ code: 'open-align', bitOffset: cur.absoluteBitOffset })
    return false
  }
  const ld = readUnconstrainedLength(cur)
  if (!ld || ld.length > MAX_OPEN) {
    issues.push({ code: 'open-len', bitOffset: cur.absoluteBitOffset })
    return false
  }
  if (!cur.align()) {
    issues.push({ code: 'open-align2', bitOffset: cur.absoluteBitOffset })
    return false
  }
  const start = cur.absoluteBitOffset
  const bits = ld.length * 8
  if (bits > cur.remainingBits) {
    issues.push({ code: 'open-oob', bitOffset: start })
    return false
  }
  if (type.contained) {
    const nestedOk = decodeType(
      cur,
      type.contained,
      `${path}.open`,
      role,
      mappingCategory,
      leaves,
      issues,
      depth + 1,
    )
    // Consume remaining open-type octets if nested used fewer
    const used = cur.absoluteBitOffset - start
    if (used < bits) {
      if (!cur.skipBits(bits - used)) {
        issues.push({ code: 'open-pad', bitOffset: cur.absoluteBitOffset })
        return false
      }
    }
    return nestedOk
  }
  // Opaque: record span and skip (caller masks)
  if (!cur.skipBits(bits)) {
    issues.push({ code: 'open-skip', bitOffset: cur.absoluteBitOffset })
    return false
  }
  leaves.push({
    path,
    role: role === 'preserve' ? 'opaque' : role,
    mappingCategory,
    span: { bitOffset: start, bitLength: bits },
    value: null,
  })
  return true
}

function encodeType(cur: BitCursor, type: AperTypeDesc, value: unknown, depth: number): boolean {
  if (depth > MAX_DEPTH) return false
  switch (type.kind) {
    case 'boolean':
      return writeBoolean(cur, Boolean(value))
    case 'integer':
      return writeConstrainedInteger(cur, type.lower, type.upper, Number(value))
    case 'enumerated': {
      const idx = typeof value === 'string' ? type.names.indexOf(value) : Number(value)
      return writeEnumerated(cur, type.names.length, type.extensible === true, idx)
    }
    case 'octet-string': {
      if (!(value instanceof Uint8Array)) return false
      const fixed = type.sizeLower === type.sizeUpper
      if (!fixed) {
        if (value.length < type.sizeLower || value.length > type.sizeUpper) return false
        if (type.sizeUpper < 65536) {
          if (!writeConstrainedWholeNumber(cur, type.sizeLower, type.sizeUpper, value.length)) return false
        } else {
          if (!writeUnconstrainedLength(cur, value.length)) return false
        }
      } else if (value.length !== type.sizeLower) {
        return false
      }
      if (!cur.align()) return false
      for (let i = 0; i < value.length; i++) {
        if (!cur.writeBits(8, value[i]!)) return false
      }
      return true
    }
    case 'bit-string': {
      if (type.sizeLower !== type.sizeUpper) return false
      return cur.writeBits(type.sizeLower, Number(value) >>> 0)
    }
    case 'sequence': {
      if (!value || typeof value !== 'object') return false
      const obj = value as Record<string, unknown>
      if (type.extensible) {
        if (!cur.writeBits(1, 0)) return false
      }
      const optionals = type.fields.filter((f) => f.optional)
      for (const f of optionals) {
        if (!cur.writeBits(1, obj[f.name] !== undefined && obj[f.name] !== null ? 1 : 0)) return false
      }
      for (const f of type.fields) {
        if (f.optional && (obj[f.name] === undefined || obj[f.name] === null)) continue
        if (!encodeType(cur, f.type, obj[f.name], depth + 1)) return false
      }
      return true
    }
    case 'choice': {
      if (!value || typeof value !== 'object') return false
      const obj = value as { alt: string; value: unknown }
      const idx = type.alts.findIndex((a) => a.name === obj.alt)
      if (idx < 0) return false
      if (!writeEnumerated(cur, type.alts.length, type.extensible === true, idx)) return false
      return encodeType(cur, type.alts[idx]!.type, obj.value, depth + 1)
    }
    case 'sequence-of': {
      if (!Array.isArray(value)) return false
      if (value.length < type.sizeLower || value.length > type.sizeUpper) return false
      if (!writeConstrainedWholeNumber(cur, type.sizeLower, type.sizeUpper, value.length)) return false
      for (const el of value) {
        if (!encodeType(cur, type.element, el, depth + 1)) return false
      }
      return true
    }
    case 'open-type': {
      const inner = type.contained
        ? encodeAper(type.contained, value, MAX_OPEN)
        : value instanceof Uint8Array
          ? value
          : null
      if (!inner) return false
      if (!writeUnconstrainedLength(cur, inner.length)) return false
      if (!cur.align()) return false
      for (let i = 0; i < inner.length; i++) {
        if (!cur.writeBits(8, inner[i]!)) return false
      }
      return true
    }
    default:
      return false
  }
}
