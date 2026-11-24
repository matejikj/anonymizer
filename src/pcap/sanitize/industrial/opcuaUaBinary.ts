/**
 * T30 — minimal OPC UA Binary codec for MSG Sign / None plaintext walks (baseline).
 */

export function readUaI32(
  buffer: Uint8Array,
  offset: number,
  end: number,
): { value: number; next: number } | null {
  if (offset + 4 > end) return null
  const value =
    (buffer[offset]!
      | (buffer[offset + 1]! << 8)
      | (buffer[offset + 2]! << 16)
      | (buffer[offset + 3]! << 24)) >> 0
  return { value, next: offset + 4 }
}

export function readUaStringSpan(
  buffer: Uint8Array,
  offset: number,
  end: number,
): { dataOffset: number; byteLength: number; next: number } | null {
  const lenField = readUaI32(buffer, offset, end)
  if (!lenField) return null
  if (lenField.value === -1) return { dataOffset: offset + 4, byteLength: 0, next: lenField.next }
  if (lenField.value < 0 || lenField.next + lenField.value > end) return null
  return {
    dataOffset: lenField.next,
    byteLength: lenField.value,
    next: lenField.next + lenField.value,
  }
}

export function readUaByteStringSpan(
  buffer: Uint8Array,
  offset: number,
  end: number,
): { dataOffset: number; byteLength: number; next: number } | null {
  return readUaStringSpan(buffer, offset, end)
}

export function readUaNodeId(
  buffer: Uint8Array,
  offset: number,
  end: number,
): { next: number } | null {
  if (offset >= end) return null
  const encoding = buffer[offset]!
  const typeId = encoding & 0x3f
  let pos = offset + 1
  if ((encoding & 0x40) !== 0) {
    if (pos + 2 > end) return null
    pos += 2
  }
  switch (typeId) {
    case 0:
      if (pos + 1 > end) return null
      return { next: pos + 1 }
    case 1:
      if (pos + 3 > end) return null
      return { next: pos + 3 }
    case 2:
      if (pos + 5 > end) return null
      return { next: pos + 5 }
    case 3:
      if (pos + 4 > end) return null
      return { next: pos + 4 }
    case 4: {
      const guidLen = readUaI32(buffer, pos, end)
      if (!guidLen || guidLen.value < 0 || guidLen.next + guidLen.value > end) return null
      return { next: guidLen.next + guidLen.value }
    }
    case 5: {
      const bs = readUaByteStringSpan(buffer, pos, end)
      return bs ? { next: bs.next } : null
    }
    default:
      return null
  }
}

/** RequestHeader (Part 6) — structured walk for auditEntryId and additionalHeader. */
export function readUaRequestHeader(
  buffer: Uint8Array,
  offset: number,
  end: number,
): { auditEntryId: { dataOffset: number; byteLength: number } | null; next: number } | null {
  let pos = offset
  const auth = readUaNodeId(buffer, pos, end)
  if (!auth) return null
  pos = auth.next
  if (pos + 8 + 4 + 4 > end) return null
  pos += 8 // DateTime
  pos += 4 // requestHandle
  pos += 4 // returnDiagnostics
  const audit = readUaStringSpan(buffer, pos, end)
  if (!audit) return null
  pos = audit.next
  if (pos + 4 > end) return null
  pos += 4 // timeoutHint
  const ext = readUaExtensionObject(buffer, pos, end)
  if (!ext) return null
  return {
    auditEntryId:
      audit.byteLength > 0 ? { dataOffset: audit.dataOffset, byteLength: audit.byteLength } : null,
    next: ext.next,
  }
}

export function readUaExtensionObject(
  buffer: Uint8Array,
  offset: number,
  end: number,
): { next: number } | null {
  const typeId = readUaNodeId(buffer, offset, end)
  if (!typeId) return null
  let pos = typeId.next
  if (pos >= end) return null
  const encoding = buffer[pos]!
  pos += 1
  if (encoding === 0) return { next: pos }
  if (encoding === 1) {
    const bodyLen = readUaI32(buffer, pos, end)
    if (!bodyLen || bodyLen.value < 0 || bodyLen.next + bodyLen.value > end) return null
    return { next: bodyLen.next + bodyLen.value }
  }
  if (encoding === 2) {
    const bs = readUaByteStringSpan(buffer, pos, end)
    return bs ? { next: bs.next } : null
  }
  return null
}

/** OpenSecureChannelRequest body inside ExtensionObject (binary). */
export function readOpenSecureChannelSecurityMode(
  buffer: Uint8Array,
  offset: number,
  end: number,
): { securityMode: number; next: number } | null {
  if (offset + 12 > end) return null
  const afterVersion = offset + 4
  const afterRequestType = afterVersion + 4
  const mode = readUaI32(buffer, afterRequestType, end)
  if (!mode) return null
  return { securityMode: mode.value >>> 0, next: mode.next }
}
