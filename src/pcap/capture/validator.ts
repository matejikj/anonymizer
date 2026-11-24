/**
 * Independent streaming conformance validator for PCAP/PCAPNG output.
 * Does NOT share any helper functions with the writer to avoid correlated bugs.
 * Validates framing, lengths, alignment, interface references, timestamps.
 */

import type { ParseIssue } from '../domain/types';
import { IssueSeverity } from '../domain/types';

export interface ValidationResult {
  readonly valid: boolean;
  readonly packetCount: number;
  readonly issues: readonly ParseIssue[];
}

/**
 * Validate a classic PCAP buffer structure.
 */
export function validateClassicPcap(buffer: ArrayBuffer): ValidationResult {
  const issues: ParseIssue[] = [];
  if (buffer.byteLength < 24) {
    issues.push({ severity: IssueSeverity.Fatal, code: 'val-too-small', message: 'File smaller than global header (24 bytes)' });
    return { valid: false, packetCount: 0, issues };
  }

  const dv = new DataView(buffer);
  const magic = dv.getUint32(0, true);

  // Determine endian
  const VALID_MAGICS = new Set([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1]);
  if (!VALID_MAGICS.has(magic)) {
    issues.push({ severity: IssueSeverity.Fatal, code: 'val-bad-magic', message: `Invalid PCAP magic: 0x${magic.toString(16)}` });
    return { valid: false, packetCount: 0, issues };
  }

  const le = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
  const nano = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
  const maxFrac = nano ? 999_999_999 : 999_999;

  const vMajor = le ? dv.getUint16(4, true) : dv.getUint16(4, false);
  const vMinor = le ? dv.getUint16(6, true) : dv.getUint16(6, false);
  if (vMajor !== 2 || vMinor !== 4) {
    issues.push({ severity: IssueSeverity.Warning, code: 'val-version', message: `Unexpected version ${vMajor}.${vMinor}` });
  }

  const snapLen = le ? dv.getUint32(16, true) : dv.getUint32(16, false);

  let offset = 24;
  let packetCount = 0;

  while (offset + 16 <= buffer.byteLength) {
    const tsFrac = le ? dv.getUint32(offset + 4, true) : dv.getUint32(offset + 4, false);
    const inclLen = le ? dv.getUint32(offset + 8, true) : dv.getUint32(offset + 8, false);
    const origLen = le ? dv.getUint32(offset + 12, true) : dv.getUint32(offset + 12, false);

    if (inclLen > origLen) {
      issues.push({ severity: IssueSeverity.Warning, code: 'val-incl-gt-orig', message: `Packet ${packetCount}: incl_len ${inclLen} > orig_len ${origLen}`, packetNumber: packetCount, fileOffset: offset });
    }

    if (inclLen > snapLen && snapLen > 0) {
      issues.push({ severity: IssueSeverity.Warning, code: 'val-exceeds-snaplen', message: `Packet ${packetCount}: incl_len ${inclLen} > snapLen ${snapLen}`, packetNumber: packetCount, fileOffset: offset });
    }

    if (tsFrac > maxFrac) {
      issues.push({ severity: IssueSeverity.Warning, code: 'val-ts-frac-range', message: `Packet ${packetCount}: timestamp fraction ${tsFrac} exceeds resolution max ${maxFrac}`, packetNumber: packetCount, fileOffset: offset });
    }

    if (offset + 16 + inclLen > buffer.byteLength) {
      issues.push({ severity: IssueSeverity.Error, code: 'val-truncated', message: `Packet ${packetCount}: data truncated`, packetNumber: packetCount, fileOffset: offset });
      return { valid: false, packetCount, issues };
    }

    offset += 16 + inclLen;
    packetCount++;
  }

  // Trailing bytes check
  if (offset !== buffer.byteLength) {
    issues.push({ severity: IssueSeverity.Warning, code: 'val-trailing-bytes', message: `${buffer.byteLength - offset} trailing bytes after last packet` });
  }

  const hasFatal = issues.some((i) => i.severity === IssueSeverity.Fatal || i.severity === IssueSeverity.Error);
  return { valid: !hasFatal, packetCount, issues };
}

/**
 * Validate a PCAPNG buffer structure.
 */
export function validatePcapng(buffer: ArrayBuffer): ValidationResult {
  const issues: ParseIssue[] = [];

  if (buffer.byteLength < 12) {
    issues.push({ severity: IssueSeverity.Fatal, code: 'val-too-small', message: 'File too small for PCAPNG' });
    return { valid: false, packetCount: 0, issues };
  }

  const dv = new DataView(buffer);
  let offset = 0;
  let packetCount = 0;
  let le = true;
  let interfaceCount = 0;

  while (offset + 12 <= buffer.byteLength) {
    const blockType = dv.getUint32(offset, true); // peek LE

    // SHB detection
    if (blockType === 0x0a0d0d0a) {
      if (offset + 12 > buffer.byteLength) break;
      const bom = dv.getUint32(offset + 8, true);
      if (bom === 0x1a2b3c4d) {
        le = true;
      } else if (bom === 0x4d3c2b1a) {
        le = false;
      } else {
        issues.push({ severity: IssueSeverity.Fatal, code: 'val-bad-bom', message: `Bad BOM at offset ${offset}`, fileOffset: offset });
        return { valid: false, packetCount, issues };
      }
      interfaceCount = 0;
    }

    const totalLen = le ? dv.getUint32(offset + 4, true) : dv.getUint32(offset + 4, false);

    // Block length invariants
    if (totalLen < 12) {
      issues.push({ severity: IssueSeverity.Fatal, code: 'val-block-len-min', message: `Block at ${offset}: totalLen ${totalLen} < 12`, fileOffset: offset });
      return { valid: false, packetCount, issues };
    }

    if (totalLen % 4 !== 0) {
      issues.push({ severity: IssueSeverity.Fatal, code: 'val-block-align', message: `Block at ${offset}: totalLen ${totalLen} not multiple of 4`, fileOffset: offset });
      return { valid: false, packetCount, issues };
    }

    if (offset + totalLen > buffer.byteLength) {
      issues.push({ severity: IssueSeverity.Error, code: 'val-block-truncated', message: `Block at ${offset} extends beyond file`, fileOffset: offset });
      return { valid: false, packetCount, issues };
    }

    // Trailing total_length must match
    const trailingLen = le ? dv.getUint32(offset + totalLen - 4, true) : dv.getUint32(offset + totalLen - 4, false);
    if (trailingLen !== totalLen) {
      issues.push({ severity: IssueSeverity.Error, code: 'val-trailing-mismatch', message: `Block at ${offset}: trailing ${trailingLen} != leading ${totalLen}`, fileOffset: offset });
    }

    // Determine real block type in correct endian
    const realType = le ? blockType : dv.getUint32(offset, false);

    if (realType === 0x00000001) {
      // IDB
      interfaceCount++;
    } else if (realType === 0x00000006 || realType === 0x00000003 || realType === 0x00000002) {
      // EPB/SPB/OPB = packet
      if (realType === 0x00000006 && totalLen >= 32) {
        // EPB: validate interface reference
        const ifaceId = le ? dv.getUint32(offset + 8, true) : dv.getUint32(offset + 8, false);
        if (ifaceId >= interfaceCount) {
          issues.push({ severity: IssueSeverity.Error, code: 'val-iface-ref', message: `EPB at ${offset}: interface ${ifaceId} >= ${interfaceCount}`, packetNumber: packetCount, fileOffset: offset });
        }
        // Validate captured <= original
        const capLen = le ? dv.getUint32(offset + 20, true) : dv.getUint32(offset + 20, false);
        const origLen = le ? dv.getUint32(offset + 24, true) : dv.getUint32(offset + 24, false);
        if (capLen > origLen) {
          issues.push({ severity: IssueSeverity.Warning, code: 'val-cap-gt-orig', message: `EPB packet ${packetCount}: capLen ${capLen} > origLen ${origLen}`, packetNumber: packetCount, fileOffset: offset });
        }
        // Validate data fits in block
        const paddedCapLen = (capLen + 3) & ~3;
        if (28 + paddedCapLen + 4 > totalLen) {
          issues.push({ severity: IssueSeverity.Error, code: 'val-epb-data-overflow', message: `EPB packet ${packetCount}: data exceeds block`, packetNumber: packetCount, fileOffset: offset });
        }
      }
      packetCount++;
    }

    // Check padding bytes are zero (for data blocks)
    // (relaxed: only check EPB padding)
    if (realType === 0x00000006 && totalLen >= 32) {
      const capLen = le ? dv.getUint32(offset + 20, true) : dv.getUint32(offset + 20, false);
      const dataEnd = offset + 28 + capLen;
      const paddedEnd = offset + 28 + ((capLen + 3) & ~3);
      for (let i = dataEnd; i < paddedEnd && i < buffer.byteLength; i++) {
        if (dv.getUint8(i) !== 0) {
          issues.push({ severity: IssueSeverity.Warning, code: 'val-nonzero-padding', message: `Non-zero padding at byte ${i} in EPB`, packetNumber: packetCount - 1, fileOffset: offset });
          break;
        }
      }
    }

    offset += totalLen;
  }

  if (offset !== buffer.byteLength) {
    issues.push({ severity: IssueSeverity.Warning, code: 'val-trailing-bytes', message: `${buffer.byteLength - offset} trailing bytes` });
  }

  const hasFatal = issues.some((i) => i.severity === IssueSeverity.Fatal || i.severity === IssueSeverity.Error);
  return { valid: !hasFatal, packetCount, issues };
}
