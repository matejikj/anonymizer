/**
 * Incremental PCAP/PCAPNG export validator (Stage 13).
 * Validates container framing as output chunks are emitted — no second full-buffer read.
 * Logic is independent from writers (same contract as capture/validator.ts).
 */

import type { ParseIssue } from '../../domain/types'
import { CaptureFormat, IssueSeverity } from '../../domain/types'
import type { ValidationResult } from '../../capture/validator'

export interface IncrementalValidator {
  feedChunk(chunk: ArrayBuffer): void
  finish(): ValidationResult
}

export function createIncrementalValidator(format: CaptureFormat): IncrementalValidator {
  return format === CaptureFormat.Pcapng
    ? new IncrementalPcapngValidator()
    : new IncrementalClassicPcapValidator()
}

class IncrementalClassicPcapValidator implements IncrementalValidator {
  private readonly issues: ParseIssue[] = []
  private phase: 'header' | 'records' = 'header'
  private packetCount = 0
  private snapLen = 0
  private le = true
  private maxFrac = 999_999

  feedChunk(chunk: ArrayBuffer): void {
    if (this.phase === 'header') {
      this.validateHeader(chunk)
      this.phase = 'records'
      return
    }
    this.validateRecord(chunk)
    this.packetCount += 1
  }

  finish(): ValidationResult {
    const hasFatal = this.issues.some(
      (i) => i.severity === IssueSeverity.Fatal || i.severity === IssueSeverity.Error,
    )
    return { valid: !hasFatal, packetCount: this.packetCount, issues: this.issues }
  }

  private validateHeader(buffer: ArrayBuffer): void {
    if (buffer.byteLength < 24) {
      this.issues.push({
        severity: IssueSeverity.Fatal,
        code: 'val-too-small',
        message: 'File smaller than global header (24 bytes)',
      })
      return
    }
    if (buffer.byteLength !== 24) {
      this.issues.push({
        severity: IssueSeverity.Error,
        code: 'val-header-size',
        message: `Global header chunk must be 24 bytes, got ${buffer.byteLength}`,
      })
    }

    const dv = new DataView(buffer)
    const magic = dv.getUint32(0, true)
    const VALID_MAGICS = new Set([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1])
    if (!VALID_MAGICS.has(magic)) {
      this.issues.push({
        severity: IssueSeverity.Fatal,
        code: 'val-bad-magic',
        message: `Invalid PCAP magic: 0x${magic.toString(16)}`,
      })
      return
    }

    this.le = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d
    const nano = magic === 0xa1b23c4d || magic === 0x4d3cb2a1
    this.maxFrac = nano ? 999_999_999 : 999_999

    const vMajor = this.le ? dv.getUint16(4, true) : dv.getUint16(4, false)
    const vMinor = this.le ? dv.getUint16(6, true) : dv.getUint16(6, false)
    if (vMajor !== 2 || vMinor !== 4) {
      this.issues.push({
        severity: IssueSeverity.Warning,
        code: 'val-version',
        message: `Unexpected version ${vMajor}.${vMinor}`,
      })
    }

    this.snapLen = this.le ? dv.getUint32(16, true) : dv.getUint32(16, false)
  }

  private validateRecord(buffer: ArrayBuffer): void {
    if (buffer.byteLength < 16) {
      this.issues.push({
        severity: IssueSeverity.Error,
        code: 'val-truncated',
        message: `Packet ${this.packetCount}: record header truncated`,
        packetNumber: this.packetCount,
      })
      return
    }

    const dv = new DataView(buffer)
    const tsFrac = this.le ? dv.getUint32(4, true) : dv.getUint32(4, false)
    const inclLen = this.le ? dv.getUint32(8, true) : dv.getUint32(8, false)
    const origLen = this.le ? dv.getUint32(12, true) : dv.getUint32(12, false)

    if (buffer.byteLength !== 16 + inclLen) {
      this.issues.push({
        severity: IssueSeverity.Error,
        code: 'val-truncated',
        message: `Packet ${this.packetCount}: chunk size ${buffer.byteLength} != 16 + incl_len ${inclLen}`,
        packetNumber: this.packetCount,
      })
      return
    }

    if (inclLen > origLen) {
      this.issues.push({
        severity: IssueSeverity.Warning,
        code: 'val-incl-gt-orig',
        message: `Packet ${this.packetCount}: incl_len ${inclLen} > orig_len ${origLen}`,
        packetNumber: this.packetCount,
      })
    }

    if (inclLen > this.snapLen && this.snapLen > 0) {
      this.issues.push({
        severity: IssueSeverity.Warning,
        code: 'val-exceeds-snaplen',
        message: `Packet ${this.packetCount}: incl_len ${inclLen} > snapLen ${this.snapLen}`,
        packetNumber: this.packetCount,
      })
    }

    if (tsFrac > this.maxFrac) {
      this.issues.push({
        severity: IssueSeverity.Warning,
        code: 'val-ts-frac-range',
        message: `Packet ${this.packetCount}: timestamp fraction ${tsFrac} exceeds resolution max ${this.maxFrac}`,
        packetNumber: this.packetCount,
      })
    }
  }
}

class IncrementalPcapngValidator implements IncrementalValidator {
  private readonly issues: ParseIssue[] = []
  private packetCount = 0
  private le = true
  private interfaceCount = 0

  feedChunk(chunk: ArrayBuffer): void {
    if (chunk.byteLength < 12) {
      this.issues.push({
        severity: IssueSeverity.Fatal,
        code: 'val-too-small',
        message: 'PCAPNG block smaller than 12 bytes',
      })
      return
    }

    const dv = new DataView(chunk)
    const blockType = dv.getUint32(0, true)

    if (blockType === 0x0a0d0d0a) {
      const bom = dv.getUint32(8, true)
      if (bom === 0x1a2b3c4d) this.le = true
      else if (bom === 0x4d3c2b1a) this.le = false
      else {
        this.issues.push({
          severity: IssueSeverity.Fatal,
          code: 'val-bad-bom',
          message: 'Bad section header BOM',
        })
        return
      }
      this.interfaceCount = 0
    }

    const totalLen = this.le ? dv.getUint32(4, true) : dv.getUint32(4, false)

    if (totalLen < 12) {
      this.issues.push({
        severity: IssueSeverity.Fatal,
        code: 'val-block-len-min',
        message: `Block totalLen ${totalLen} < 12`,
      })
      return
    }

    if (totalLen % 4 !== 0) {
      this.issues.push({
        severity: IssueSeverity.Fatal,
        code: 'val-block-align',
        message: `Block totalLen ${totalLen} not multiple of 4`,
      })
      return
    }

    if (chunk.byteLength !== totalLen) {
      this.issues.push({
        severity: IssueSeverity.Error,
        code: 'val-block-truncated',
        message: `Block chunk size ${chunk.byteLength} != totalLen ${totalLen}`,
      })
      return
    }

    const trailingLen = this.le
      ? dv.getUint32(totalLen - 4, true)
      : dv.getUint32(totalLen - 4, false)
    if (trailingLen !== totalLen) {
      this.issues.push({
        severity: IssueSeverity.Error,
        code: 'val-trailing-mismatch',
        message: `Block trailing ${trailingLen} != leading ${totalLen}`,
      })
    }

    const realType = this.le ? blockType : dv.getUint32(0, false)

    if (realType === 0x00000001) {
      this.interfaceCount += 1
    } else if (realType === 0x00000006 || realType === 0x00000003 || realType === 0x00000002) {
      if (realType === 0x00000006 && totalLen >= 32) {
        const ifaceId = this.le ? dv.getUint32(8, true) : dv.getUint32(8, false)
        if (ifaceId >= this.interfaceCount) {
          this.issues.push({
            severity: IssueSeverity.Error,
            code: 'val-iface-ref',
            message: `EPB interface ${ifaceId} >= ${this.interfaceCount}`,
            packetNumber: this.packetCount,
          })
        }
        const capLen = this.le ? dv.getUint32(20, true) : dv.getUint32(20, false)
        const origLen = this.le ? dv.getUint32(24, true) : dv.getUint32(24, false)
        if (capLen > origLen) {
          this.issues.push({
            severity: IssueSeverity.Warning,
            code: 'val-cap-gt-orig',
            message: `EPB packet ${this.packetCount}: capLen ${capLen} > origLen ${origLen}`,
            packetNumber: this.packetCount,
          })
        }
        const paddedCapLen = (capLen + 3) & ~3
        if (28 + paddedCapLen + 4 > totalLen) {
          this.issues.push({
            severity: IssueSeverity.Error,
            code: 'val-epb-data-overflow',
            message: `EPB packet ${this.packetCount}: data exceeds block`,
            packetNumber: this.packetCount,
          })
        }
        for (let i = 28 + capLen; i < 28 + paddedCapLen; i++) {
          if (dv.getUint8(i) !== 0) {
            this.issues.push({
              severity: IssueSeverity.Warning,
              code: 'val-nonzero-padding',
              message: `Non-zero padding in EPB packet ${this.packetCount}`,
              packetNumber: this.packetCount,
            })
            break
          }
        }
      }
      this.packetCount += 1
    }
  }

  finish(): ValidationResult {
    const hasFatal = this.issues.some(
      (i) => i.severity === IssueSeverity.Fatal || i.severity === IssueSeverity.Error,
    )
    return { valid: !hasFatal, packetCount: this.packetCount, issues: this.issues }
  }
}
