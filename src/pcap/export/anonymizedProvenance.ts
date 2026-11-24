/**
 * Streaming provenance between original capture bytes and actually serialized
 * anonymized output. Lives in the export hot path — recovery must not import this
 * module from incrementalExportEngine; the engine accepts an optional recorder.
 *
 * COPY_ANON is only recorded for verified byte-equal runs with monotonic,
 * non-overlapping original and anonymized offsets.
 */

/** Runs shorter than this stay LITERAL — COPY_ANON op overhead is 13 bytes. */
export const COPY_ANON_MIN_RUN_BYTES = 16

export interface ProvenanceCopyRun {
  readonly originalOffset: number
  readonly anonymizedOffset: number
  readonly length: number
}

export function validateProvenanceCopies(
  copies: readonly ProvenanceCopyRun[],
  originalByteLength: number,
  anonymizedByteLength: number,
): boolean {
  if (!Number.isSafeInteger(originalByteLength) || originalByteLength < 0) return false
  if (!Number.isSafeInteger(anonymizedByteLength) || anonymizedByteLength < 0) return false
  let origEnd = 0
  let anonEnd = 0
  for (const run of copies) {
    if (!Number.isInteger(run.originalOffset) || !Number.isInteger(run.anonymizedOffset)) return false
    if (!Number.isInteger(run.length) || run.length <= 0) return false
    if (run.originalOffset < origEnd) return false
    if (run.anonymizedOffset < anonEnd) return false
    const oEnd = run.originalOffset + run.length
    const aEnd = run.anonymizedOffset + run.length
    if (oEnd > originalByteLength || aEnd > anonymizedByteLength) return false
    origEnd = oEnd
    anonEnd = aEnd
  }
  return true
}

/**
 * Records copy-equal payload ranges as anonymized bytes are emitted.
 * Headers, timestamps, checksums, dropped records, and unmatched PCAPNG
 * metadata are never recorded — they stay LITERAL at restore time.
 */
export class AnonymizedProvenanceRecorder {
  private anonCursor = 0
  private valid = true
  private readonly copies: ProvenanceCopyRun[] = []

  get anonymizedOffset(): number {
    return this.anonCursor
  }

  get isValid(): boolean {
    return this.valid
  }

  invalidate(): void {
    this.valid = false
    this.copies.length = 0
  }

  /** Rewritten bytes with no proven original counterpart (headers, padding, SHB/IDB). */
  recordRewrite(byteLength: number): void {
    if (!this.valid) return
    if (!Number.isInteger(byteLength) || byteLength < 0) {
      this.invalidate()
      return
    }
    this.anonCursor += byteLength
  }

  /**
   * Compare original payload to actually emitted payload bytes.
   * Equal runs ≥ COPY_ANON_MIN_RUN_BYTES become COPY_ANON; everything else
   * advances the anonymized cursor as rewrite.
   */
  recordVerifiedCopies(input: {
    readonly originalPayload: Uint8Array
    readonly emittedPayload: Uint8Array
    readonly originalFileOffset: number
  }): void {
    if (!this.valid) return
    const orig = input.originalPayload
    const emitted = input.emittedPayload
    const base = input.originalFileOffset
    if (!Number.isInteger(base) || base < 0) {
      this.invalidate()
      return
    }

    let i = 0
    while (i < emitted.byteLength) {
      const origByte = i < orig.byteLength ? orig[i] : undefined
      if (origByte === emitted[i]) {
        let j = i + 1
        while (j < emitted.byteLength && j < orig.byteLength && orig[j] === emitted[j]) j++
        const len = j - i
        if (len >= COPY_ANON_MIN_RUN_BYTES) {
          this.copies.push({
            originalOffset: base + i,
            anonymizedOffset: this.anonCursor,
            length: len,
          })
        }
        this.anonCursor += len
        i = j
      } else {
        this.anonCursor += 1
        i += 1
      }
    }
  }

  /**
   * After the anonymized stream completes: copies if the cursor matches the
   * hashed output length and runs stay monotonic; otherwise null (caller
   * must fall back to full-literal).
   */
  finish(anonymizedByteLength: number, originalByteLength: number): ProvenanceCopyRun[] | null {
    if (!this.valid) return null
    if (this.anonCursor !== anonymizedByteLength) return null
    if (!validateProvenanceCopies(this.copies, originalByteLength, anonymizedByteLength)) {
      return null
    }
    return this.copies.slice()
  }
}
