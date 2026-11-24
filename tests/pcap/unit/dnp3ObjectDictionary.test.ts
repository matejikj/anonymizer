/**
 * T30 — DNP3 object group/variation dictionary baseline.
 */
import { describe, expect, it } from 'vitest'
import {
  dnp3ObjectStride,
  dnp3ParseQualifierRange,
} from '../../../src/pcap/sanitize/industrial/dnp3ObjectDictionary'

describe('dnp3ObjectDictionary', () => {
  it('resolves G30V1 analog stride', () => {
    expect(dnp3ObjectStride(30, 1)).toEqual({ valueSize: 5, indexPrefixBytes: 0 })
  })

  it('parses 8-bit count qualifier', () => {
    const buf = new Uint8Array([2])
    const range = dnp3ParseQualifierRange(0x03, buf, 0, 1)
    expect(range?.objectCount).toBe(2)
    expect(range?.rangeBytes).toBe(1)
  })
})
