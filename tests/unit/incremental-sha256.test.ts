/**
 * Incremental SHA-256 — NIST vectors and arbitrary chunk boundaries.
 */

import { describe, expect, it } from 'vitest'
import {
  IncrementalSha256,
  bytesToHex,
  hexToBytes,
  sha256,
} from '../../src/crypto/incrementalSha256'

const NIST = [
  {
    msg: '',
    dig: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  },
  {
    msg: 'abc',
    dig: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  },
  {
    msg: 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
    dig: '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
  },
  {
    msg: 'a'.repeat(1_000_000),
    dig: 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
  },
] as const

describe('IncrementalSha256', () => {
  it('matches NIST known-answer vectors', () => {
    for (const { msg, dig } of NIST) {
      const bytes = new TextEncoder().encode(msg)
      expect(bytesToHex(sha256(bytes))).toBe(dig)
    }
  })

  it('is invariant across chunk boundaries', () => {
    const payload = new TextEncoder().encode('The quick brown fox jumps over the lazy dog')
    const expected = bytesToHex(sha256(payload))
    for (const size of [1, 3, 7, 63, 64, 65, 128, payload.byteLength]) {
      const hasher = new IncrementalSha256()
      for (let i = 0; i < payload.byteLength; i += size) {
        hasher.update(payload.subarray(i, Math.min(i + size, payload.byteLength)))
      }
      expect(bytesToHex(hasher.digest()), `chunk=${size}`).toBe(expected)
    }
  })

  it('matches Web Crypto subtle.digest for random payloads', async () => {
    for (const len of [0, 1, 15, 64, 1000, 10_000]) {
      const payload = crypto.getRandomValues(new Uint8Array(len))
      const ours = sha256(payload)
      const ref = new Uint8Array(await crypto.subtle.digest('SHA-256', payload))
      expect(bytesToHex(ours)).toBe(bytesToHex(ref))
    }
  })

  it('hex helpers round-trip', () => {
    const bytes = hexToBytes('deadbeef')
    expect(bytesToHex(bytes)).toBe('deadbeef')
  })
})
