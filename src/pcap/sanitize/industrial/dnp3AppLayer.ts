/**
 * T30 — DNP3 transport/application object walk with group/variation stride dictionary.
 */

import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { LayerCoverage } from '../types.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'
import {
  dnp3ObjectStride,
  dnp3ParseQualifierRange,
} from './dnp3ObjectDictionary.ts'

export interface Dnp3AppLayerResult {
  readonly coverage: LayerCoverage[]
  readonly issues: string[]
}

function maskInPlace(
  buffer: Uint8Array,
  offset: number,
  length: number,
  packetIndex: number,
  intents: IntentCollector | undefined,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({
    length,
    packetIndex,
    offset,
    domain: 'dnp3-values',
  })
  buffer.set(fill, offset)
  intents?.recordMaskRange(packetIndex, offset, length, 'dnp3-values', 'dnp3')
}

export function sanitizeDnp3ApplicationLayer(
  buffer: Uint8Array,
  offset: number,
  length: number,
  intents: IntentCollector | undefined,
  packetIndex: number,
  absoluteBase: number,
): Dnp3AppLayerResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  if (length < 3) {
    maskInPlace(buffer, offset, length, packetIndex, intents)
    coverage.push({
      protocol: 'dnp3-body',
      offset: absoluteBase + offset,
      length,
      status: 'redacted',
    })
    return { coverage, issues }
  }

  coverage.push({
    protocol: 'dnp3',
    offset: absoluteBase + pos,
    length: 1,
    status: 'covered',
  })
  pos += 1

  coverage.push({
    protocol: 'dnp3',
    offset: absoluteBase + pos,
    length: 2,
    status: 'covered',
  })
  pos += 2

  while (pos + 3 <= end) {
    const group = buffer[pos]!
    const variation = buffer[pos + 1]!
    const qualifier = buffer[pos + 2]!
    coverage.push({
      protocol: 'dnp3',
      offset: absoluteBase + pos,
      length: 3,
      status: 'covered',
    })
    pos += 3

    const range = dnp3ParseQualifierRange(qualifier, buffer, pos, end)
    if (!range) {
      maskInPlace(buffer, pos, end - pos, packetIndex, intents)
      coverage.push({
        protocol: 'dnp3-body',
        offset: absoluteBase + pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('dnp3-unknown-qualifier')
      break
    }
    if (range.rangeBytes > 0) {
      coverage.push({
        protocol: 'dnp3',
        offset: absoluteBase + pos,
        length: range.rangeBytes,
        status: 'covered',
      })
      pos += range.rangeBytes
    }

    const stride = dnp3ObjectStride(group, variation)
    if (!stride) {
      issues.push('dnp3-unknown-object-variation')
      if (pos < end) {
        maskInPlace(buffer, pos, end - pos, packetIndex, intents)
        coverage.push({
          protocol: 'dnp3-values',
          offset: absoluteBase + pos,
          length: end - pos,
          status: 'redacted',
        })
      }
      break
    }

    const indexPrefix = range.indexPrefixBytes || stride.indexPrefixBytes
    const count = range.objectCount
    if (count === 0 && qualifier === 0x00) {
      continue
    }
    for (let o = 0; o < count; o++) {
      if (pos + indexPrefix + stride.valueSize > end) {
        issues.push('dnp3-object-truncated')
        maskInPlace(buffer, pos, end - pos, packetIndex, intents)
        coverage.push({
          protocol: 'dnp3-values',
          offset: absoluteBase + pos,
          length: end - pos,
          status: 'redacted',
        })
        return { coverage, issues }
      }
      if (indexPrefix > 0) {
        coverage.push({
          protocol: 'dnp3',
          offset: absoluteBase + pos,
          length: indexPrefix,
          status: 'covered',
        })
        pos += indexPrefix
      }
      if (stride.valueSize > 0) {
        maskInPlace(buffer, pos, stride.valueSize, packetIndex, intents)
        coverage.push({
          protocol: 'dnp3-values',
          offset: absoluteBase + pos,
          length: stride.valueSize,
          status: 'redacted',
        })
        pos += stride.valueSize
      }
    }
    issues.push('dnp3-object-dictionary-walk')
  }

  if (pos < end) {
    maskInPlace(buffer, pos, end - pos, packetIndex, intents)
    coverage.push({
      protocol: 'dnp3-body',
      offset: absoluteBase + pos,
      length: end - pos,
      status: 'redacted',
    })
  }

  return { coverage, issues }
}
