/**
 * Guards against overclaiming finished kernel status in live code metadata.
 * Construction-time overview markdown was removed for the public tree.
 */

import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { APPLICATION_HANDLER_ORDER } from '../../src/pcap/kernel/applicationHandlers'
import {
  APPLICATION_DISPATCH_REGISTRY,
  TEMP_LEGACY_INLINE_HANDLERS,
} from '../../src/pcap/sanitize/applicationDispatchRegistry'

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '../..')

describe('anonymization honesty guards (code, not construction docs)', () => {
  it('does not ship obsolete overview / ANONYMIZER construction markdown', () => {
    expect(existsSync(join(rootDir, 'ANONYMIZER.md'))).toBe(false)
    expect(existsSync(join(rootDir, 'docs/PCAP_ANONYMIZATION_OVERVIEW.md'))).toBe(false)
    expect(existsSync(join(rootDir, 'docs'))).toBe(false)
  })

  it('keeps application dispatch registry coverage honest', () => {
    const orderCount = APPLICATION_HANDLER_ORDER.length
    const registryCount = APPLICATION_DISPATCH_REGISTRY.size
    expect(registryCount).toBeGreaterThan(0)
    expect(orderCount).toBeGreaterThanOrEqual(registryCount)
    // intentional inline tail may remain unregistered
    expect(TEMP_LEGACY_INLINE_HANDLERS.size).toBe(orderCount - registryCount)
    expect(registryCount).toBeGreaterThanOrEqual(orderCount - 1)
  })
})
