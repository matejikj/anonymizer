import { describe, expect, it } from 'vitest'
import {
  PCAP_PROCESSING_PROTOCOL_VERSION,
  validateProcessingProtocolVersion,
  PCAP_PROCESSING_WORKER_ERROR,
  type WireCoverageEntry,
  type WireEntityEntry,
  type WirePacketSummary,
} from '../../src/pcap/processing/workerProtocol.ts'
import {
  PCAP_EXPORT_PROTOCOL_VERSION,
  validateExportProtocolVersion,
  PCAP_EXPORT_WORKER_ERROR,
} from '../../src/pcap/export/workerProtocol.ts'
import { WORKER_PROTOCOL_VERSIONS } from './primitives.ts'

describe('conformance — PCAP worker ports', () => {
  it('processing wire DTOs are typed (no unknown[] payloads)', () => {
    const coverage: WireCoverageEntry = {
      protocolId: 'eth',
      packetCount: 1,
      unsupportedCount: 0,
      issues: [],
    }
    const entity: WireEntityEntry = {
      key: 'ip:10.0.0.1',
      category: 'ipv4',
      value: '10.0.0.1',
      firstPacket: 1,
      count: 1,
    }
    const summary: WirePacketSummary = {
      packetNumber: 1,
      protocols: ['eth', 'ipv4'],
      issues: [],
      hasUnsupported: false,
    }
    expect(coverage.protocolId).toBe('eth')
    expect(entity.key).toContain('ip')
    expect(summary.hasUnsupported).toBe(false)
  })

  it('validates processing protocol version', () => {
    expect(validateProcessingProtocolVersion(PCAP_PROCESSING_PROTOCOL_VERSION)).toBeNull()
    expect(validateProcessingProtocolVersion(0)).toBe(
      PCAP_PROCESSING_WORKER_ERROR.invalidVersion,
    )
  })

  it('validates export protocol version on all request kinds', () => {
    expect(validateExportProtocolVersion(PCAP_EXPORT_PROTOCOL_VERSION)).toBeNull()
    expect(validateExportProtocolVersion(0)).toBe(PCAP_EXPORT_WORKER_ERROR.invalidVersion)
  })

  it('exposes stable worker protocol version map', () => {
    // 6 — R10 packed discover transfer; 7 — rollup reassembly/malformed span counts.
    expect(WORKER_PROTOCOL_VERSIONS.pcapProcessing).toBe(9)
    expect(WORKER_PROTOCOL_VERSIONS.pcapExport).toBe(3)
  })
})
