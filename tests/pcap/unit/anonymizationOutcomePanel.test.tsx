/**
 * @vitest-environment happy-dom
 */
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { AnonymizationOutcomePanel } from '../../../src/pcap/ui/AnonymizationOutcomePanel'
import { usePcapStore } from '../../../src/pcap/ui/pcapStore'
import { clearPcapSession } from '../../../src/pcap/ui/pcapSession'
import type { AnonymizationOutcome } from '../../../src/pcap/coverage/anonymizationOutcome'

vi.mock('../../../src/pcap/ui/pcapLoadController.ts', () => ({
  refreshPcapFilter: vi.fn(),
}))

const sampleOutcome: AnonymizationOutcome = {
  summarySentence: 'Ve vašem souboru jsou protokoly SIP. Anonymizace vypadá v pořádku — soubor je připravený pro AI.',
  gate: 'AI_READY',
  gateLabel: 'Připraveno pro AI',
  families: [
    {
      familyId: 'sip',
      familyLabel: 'SIP',
      state: 'anonymized',
      stateLabel: 'Anonymizováno',
      packetCount: 4,
      explanation: '4 paketů — identity nahrazené',
      recommendation: 'V pořádku',
      filterProtocol: 'sip',
      probable: false,
    },
  ],
  incidents: [],
  incidentTotal: 0,
  incidentMoreCount: 0,
  maskedPacketRanges: [],
  supportRequests: [],
  diagnosticImpact: {
    analyzableFamilyCount: 1,
    maskedWithoutAnalysisFamilyCount: 0,
    needsAttentionFamilyCount: 0,
    processingFailedPacketCount: 0,
  },
}

describe('AnonymizationOutcomePanel', () => {
  beforeEach(() => {
    clearPcapSession()
    usePcapStore.getState().resetToEmpty()
  })

  afterEach(() => {
    clearPcapSession()
  })

  it('renders summary, gate, and family rows', () => {
    render(<AnonymizationOutcomePanel outcome={sampleOutcome} testId="outcome" />)
    expect(screen.getByTestId('outcome')).toBeTruthy()
    expect(screen.getByTestId('outcome-summary').textContent).toContain('připravený pro AI')
    expect(screen.getByTestId('outcome-gate').getAttribute('data-gate')).toBe('AI_READY')
    expect(screen.getByTestId('outcome-family-sip')).toBeTruthy()
  })

  it('show packets sets protocol filter', async () => {
    const { refreshPcapFilter } = await import('../../../src/pcap/ui/pcapLoadController.ts')
    render(<AnonymizationOutcomePanel outcome={sampleOutcome} testId="outcome" />)
    fireEvent.click(screen.getByTestId('outcome-show-sip'))
    expect(usePcapStore.getState().filter.protocol).toBe('sip')
    await Promise.resolve()
    expect(refreshPcapFilter).toHaveBeenCalled()
  })

  it('renders copy-support action for unsupported protocols', () => {
    const writeText = vi.fn()
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    })
    const withSupport: AnonymizationOutcome = {
      ...sampleOutcome,
      supportRequests: [
        {
          code: 'unsupported:ssdp',
          family: 'SSDP',
          packetCount: 3,
          flowCount: 0,
          message: 'Protokol unsupported:ssdp (3 paketů) byl kvůli ochraně dat zamaskován.',
          clipboardText: 'kód: unsupported:ssdp\n',
        },
      ],
    }
    render(<AnonymizationOutcomePanel outcome={withSupport} testId="outcome" />)
    expect(screen.getByTestId('outcome-support-requests')).toBeTruthy()
    fireEvent.click(screen.getByTestId('outcome-copy-support-unsupported:ssdp'))
    expect(writeText).toHaveBeenCalledWith('kód: unsupported:ssdp\n')
  })
})
