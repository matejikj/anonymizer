/**
 * @vitest-environment happy-dom
 */
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { PcapOutcomeDialog } from '../../../src/pcap/ui/PcapOutcomeDialog'
import { usePcapStore } from '../../../src/pcap/ui/pcapStore'
import { clearPcapSession } from '../../../src/pcap/ui/pcapSession'
import type { AnonymizationOutcome } from '../../../src/pcap/coverage/anonymizationOutcome'

const sampleOutcome: AnonymizationOutcome = {
  summarySentence: 'Ve vašem souboru jsou protokoly SIP. Anonymizace vypadá v pořádku.',
  gate: 'AI_READY',
  gateLabel: 'Připraveno pro AI',
  families: [
    {
      familyId: 'sip',
      familyLabel: 'SIP',
      state: 'anonymized',
      stateLabel: 'Anonymizováno',
      packetCount: 4,
      explanation: '4 paketů',
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

vi.mock('../../../src/pcap/ui/getAnonymizationOutcome.ts', () => ({
  getAnonymizationOutcome: () => sampleOutcome,
}))

vi.mock('../../../src/pcap/ui/pcapLoadController.ts', () => ({
  refreshPcapFilter: vi.fn(),
}))

describe('PcapOutcomeDialog', () => {
  beforeEach(() => {
    clearPcapSession()
    usePcapStore.getState().resetToEmpty()
    usePcapStore.getState().setPhase('workspace')
    usePcapStore.getState().setOutcomeDialogOpen(true)
  })

  afterEach(() => {
    clearPcapSession()
    usePcapStore.getState().resetToEmpty()
  })

  it('opens after analysis with closable dialog; closing leaves store flag false', () => {
    render(<PcapOutcomeDialog />)
    expect(screen.getByTestId('pcap-outcome-dialog')).toBeTruthy()
    expect(screen.getByTestId('pcap-workspace-outcome')).toBeTruthy()
    fireEvent.click(screen.getByTestId('pcap-outcome-dialog-close'))
    expect(usePcapStore.getState().outcomeDialogOpen).toBe(false)
  })

  it('show packets closes the dialog', async () => {
    render(<PcapOutcomeDialog />)
    fireEvent.click(screen.getByTestId('pcap-workspace-outcome-show-sip'))
    expect(usePcapStore.getState().outcomeDialogOpen).toBe(false)
    expect(usePcapStore.getState().filter.protocol).toBe('sip')
  })
})
