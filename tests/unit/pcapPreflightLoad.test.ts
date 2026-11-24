import { describe, expect, it, beforeEach, vi } from 'vitest'
import {
  clearPcapSession,
  createMinimalPcapSession,
  getPcapSession,
} from '../../src/pcap/ui/pcapSession.ts'
import { CaptureFormat } from '../../src/pcap/domain/types.ts'
import { usePcapStore } from '../../src/pcap/ui/pcapStore.ts'
import { useAppStore } from '../../src/app/store.ts'
import {
  cancelPcapReplace,
  loadPcapFile,
} from '../../src/pcap/ui/pcapLoadController.ts'
import { MAX_PCAP_FILE_BYTES } from '../../src/domain/capabilityContract.ts'
import { PCAP_MAGIC_MICRO_LE } from '../../src/pcap/domain/types.ts'

function seedSession(fileName = 'existing.pcap'): void {
  createMinimalPcapSession({
    fileName,
    fileSize: 128,
    format: CaptureFormat.ClassicPcap,
  })
}

function mockFile(size: number, magic = PCAP_MAGIC_MICRO_LE, name = 'new.pcap'): File {
  const prefix = new Uint8Array(4)
  new DataView(prefix.buffer).setUint32(0, magic, true)
  const file = new File([prefix], name, { type: 'application/octet-stream' })
  Object.defineProperty(file, 'size', { value: size, configurable: true })
  return file
}

describe('pcap load preflight integration', () => {
  beforeEach(() => {
    clearPcapSession()
    usePcapStore.setState({
      phase: 'workspace',
      replaceDialog: 'none',
      pendingReplaceFileName: null,
      errorMessage: null,
    })
    useAppStore.setState({ toast: null })
  })

  it('does not destroy an open session when preflight rejects oversize input', async () => {
    seedSession()
    usePcapStore.getState().setPhase('workspace')

    await loadPcapFile(mockFile(MAX_PCAP_FILE_BYTES + 1))

    expect(getPcapSession()?.fileName).toBe('existing.pcap')
    expect(usePcapStore.getState().phase).toBe('workspace')
    expect(useAppStore.getState().toast?.message).toContain('+1 B')
  })

  it('opens replace dialog after successful preflight when a session is open', async () => {
    seedSession()
    usePcapStore.getState().setPhase('workspace')

    await loadPcapFile(mockFile(256, PCAP_MAGIC_MICRO_LE, 'replacement.pcap'))

    expect(getPcapSession()?.fileName).toBe('existing.pcap')
    expect(usePcapStore.getState().replaceDialog).toBe('open')
    expect(usePcapStore.getState().pendingReplaceFileName).toBe('replacement.pcap')
  })

  it('keeps the session when replace dialog is cancelled', async () => {
    seedSession()
    usePcapStore.getState().setPhase('workspace')
    await loadPcapFile(mockFile(256, PCAP_MAGIC_MICRO_LE, 'replacement.pcap'))

    cancelPcapReplace()

    expect(getPcapSession()?.fileName).toBe('existing.pcap')
    expect(usePcapStore.getState().replaceDialog).toBe('none')
  })

  it('does not call full-file arrayBuffer during preflight rejection', async () => {
    const file = mockFile(MAX_PCAP_FILE_BYTES + 1)
    file.arrayBuffer = vi.fn(async () => {
      throw new Error('should not read whole file')
    })

    await loadPcapFile(file)

    expect(file.arrayBuffer).not.toHaveBeenCalled()
  })
})
