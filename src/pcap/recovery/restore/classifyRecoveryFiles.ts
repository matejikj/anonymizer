/**
 * Role detection for recovery unlock — magic bytes, not file extension.
 */

import { probeFormat } from '../../capture/probe'
import { RECOVERY_MAGIC_BYTES } from '../codec/formatConstants'

export type RecoveryFileRole = 'anonymized' | 'recovery' | 'unknown'

function magicEquals(head: Uint8Array, expected: Uint8Array): boolean {
  if (head.byteLength < expected.byteLength) return false
  for (let i = 0; i < expected.byteLength; i++) {
    if (head[i] !== expected[i]) return false
  }
  return true
}

export async function classifyRecoveryFileRole(file: File): Promise<RecoveryFileRole> {
  const head = new Uint8Array(await file.slice(0, 16).arrayBuffer())
  if (magicEquals(head, RECOVERY_MAGIC_BYTES)) return 'recovery'
  const copy = head.slice()
  const probed = probeFormat(copy.buffer)
  if (probed.format != null) return 'anonymized'
  return 'unknown'
}

export async function mergeRecoveryPairFiles(input: {
  incoming: readonly File[]
  anonymizedFile: File | null
  recoveryFile: File | null
}): Promise<{
  anonymizedFile: File | null
  recoveryFile: File | null
  unknownCount: number
  duplicateRole: RecoveryFileRole | null
}> {
  let anonymizedFile = input.anonymizedFile
  let recoveryFile = input.recoveryFile
  let unknownCount = 0
  let duplicateRole: RecoveryFileRole | null = null

  for (const file of input.incoming) {
    const role = await classifyRecoveryFileRole(file)
    if (role === 'anonymized') {
      if (anonymizedFile && anonymizedFile !== file) duplicateRole = 'anonymized'
      anonymizedFile = file
    } else if (role === 'recovery') {
      if (recoveryFile && recoveryFile !== file) duplicateRole = 'recovery'
      recoveryFile = file
    } else {
      unknownCount += 1
    }
  }

  return { anonymizedFile, recoveryFile, unknownCount, duplicateRole }
}
