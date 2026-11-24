/**
 * T51 — pinned QSIG ROSE operation baseline (ECMA-143/165 + reviewed supplementary services).
 * Local operation integers shared across PISN GF; argument ASN.1 is service-specific.
 * Not a full ECMA catalog — unknown opcodes fail closed on argument bytes only.
 */

/** QSIG local operation values (ECMA GF / Wikipedia opcode table, verified against ECMA-164/174/178). */
export const QSIG_OP = {
  CALLING_NAME: 0,
  CALLED_NAME: 1,
  CONNECTED_NAME: 2,
  BUSY_NAME: 3,
  CALL_TRANSFER_IDENTITY: 7,
  CALL_TRANSFER_INITIATE: 9,
  CALL_TRANSFER_SETUP: 10,
  CALL_TRANSFER_ACTIVE: 11,
  CALL_TRANSFER_COMPLETE: 12,
  ACTIVATE_DIVERSION: 15,
  DEACTIVATE_DIVERSION: 16,
  INTERROGATE_DIVERSION: 17,
  CALL_REROUTING: 19,
  DIVERTING_LEG_INFO1: 20,
  DIVERTING_LEG_INFO2: 21,
  DIVERTING_LEG_INFO3: 22,
} as const

export type QsigOperationRole = 'name' | 'transfer' | 'diversion'

export interface QsigPinnedOperation {
  readonly opcode: number
  readonly name: string
  readonly ecma: string
  readonly role: QsigOperationRole
}

/** Argument sanitization policy per pinned operation (BER walk inside ROSE argument). */
export const QSIG_PINNED_OPERATIONS: Readonly<Record<number, QsigPinnedOperation>> = {
  [QSIG_OP.CALLING_NAME]: {
    opcode: QSIG_OP.CALLING_NAME,
    name: 'callingName',
    ecma: 'ECMA-164',
    role: 'name',
  },
  [QSIG_OP.CALLED_NAME]: {
    opcode: QSIG_OP.CALLED_NAME,
    name: 'calledName',
    ecma: 'ECMA-164',
    role: 'name',
  },
  [QSIG_OP.CONNECTED_NAME]: {
    opcode: QSIG_OP.CONNECTED_NAME,
    name: 'connectedName',
    ecma: 'ECMA-164',
    role: 'name',
  },
  [QSIG_OP.BUSY_NAME]: {
    opcode: QSIG_OP.BUSY_NAME,
    name: 'busyName',
    ecma: 'ECMA-164',
    role: 'name',
  },
  [QSIG_OP.CALL_TRANSFER_IDENTITY]: {
    opcode: QSIG_OP.CALL_TRANSFER_IDENTITY,
    name: 'callTransferIdentity',
    ecma: 'ECMA-178',
    role: 'transfer',
  },
  [QSIG_OP.CALL_TRANSFER_INITIATE]: {
    opcode: QSIG_OP.CALL_TRANSFER_INITIATE,
    name: 'callTransferInitiate',
    ecma: 'ECMA-178',
    role: 'transfer',
  },
  [QSIG_OP.CALL_TRANSFER_SETUP]: {
    opcode: QSIG_OP.CALL_TRANSFER_SETUP,
    name: 'callTransferSetup',
    ecma: 'ECMA-178',
    role: 'transfer',
  },
  [QSIG_OP.CALL_TRANSFER_ACTIVE]: {
    opcode: QSIG_OP.CALL_TRANSFER_ACTIVE,
    name: 'callTransferActive',
    ecma: 'ECMA-178',
    role: 'transfer',
  },
  [QSIG_OP.CALL_TRANSFER_COMPLETE]: {
    opcode: QSIG_OP.CALL_TRANSFER_COMPLETE,
    name: 'callTransferComplete',
    ecma: 'ECMA-178',
    role: 'transfer',
  },
  [QSIG_OP.ACTIVATE_DIVERSION]: {
    opcode: QSIG_OP.ACTIVATE_DIVERSION,
    name: 'activateDiversionQ',
    ecma: 'ECMA-174',
    role: 'diversion',
  },
  [QSIG_OP.DEACTIVATE_DIVERSION]: {
    opcode: QSIG_OP.DEACTIVATE_DIVERSION,
    name: 'deactivateDiversionQ',
    ecma: 'ECMA-174',
    role: 'diversion',
  },
  [QSIG_OP.INTERROGATE_DIVERSION]: {
    opcode: QSIG_OP.INTERROGATE_DIVERSION,
    name: 'interrogateDiversionQ',
    ecma: 'ECMA-174',
    role: 'diversion',
  },
  [QSIG_OP.CALL_REROUTING]: {
    opcode: QSIG_OP.CALL_REROUTING,
    name: 'callRerouting',
    ecma: 'ECMA-174',
    role: 'diversion',
  },
  [QSIG_OP.DIVERTING_LEG_INFO1]: {
    opcode: QSIG_OP.DIVERTING_LEG_INFO1,
    name: 'divertingLegInformation1',
    ecma: 'ECMA-174',
    role: 'diversion',
  },
  [QSIG_OP.DIVERTING_LEG_INFO2]: {
    opcode: QSIG_OP.DIVERTING_LEG_INFO2,
    name: 'divertingLegInformation2',
    ecma: 'ECMA-174',
    role: 'diversion',
  },
  [QSIG_OP.DIVERTING_LEG_INFO3]: {
    opcode: QSIG_OP.DIVERTING_LEG_INFO3,
    name: 'divertingLegInformation3',
    ecma: 'ECMA-174',
    role: 'diversion',
  },
}

export function qsigPinnedOperation(opcode: number): QsigPinnedOperation | undefined {
  return QSIG_PINNED_OPERATIONS[opcode]
}

/** ECMA-165 Facility APDU context tags (IMPLICIT TAGS module). */
export const QSIG_FACILITY_TAG = {
  ROSE_INVOKE: 1,
  ROSE_RETURN_RESULT: 2,
  ROSE_RETURN_ERROR: 3,
  ROSE_REJECT: 4,
  NFE: 10,
  INTERPRETATION: 11,
} as const
