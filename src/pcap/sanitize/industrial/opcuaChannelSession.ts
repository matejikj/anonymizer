/**
 * T30 — capture-scoped OPC UA SecureChannel SecurityMode from OPN (Sign vs SignAndEncrypt).
 */

import type { ApplicationFlowEndpoint } from '../applicationDispatchTypes.ts'

export type OpcuaSecurityMode = 'unknown' | 'none' | 'sign' | 'sign-and-encrypt'

export class OpcuaChannelSession {
  private readonly modes = new Map<string, OpcuaSecurityMode>()

  flowKey(
    flowEndpoint: ApplicationFlowEndpoint | null,
    srcPort: number,
    dstPort: number,
  ): string {
    if (flowEndpoint) {
      return `${flowEndpoint.srcIp}:${srcPort}->${flowEndpoint.dstIp}:${dstPort}`
    }
    return `ports:${srcPort}->${dstPort}`
  }

  setSecurityMode(flowKey: string, mode: OpcuaSecurityMode): void {
    this.modes.set(flowKey, mode)
  }

  getSecurityMode(flowKey: string): OpcuaSecurityMode {
    return this.modes.get(flowKey) ?? 'unknown'
  }
}

/** OPC UA MessageSecurityMode (Part 4). */
export function opcuaSecurityModeFromWire(value: number): OpcuaSecurityMode {
  switch (value) {
    case 1:
      return 'none'
    case 2:
      return 'sign'
    case 3:
      return 'sign-and-encrypt'
    default:
      return 'unknown'
  }
}
