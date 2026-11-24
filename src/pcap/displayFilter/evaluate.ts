/**
 * Display filter evaluation (step 2).
 */

import type { FilterExpr, PacketFilterContext } from './types'

export function evaluateDisplayFilter(expr: FilterExpr | null, ctx: PacketFilterContext): boolean {
  if (!expr) return true
  switch (expr.kind) {
    case 'and':
      return evaluateDisplayFilter(expr.left, ctx) && evaluateDisplayFilter(expr.right, ctx)
    case 'or':
      return evaluateDisplayFilter(expr.left, ctx) || evaluateDisplayFilter(expr.right, ctx)
    case 'not':
      return !evaluateDisplayFilter(expr.expr, ctx)
    case 'protocol':
      return ctx.protocols.some((p) => p.toLowerCase() === expr.name || p.toLowerCase().includes(expr.name))
    case 'compare':
      return evalCompare(expr.field.toLowerCase(), expr.op, expr.value, ctx)
    default:
      return false
  }
}

function evalCompare(
  field: string,
  op: string,
  value: string | number | boolean,
  ctx: PacketFilterContext,
): boolean {
  switch (field) {
    case 'ip.addr':
      return compareStr(op, String(value), ctx.srcIpv4) || compareStr(op, String(value), ctx.dstIpv4)
    case 'ip.src':
      return compareStr(op, String(value), ctx.srcIpv4)
    case 'ip.dst':
      return compareStr(op, String(value), ctx.dstIpv4)
    case 'eth.addr':
      return compareStr(op, String(value).toLowerCase(), ctx.srcMac?.toLowerCase())
        || compareStr(op, String(value).toLowerCase(), ctx.dstMac?.toLowerCase())
    case 'tcp.port':
      if (ctx.l4Proto !== 'tcp') return false
      return compareNum(op, Number(value), ctx.srcPort) || compareNum(op, Number(value), ctx.dstPort)
    case 'udp.port':
      if (ctx.l4Proto !== 'udp') return false
      return compareNum(op, Number(value), ctx.srcPort) || compareNum(op, Number(value), ctx.dstPort)
    case 'frame.number':
      return compareNum(op, Number(value), ctx.packetNumber)
    case 'frame.len':
      return compareNum(op, Number(value), ctx.capturedLength)
    case 'frame.changed':
      return compareBool(op, Boolean(value), ctx.changed)
    case 'frame.issue':
      return compareBool(op, Boolean(value), ctx.hasIssue)
    case 'protocol':
      return compareStr(op, String(value).toLowerCase(), ctx.protocols.join(',').toLowerCase())
    default:
      return false
  }
}

function compareStr(op: string, expected: string, actual: string | undefined): boolean {
  if (actual === undefined) return op === '!=' 
  switch (op) {
    case '==': return actual === expected
    case '!=': return actual !== expected
    case 'contains': return actual.includes(expected)
    default: return false
  }
}

function compareNum(op: string, expected: number, actual: number | undefined): boolean {
  if (actual === undefined || Number.isNaN(expected)) return false
  switch (op) {
    case '==': return actual === expected
    case '!=': return actual !== expected
    case '>': return actual > expected
    case '<': return actual < expected
    case '>=': return actual >= expected
    case '<=': return actual <= expected
    default: return false
  }
}

function compareBool(op: string, expected: boolean, actual: boolean): boolean {
  switch (op) {
    case '==': return actual === expected
    case '!=': return actual !== expected
    default: return false
  }
}

export function buildFilterContext(input: {
  packetIndex: number
  packetNumber: number
  capturedLength: number
  linkType: number
  data: Uint8Array
  protocols: readonly string[]
  changed: boolean
  hasIssue: boolean
}): PacketFilterContext {
  const ctx: PacketFilterContext = { ...input }
  if (input.linkType === 1 && input.data.length >= 34 && input.data[12] === 0x08 && input.data[13] === 0x00) {
    return {
      ...ctx,
      srcIpv4: fmtIp4(input.data, 26),
      dstIpv4: fmtIp4(input.data, 30),
      srcMac: fmtMac(input.data, 6),
      dstMac: fmtMac(input.data, 0),
      l4Proto: input.data[23] === 6 ? 'tcp' : input.data[23] === 17 ? 'udp' : undefined,
      srcPort: input.data.length >= 36 ? rd16(input.data, 34) : undefined,
      dstPort: input.data.length >= 38 ? rd16(input.data, 36) : undefined,
    }
  }
  if (input.linkType === 1 && input.data.length >= 14) {
    return {
      ...ctx,
      srcMac: fmtMac(input.data, 6),
      dstMac: fmtMac(input.data, 0),
    }
  }
  return ctx
}

function fmtIp4(data: Uint8Array, off: number): string {
  return `${data[off]}.${data[off + 1]}.${data[off + 2]}.${data[off + 3]}`
}

function fmtMac(data: Uint8Array, off: number): string {
  return Array.from(data.slice(off, off + 6)).map((b) => b.toString(16).padStart(2, '0')).join(':')
}

function rd16(data: Uint8Array, off: number): number {
  return (data[off]! << 8) | data[off + 1]!
}
