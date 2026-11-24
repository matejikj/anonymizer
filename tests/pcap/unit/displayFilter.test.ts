import { describe, expect, it } from 'vitest'
import { parseDisplayFilter, evaluateDisplayFilter, buildFilterContext } from '../../../src/pcap/displayFilter'

describe('displayFilter parser', () => {
  it('parses hyphenated protocol token', () => {
    const r = parseDisplayFilter('sip-tls')
    expect(r.status).toBe('valid')
    expect(r.expr).toEqual({ kind: 'protocol', name: 'sip-tls' })
  })

  it('parses plain protocol token', () => {
    const r = parseDisplayFilter('sip')
    expect(r.status).toBe('valid')
    expect(r.expr).toEqual({ kind: 'protocol', name: 'sip' })
  })

  it('parses field comparison', () => {
    const r = parseDisplayFilter('frame.number == 42')
    expect(r.status).toBe('valid')
    expect(r.expr?.kind).toBe('compare')
  })

  it('parses and/or/not', () => {
    const r = parseDisplayFilter('sip and not frame.issue == true')
    expect(r.status).toBe('valid')
    expect(r.expr?.kind).toBe('and')
  })

  it('reports unsupported field', () => {
    const r = parseDisplayFilter('foo.bar == 1')
    expect(r.status).toBe('invalid')
    expect(r.error?.offset).toBeGreaterThanOrEqual(0)
  })

  it('reports incomplete expression', () => {
    const r = parseDisplayFilter('sip and')
    expect(['incomplete', 'invalid']).toContain(r.status)
  })

  it('evaluates frame.changed', () => {
    const expr = parseDisplayFilter('frame.changed == true').expr
    const ctx = buildFilterContext({
      packetIndex: 0,
      packetNumber: 1,
      capturedLength: 100,
      linkType: 1,
      data: new Uint8Array(42),
      protocols: ['ipv4'],
      changed: true,
      hasIssue: false,
    })
    expect(evaluateDisplayFilter(expr, ctx)).toBe(true)
  })

  it('evaluates eth.addr with unquoted MAC literal', () => {
    const data = new Uint8Array(14)
    data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 0)
    const ctx = buildFilterContext({
      packetIndex: 0,
      packetNumber: 1,
      capturedLength: 14,
      linkType: 1,
      data,
      protocols: ['ethernet'],
      changed: false,
      hasIssue: false,
    })
    const expr = parseDisplayFilter('eth.addr == aa:bb:cc:dd:ee:ff').expr
    expect(expr).not.toBeNull()
    expect(evaluateDisplayFilter(expr, ctx)).toBe(true)
  })

  it('evaluates ip.addr from decoded bytes', () => {
    const data = new Uint8Array(42)
    data.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
    data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
    data[12] = 0x08
    data[13] = 0x00
    data[14] = 0x45
    data[16] = 0
    data[17] = 28
    data[23] = 17
    data.set([192, 168, 1, 10], 26)
    data.set([10, 0, 0, 1], 30)
    const ctx = buildFilterContext({
      packetIndex: 0,
      packetNumber: 1,
      capturedLength: 42,
      linkType: 1,
      data,
      protocols: ['ipv4'],
      changed: false,
      hasIssue: false,
    })
    expect(ctx.srcIpv4).toBe('192.168.1.10')
    const expr = parseDisplayFilter('ip.addr == 192.168.1.10').expr
    expect(evaluateDisplayFilter(expr, ctx)).toBe(true)
  })
})
