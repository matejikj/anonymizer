/**
 * Wireshark-compatible display filter parser (step 2 subset).
 */

import type { CompareOp, FilterExpr, FilterValue, ParseResult, ParseStatus } from './types'
import { SANITIZER_PROTOCOL_IDS } from '../coverage/protocolRegistry'
import { isFilterableProtocolToken } from '../coverage/protocolFamilies'

const FIELDS = new Set([
  'ip.addr', 'ip.src', 'ip.dst', 'tcp.port', 'udp.port',
  'frame.number', 'frame.len', 'frame.changed', 'frame.issue', 'eth.addr', 'protocol',
])

const PROTOCOL_TOKENS = new Set([
  ...SANITIZER_PROTOCOL_IDS,
  'dhcpv4', 'tls-clienthello', 'tls-serverhello', 'tls-certificate',
  'tls-handshake-unsupported', 'tls-encrypted-payload', 'tls',
  'arp', 'icmp', 'icmpv4', 'icmpv6', 'tcp', 'udp', 'ipv4', 'ipv6',
  'ethernet', 'vlan', 'fragment', 'payload', 'gre', 'vxlan', 'sll', 'sll2', 'link',
])

interface Token {
  readonly kind: 'ident' | 'number' | 'string' | 'op' | 'lparen' | 'rparen' | 'eof'
  readonly text: string
  readonly start: number
  readonly end: number
}

export function parseDisplayFilter(input: string): ParseResult {
  const trimmed = input.trim()
  if (trimmed.length === 0) {
    return { status: 'valid', expr: null, error: null }
  }
  const tokens = tokenize(trimmed)
  if (tokens.error) {
    return { status: 'invalid', expr: null, error: tokens.error }
  }
  const parser = new Parser(tokens.tokens)
  const expr = parser.parseExpr()
  if (parser.error) {
    const status: ParseStatus = parser.incomplete ? 'incomplete' : 'invalid'
    return { status, expr: null, error: parser.error }
  }
  if (parser.peek().kind !== 'eof') {
    return {
      status: 'invalid',
      expr: null,
      error: { message: `Unexpected token '${parser.peek().text}'`, offset: parser.peek().start },
    }
  }
  return { status: 'valid', expr, error: null }
}

function tokenize(input: string): { tokens: Token[]; error: { message: string; offset: number } | null } {
  const tokens: Token[] = []
  let i = 0
  while (i < input.length) {
    const ch = input[i]!
    if (/\s/.test(ch)) { i++; continue }
    const start = i
    if (ch === '(') { tokens.push({ kind: 'lparen', text: '(', start, end: i + 1 }); i++; continue }
    if (ch === ')') { tokens.push({ kind: 'rparen', text: ')', start, end: i + 1 }); i++; continue }
    if (ch === '"' || ch === "'") {
      const quote = ch
      i++
      let value = ''
      while (i < input.length && input[i] !== quote) {
        if (input[i] === '\\' && i + 1 < input.length) { value += input[i + 1]; i += 2; continue }
        value += input[i]
        i++
      }
      if (i >= input.length) {
        return { tokens, error: { message: 'Unterminated string literal', offset: start } }
      }
      i++
      tokens.push({ kind: 'string', text: value, start, end: i })
      continue
    }
    if (/[0-9]/.test(ch) || (ch === '-' && i + 1 < input.length && /[0-9]/.test(input[i + 1]!))) {
      let num = ch === '-' ? '-' : ''
      if (ch === '-') i++
      while (i < input.length && /[0-9.]/.test(input[i]!)) { num += input[i]; i++ }
      tokens.push({ kind: 'number', text: num, start, end: i })
      continue
    }
    if (/[a-zA-Z_.]/.test(ch)) {
      let ident = ''
      while (i < input.length && /[a-zA-Z0-9_.-]/.test(input[i]!)) { ident += input[i]; i++ }
      // T09 — `unsupported:<name>` is one protocol token (colon allowed only here).
      if (ident.toLowerCase() === 'unsupported' && input[i] === ':') {
        ident += ':'
        i++
        while (i < input.length && /[a-zA-Z0-9_-]/.test(input[i]!)) {
          ident += input[i]
          i++
        }
      }
      if (/^[0-9a-fA-F]{2}$/.test(ident)) {
        let mac = ident
        let octets = 1
        while (
          octets < 6
          && i + 3 <= input.length
          && input[i] === ':'
          && /^[0-9a-fA-F]{2}$/.test(input.slice(i + 1, i + 3))
        ) {
          mac += input.slice(i, i + 3)
          i += 3
          octets++
        }
        if (octets === 6) {
          tokens.push({ kind: 'string', text: mac.toLowerCase(), start, end: i })
          continue
        }
      }
      const lower = ident.toLowerCase()
      if (lower === 'and' || lower === 'or' || lower === 'not' || lower === 'contains') {
        tokens.push({ kind: 'op', text: lower, start, end: i })
      } else if (ident === '==' || ident === '!=' || ident === '>=' || ident === '<=' || ident === '>' || ident === '<') {
        tokens.push({ kind: 'op', text: ident, start, end: i })
      } else {
        tokens.push({ kind: 'ident', text: ident, start, end: i })
      }
      continue
    }
    if (input.startsWith('==', i) || input.startsWith('!=', i) || input.startsWith('>=', i) || input.startsWith('<=', i)) {
      const op = input.slice(i, i + 2)
      tokens.push({ kind: 'op', text: op, start, end: i + 2 })
      i += 2
      continue
    }
    if (ch === '>' || ch === '<') {
      tokens.push({ kind: 'op', text: ch, start, end: i + 1 })
      i++
      continue
    }
    return { tokens, error: { message: `Unexpected character '${ch}'`, offset: i } }
  }
  tokens.push({ kind: 'eof', text: '', start: input.length, end: input.length })
  return { tokens, error: null }
}

class Parser {
  tokens: Token[]
  pos = 0
  error: { message: string; offset: number } | null = null
  incomplete = false

  constructor(tokens: Token[]) {
    this.tokens = tokens
  }

  peek(): Token {
    return this.tokens[this.pos] ?? { kind: 'eof', text: '', start: 0, end: 0 }
  }

  consume(): Token {
    const t = this.peek()
    if (t.kind !== 'eof') this.pos++
    return t
  }

  parseExpr(): FilterExpr | null {
    return this.parseOr()
  }

  private parseOr(): FilterExpr | null {
    let left = this.parseAnd()
    if (!left) return null
    while (this.peek().kind === 'op' && this.peek().text === 'or') {
      this.consume()
      const right = this.parseAnd()
      if (!right) { this.incomplete = true; this.error ??= { message: 'Expected expression after or', offset: this.peek().start }; return null }
      left = { kind: 'or', left, right }
    }
    return left
  }

  private parseAnd(): FilterExpr | null {
    let left = this.parseNot()
    if (!left) return null
    while (this.peek().kind === 'op' && this.peek().text === 'and') {
      this.consume()
      const right = this.parseNot()
      if (!right) { this.incomplete = true; this.error ??= { message: 'Expected expression after and', offset: this.peek().start }; return null }
      left = { kind: 'and', left, right }
    }
    return left
  }

  private parseNot(): FilterExpr | null {
    if (this.peek().kind === 'op' && this.peek().text === 'not') {
      this.consume()
      const expr = this.parseNot()
      if (!expr) { this.incomplete = true; this.error ??= { message: 'Expected expression after not', offset: this.peek().start }; return null }
      return { kind: 'not', expr }
    }
    return this.parsePrimary()
  }

  private parsePrimary(): FilterExpr | null {
    const t = this.peek()
    if (t.kind === 'lparen') {
      this.consume()
      const inner = this.parseExpr()
      if (!inner) return null
      if (this.peek().kind !== 'rparen') {
        this.incomplete = true
        this.error ??= { message: 'Expected closing parenthesis', offset: this.peek().start }
        return null
      }
      this.consume()
      return inner
    }
    if (t.kind === 'ident') {
      const ident = t.text.toLowerCase()
      const knownProtocol =
        (PROTOCOL_TOKENS.has(ident) || isFilterableProtocolToken(ident)) && !FIELDS.has(ident)
      if (knownProtocol) {
        const next = this.tokens[this.pos + 1]
        const followedByFieldCompare =
          next?.kind === 'ident' && FIELDS.has(next.text.toLowerCase())
        if (!followedByFieldCompare) {
          this.consume()
          return { kind: 'protocol', name: ident }
        }
      }
      if (!FIELDS.has(ident)) {
        this.error = { message: `Unsupported field or protocol '${t.text}'`, offset: t.start }
        return null
      }
      const field = t.text
      this.consume()
      let op: CompareOp
      const opTok = this.peek()
      if (opTok.kind === 'op' && opTok.text === 'contains') {
        this.consume()
        op = 'contains'
      } else if (opTok.kind === 'op' && ['==', '!=', '>=', '<=', '>', '<'].includes(opTok.text)) {
        op = opTok.text as CompareOp
        this.consume()
      } else {
        this.error = { message: `Expected comparison operator after '${field}'`, offset: opTok.start }
        return null
      }
      const value = this.parseValue()
      if (value === undefined) return null
      return { kind: 'compare', field, op, value }
    }
    this.error = { message: `Expected field name or protocol, got '${t.text}'`, offset: t.start }
    return null
  }

  private parseValue(): FilterValue | undefined {
    const t = this.peek()
    if (t.kind === 'string') {
      this.consume()
      return t.text
    }
    if (t.kind === 'number') {
      this.consume()
      if (/^\d+\.\d+\.\d+\.\d+$/.test(t.text)) {
        return t.text
      }
      return Number.parseFloat(t.text)
    }
    if (t.kind === 'ident') {
      const lower = t.text.toLowerCase()
      if (lower === 'true') { this.consume(); return true }
      if (lower === 'false') { this.consume(); return false }
      this.consume()
      return t.text
    }
    this.error = { message: 'Expected value', offset: t.start }
    return undefined
  }
}

export function filterSuggestions(partial: string): string[] {
  const tail = partial.trim().split(/\s+/).pop()?.toLowerCase() ?? ''
  const all = [
    ...FIELDS,
    ...PROTOCOL_TOKENS,
    'and', 'or', 'not', 'contains', '==', '!=', '>=', '<=',
    'frame.changed == true', 'frame.issue == true', 'ip.addr == ',
    'tcp.port == ', 'udp.port == ', 'frame.number == ',
  ]
  return all.filter((s) => s.startsWith(tail) && s !== tail).slice(0, 12)
}
