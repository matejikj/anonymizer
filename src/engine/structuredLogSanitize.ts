/**
 * T43 — structured text log sanitization before detection.worker.
 * Secret keys always mask; identity fields stay for detectors; output keeps format validity.
 * Malformed records are isolated (T07) — never truncate the whole file.
 */

export type StructuredLogFormat =
  | 'ndjson'
  | 'json'
  | 'csv'
  | 'tsv'
  | 'cef'
  | 'leef'
  | 'logfmt'
  | 'access-combined'
  | 'har'
  | 'tshark-json'
  | 'plain'

/** Keys whose values are always masked (no detector opt-out). */
const SECRET_KEY_RE =
  /^(?:pass(?:word)?|passwd|pwd|token|secret|auth(?:orization)?|api[_-]?key|access[_-]?token|refresh[_-]?token|cookie|set-cookie|session(?:[_-]?id)?|bearer|x-api-key|private[_-]?key|client[_-]?secret)$/i

/** Header / field names that hint a delimited table (CSV/TSV). */
const TABLE_HEADER_HINT_RE =
  /^(?:user(?:name)?|email|msisdn|phone|ip|client[_-]?ip|host(?:name)?|src|dst|suser|duser|shost|password|token|secret|timestamp|time|date|level|msg|message)$/i

const CEF_PREFIX = /^CEF:/i
const LEEF_PREFIX = /^LEEF:/i

/** Apache/nginx combined access log (single-line). */
const ACCESS_COMBINED_RE =
  /^(\S+) (\S+) (\S+) \[([^\]]*)\] "([^"]*)" (\d{3}|-) (\d+|-|-)(?: "([^"]*)" "([^"]*)")?/

export interface StructuredSanitizeStats {
  readonly format: StructuredLogFormat
  readonly recordsTotal: number
  readonly recordsSanitized: number
  readonly recordsMalformed: number
  readonly secretFieldsMasked: number
}

export interface StructuredSanitizeResult {
  readonly text: string
  readonly stats: StructuredSanitizeStats
}

export function isSecretStructuredKey(key: string): boolean {
  return SECRET_KEY_RE.test(key.trim())
}

export function detectStructuredLogFormat(text: string): StructuredLogFormat {
  const trimmed = text.trim()
  if (trimmed.length === 0) return 'plain'

  if (looksLikeHar(trimmed)) return 'har'
  if (looksLikeTsharkJson(trimmed)) return 'tshark-json'

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      JSON.parse(trimmed)
      return 'json'
    } catch {
      // may be NDJSON or another line format
    }
  }

  const sampleLines = nonEmptyLines(text, 12)
  if (sampleLines.length === 0) return 'plain'

  if (sampleLines.every((l) => CEF_PREFIX.test(l))) return 'cef'
  if (sampleLines.every((l) => LEEF_PREFIX.test(l))) return 'leef'

  const accessHits = sampleLines.filter((l) => ACCESS_COMBINED_RE.test(l)).length
  if (accessHits >= Math.max(1, Math.ceil(sampleLines.length * 0.7))) return 'access-combined'

  const delim = detectTableDelimiter(text)
  if (delim) return delim === '\t' ? 'tsv' : 'csv'

  const logfmtHits = sampleLines.filter((l) => looksLikeLogfmtLine(l)).length
  if (logfmtHits >= Math.max(1, Math.ceil(sampleLines.length * 0.7))) return 'logfmt'

  let jsonLines = 0
  for (const line of sampleLines) {
    try {
      JSON.parse(line)
      jsonLines++
    } catch {
      return 'plain'
    }
  }
  if (jsonLines === sampleLines.length) return 'ndjson'
  return 'plain'
}

export function sanitizeStructuredLogText(text: string): StructuredSanitizeResult {
  const format = detectStructuredLogFormat(text)
  switch (format) {
    case 'plain':
      return { text, stats: emptyStats('plain') }
    case 'json':
      return sanitizeJsonDocument(text)
    case 'ndjson':
      return sanitizeNdjson(text)
    case 'har':
      return sanitizeHar(text)
    case 'tshark-json':
      return sanitizeTsharkJson(text)
    case 'csv':
      return sanitizeDelimitedTable(text, ',')
    case 'tsv':
      return sanitizeDelimitedTable(text, '\t')
    case 'cef':
      return sanitizeCefFamily(text, 'cef')
    case 'leef':
      return sanitizeCefFamily(text, 'leef')
    case 'logfmt':
      return sanitizeLogfmt(text)
    case 'access-combined':
      return sanitizeAccessCombined(text)
    default:
      return { text, stats: emptyStats('plain') }
  }
}

function emptyStats(format: StructuredLogFormat): StructuredSanitizeStats {
  return {
    format,
    recordsTotal: 0,
    recordsSanitized: 0,
    recordsMalformed: 0,
    secretFieldsMasked: 0,
  }
}

function nonEmptyLines(text: string, max: number): string[] {
  const out: string[] = []
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim()
    if (t.length === 0) continue
    out.push(t)
    if (out.length >= max) break
  }
  return out
}

function looksLikeHar(trimmed: string): boolean {
  if (!(trimmed.startsWith('{') && trimmed.includes('"log"'))) return false
  try {
    const parsed = JSON.parse(trimmed) as { log?: { entries?: unknown; version?: unknown } }
    return Array.isArray(parsed.log?.entries)
  } catch {
    return false
  }
}

function looksLikeTsharkJson(trimmed: string): boolean {
  if (!(trimmed.startsWith('[') || trimmed.startsWith('{'))) return false
  try {
    const parsed = JSON.parse(trimmed) as unknown
    const rows = Array.isArray(parsed) ? parsed : [parsed]
    if (rows.length === 0) return false
    let hits = 0
    for (const row of rows.slice(0, 6)) {
      if (!row || typeof row !== 'object') continue
      const r = row as Record<string, unknown>
      if (r._source && typeof r._source === 'object') hits++
      else if (typeof r._index === 'string' && String(r._index).includes('packets')) hits++
      else if (r.layers && typeof r.layers === 'object') hits++
    }
    return hits >= Math.min(rows.length, 2) || (rows.length === 1 && hits === 1)
  } catch {
    return false
  }
}

function detectTableDelimiter(sampleText: string): ',' | '\t' | null {
  for (const delim of ['\t', ','] as const) {
    const records = splitDelimitedRecords(sampleText, delim)
    if (records.length < 1) continue
    const header = records[0]!
    const cols = splitDelimitedLine(header, delim)
    if (cols.length < 2) continue
    const hintHits = cols.filter((c) => TABLE_HEADER_HINT_RE.test(c.trim().replace(/^"|"$/g, ''))).length
    if (hintHits === 0) continue
    let consistent = 0
    for (const rec of records) {
      if (splitDelimitedLine(rec, delim).length === cols.length) consistent++
    }
    if (consistent >= Math.ceil(records.length * 0.8)) return delim
  }
  return null
}

function looksLikeLogfmtLine(line: string): boolean {
  // at least two key=value tokens; values may be quoted
  const tokens = line.match(/[A-Za-z_][\w.-]*=(?:"(?:\\.|[^"\\])*"|[^\s]+)/g)
  return (tokens?.length ?? 0) >= 2
}

function maskTextPreservingLength(value: string): string {
  if (value.length === 0) return value
  return '*'.repeat(Math.min(value.length, 256))
}

/**
 * V14 — mask secret-keyed values in JSON without JSON.parse/stringify.
 * Preserves raw lexemes (large integers, duplicate keys, whitespace, escapes).
 * Returns null when the document is not a safely walkable JSON text.
 */
export function sanitizeJsonLexemesInPlace(
  text: string,
  isSecretKey: (key: string) => boolean = isSecretStructuredKey,
): { text: string; secretFieldsMasked: number } | null {
  const chars = text.split('')
  let i = 0
  let secretFieldsMasked = 0
  /** Stack: true = object, false = array. */
  const containerIsObject: boolean[] = []
  /** Depth of secret-keyed containers still open (mask all leaves inside). */
  let secretDepth = 0
  let pendingKey: string | null = null
  let afterColon = false
  let maskNextValue = false

  const skipWs = () => {
    while (i < chars.length && (chars[i] === ' ' || chars[i] === '\t' || chars[i] === '\n' || chars[i] === '\r')) {
      i++
    }
  }

  const inObject = () => containerIsObject.length > 0 && containerIsObject[containerIsObject.length - 1] === true

  const maskRange = (start: number, end: number, mode: 'string' | 'number') => {
    for (let p = start; p < end; p++) {
      const ch = chars[p]!
      if (mode === 'string') {
        if (ch !== '\\') chars[p] = '*'
      } else if (/[0-9a-fA-FxX+]/.test(ch)) {
        chars[p] = ch === '+' || ch === 'x' || ch === 'X' ? ch : '0'
      }
    }
  }

  const readString = (): { raw: string; start: number; end: number } | null => {
    if (chars[i] !== '"') return null
    const start = i
    i++
    let raw = ''
    while (i < chars.length) {
      const c = chars[i]!
      if (c === '"') {
        i++
        return { raw, start, end: i }
      }
      if (c === '\\') {
        if (i + 1 >= chars.length) return null
        raw += c + chars[i + 1]!
        i += 2
        continue
      }
      if (c === '\n' || c === '\r') return null
      raw += c
      i++
    }
    return null
  }

  const readLiteralOrNumber = (): { start: number; end: number; kind: 'number' | 'literal' } | null => {
    const start = i
    const ch = chars[i]!
    if (ch === 't' || ch === 'f' || ch === 'n') {
      const lit = ch === 't' ? 'true' : ch === 'f' ? 'false' : 'null'
      for (let k = 0; k < lit.length; k++) {
        if (chars[i + k] !== lit[k]) return null
      }
      i += lit.length
      return { start, end: i, kind: 'literal' }
    }
    if (ch === '-' || (ch >= '0' && ch <= '9')) {
      i++
      while (i < chars.length && /[0-9.eE+-]/.test(chars[i]!)) i++
      return { start, end: i, kind: 'number' }
    }
    return null
  }

  while (i < chars.length) {
    skipWs()
    if (i >= chars.length) break
    const ch = chars[i]!

    if (ch === '{') {
      const enterSecret = maskNextValue || secretDepth > 0
      containerIsObject.push(true)
      if (enterSecret) secretDepth++
      pendingKey = null
      afterColon = false
      maskNextValue = false
      i++
      continue
    }
    if (ch === '[') {
      const enterSecret = maskNextValue || secretDepth > 0
      containerIsObject.push(false)
      if (enterSecret) secretDepth++
      pendingKey = null
      afterColon = false
      maskNextValue = false
      i++
      continue
    }
    if (ch === '}' || ch === ']') {
      if (containerIsObject.length === 0) return null
      containerIsObject.pop()
      if (secretDepth > 0) secretDepth--
      pendingKey = null
      afterColon = false
      maskNextValue = false
      i++
      continue
    }
    if (ch === ':') {
      afterColon = true
      i++
      continue
    }
    if (ch === ',') {
      afterColon = false
      pendingKey = null
      maskNextValue = false
      i++
      continue
    }
    if (ch === '"') {
      const str = readString()
      if (!str) return null
      const isKey = inObject() && !afterColon
      if (isKey) {
        pendingKey = str.raw
        afterColon = false
        maskNextValue = isSecretKey(str.raw) || secretDepth > 0
      } else {
        const shouldMask = maskNextValue || secretDepth > 0
        if (shouldMask) {
          // Mask interior of quotes only (preserve escapes structure loosely).
          for (let p = str.start + 1; p < str.end - 1; p++) {
            if (chars[p] === '\\' && p + 1 < str.end - 1) {
              chars[p] = '*'
              chars[p + 1] = '*'
              p++
            } else {
              chars[p] = '*'
            }
          }
          secretFieldsMasked++
        }
        pendingKey = null
        afterColon = false
        maskNextValue = false
      }
      continue
    }

    const lit = readLiteralOrNumber()
    if (lit) {
      const shouldMask = maskNextValue || secretDepth > 0
      if (shouldMask && lit.kind === 'number') {
        maskRange(lit.start, lit.end, 'number')
        secretFieldsMasked++
      } else if (shouldMask && lit.kind === 'literal') {
        // Keep JSON validity (true/false/null) — structural, not a secret channel when under secret key.
        secretFieldsMasked++
      }
      pendingKey = null
      afterColon = false
      maskNextValue = false
      continue
    }
    return null
  }

  if (containerIsObject.length !== 0) return null
  void pendingKey
  return { text: chars.join(''), secretFieldsMasked }
}

function sanitizeJsonDocument(text: string): StructuredSanitizeResult {
  const lex = sanitizeJsonLexemesInPlace(text)
  if (!lex) {
    return {
      text,
      stats: {
        format: 'json',
        recordsTotal: 1,
        recordsSanitized: 0,
        recordsMalformed: 1,
        secretFieldsMasked: 0,
      },
    }
  }
  return {
    text: lex.text.endsWith('\n') ? lex.text : `${lex.text}\n`,
    stats: {
      format: 'json',
      recordsTotal: 1,
      recordsSanitized: 1,
      recordsMalformed: 0,
      secretFieldsMasked: lex.secretFieldsMasked,
    },
  }
}

function lineEnding(text: string): string {
  return text.includes('\r\n') ? '\r\n' : '\n'
}

function splitPhysicalLines(text: string): { lines: string[]; nl: string; endsWithNl: boolean } {
  const nl = lineEnding(text)
  const endsWithNl = /\r?\n$/.test(text)
  const lines = text.split(/\r?\n/)
  if (endsWithNl && lines.length > 0 && lines[lines.length - 1] === '') {
    lines.pop()
  }
  return { lines, nl, endsWithNl }
}

function sanitizeNdjson(text: string): StructuredSanitizeResult {
  const { lines, nl, endsWithNl } = splitPhysicalLines(text)
  let recordsTotal = 0
  let recordsSanitized = 0
  let recordsMalformed = 0
  let secretFieldsMasked = 0
  const out: string[] = []
  for (const line of lines) {
    if (line.length === 0) {
      out.push('')
      continue
    }
    recordsTotal++
    const lex = sanitizeJsonLexemesInPlace(line)
    if (!lex) {
      out.push(line)
      recordsMalformed++
      continue
    }
    secretFieldsMasked += lex.secretFieldsMasked
    out.push(lex.text)
    recordsSanitized++
  }
  let joined = out.join(nl)
  if (endsWithNl) joined += nl
  return {
    text: joined,
    stats: {
      format: 'ndjson',
      recordsTotal,
      recordsSanitized,
      recordsMalformed,
      secretFieldsMasked,
    },
  }
}

function sanitizeHar(text: string): StructuredSanitizeResult {
  let secretFieldsMasked = 0
  try {
    const parsed = JSON.parse(text) as {
      log?: {
        entries?: Array<{
          startedDateTime?: string
          serverIPAddress?: string
          request?: HarMessage
          response?: HarMessage
          time?: number
        }>
      }
    }
    const entries = parsed.log?.entries
    if (!Array.isArray(entries)) {
      return sanitizeJsonDocument(text)
    }
    for (const entry of entries) {
      if (entry.request) secretFieldsMasked += sanitizeHarMessage(entry.request)
      if (entry.response) secretFieldsMasked += sanitizeHarMessage(entry.response)
      // Absolute times stay for Δ in later stages; durations preserved. IP left for detectors.
    }
    const pretty = text.includes('\n')
    return {
      text: `${JSON.stringify(parsed, null, pretty ? 2 : undefined)}\n`,
      stats: {
        format: 'har',
        recordsTotal: entries.length,
        recordsSanitized: entries.length,
        recordsMalformed: 0,
        secretFieldsMasked,
      },
    }
  } catch {
    return {
      text,
      stats: {
        format: 'har',
        recordsTotal: 1,
        recordsSanitized: 0,
        recordsMalformed: 1,
        secretFieldsMasked: 0,
      },
    }
  }
}

interface HarMessage {
  headers?: Array<{ name?: string; value?: string }>
  cookies?: Array<{ name?: string; value?: string }>
  queryString?: Array<{ name?: string; value?: string }>
  postData?: { text?: string; mimeType?: string; params?: Array<{ name?: string; value?: string }> }
  content?: { text?: string; encoding?: string; mimeType?: string }
}

function sanitizeHarMessage(msg: HarMessage): number {
  let masked = 0
  if (Array.isArray(msg.headers)) {
    for (const h of msg.headers) {
      if (!h || typeof h.name !== 'string') continue
      if (isSecretStructuredKey(h.name) || /^(cookie|set-cookie|authorization)$/i.test(h.name)) {
        if (typeof h.value === 'string') {
          h.value = maskTextPreservingLength(h.value)
          masked++
        }
      }
    }
  }
  if (Array.isArray(msg.cookies)) {
    for (const c of msg.cookies) {
      if (c && typeof c.value === 'string' && c.value.length > 0) {
        c.value = maskTextPreservingLength(c.value)
        masked++
      }
    }
  }
  if (Array.isArray(msg.queryString)) {
    for (const q of msg.queryString) {
      if (!q || typeof q.name !== 'string') continue
      if (isSecretStructuredKey(q.name) && typeof q.value === 'string') {
        q.value = maskTextPreservingLength(q.value)
        masked++
      }
    }
  }
  if (msg.postData) {
    if (Array.isArray(msg.postData.params)) {
      for (const p of msg.postData.params) {
        if (p && typeof p.name === 'string' && isSecretStructuredKey(p.name) && typeof p.value === 'string') {
          p.value = maskTextPreservingLength(p.value)
          masked++
        }
      }
    }
    if (typeof msg.postData.text === 'string' && msg.postData.text.length > 0) {
      const body = sanitizeNestedJsonOrMaskSecrets(msg.postData.text)
      masked += body.masked
      msg.postData.text = body.text
    }
  }
  if (msg.content && typeof msg.content.text === 'string' && msg.content.text.length > 0) {
    // base64 bodies: mask wholesale (cannot length-preserve decode safely without policy)
    if (String(msg.content.encoding ?? '').toLowerCase() === 'base64') {
      msg.content.text = maskTextPreservingLength(msg.content.text)
      masked++
    } else {
      const body = sanitizeNestedJsonOrMaskSecrets(msg.content.text)
      masked += body.masked
      msg.content.text = body.text
    }
  }
  return masked
}

function sanitizeNestedJsonOrMaskSecrets(text: string): { text: string; masked: number } {
  const t = text.trim()
  if (t.startsWith('{') || t.startsWith('[')) {
    const lex = sanitizeJsonLexemesInPlace(text)
    if (lex) return { text: lex.text, masked: lex.secretFieldsMasked }
  }
  return { text, masked: 0 }
}

function sanitizeTsharkJson(text: string): StructuredSanitizeResult {
  const isTsharkSecretKey = (key: string): boolean => {
    const base = key.includes('.') ? key.slice(key.lastIndexOf('.') + 1) : key
    return isSecretStructuredKey(key) || isSecretStructuredKey(base)
  }
  const lex = sanitizeJsonLexemesInPlace(text, isTsharkSecretKey)
  if (!lex) {
    return {
      text,
      stats: {
        format: 'tshark-json',
        recordsTotal: 1,
        recordsSanitized: 0,
        recordsMalformed: 1,
        secretFieldsMasked: 0,
      },
    }
  }
  let count = 1
  try {
    const parsed = JSON.parse(text) as unknown
    count = Array.isArray(parsed) ? parsed.length : 1
  } catch {
    count = 1
  }
  return {
    text: lex.text.endsWith('\n') ? lex.text : `${lex.text}\n`,
    stats: {
      format: 'tshark-json',
      recordsTotal: count,
      recordsSanitized: count,
      recordsMalformed: 0,
      secretFieldsMasked: lex.secretFieldsMasked,
    },
  }
}

/**
 * RFC 4180 record framer: quoted fields may contain newlines; records end at unquoted NL/CRLF.
 */
export function splitDelimitedRecords(text: string, _delim: string): string[] {
  const records: string[] = []
  let cur = ''
  let inQuotes = false
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!
    if (inQuotes) {
      cur += ch
      if (ch === '"') {
        if (text[i + 1] === '"') {
          cur += '"'
          i++
        } else {
          inQuotes = false
        }
      }
      continue
    }
    if (ch === '"') {
      inQuotes = true
      cur += ch
      continue
    }
    if (ch === '\r' || ch === '\n') {
      if (ch === '\r' && text[i + 1] === '\n') i++
      records.push(cur)
      cur = ''
      continue
    }
    cur += ch
  }
  if (cur.length > 0) records.push(cur)
  // Final newline produces a trailing empty record — drop it (matches physical-line split).
  if (records.length > 0 && records[records.length - 1] === '' && /[\r\n]$/.test(text)) {
    records.pop()
  }
  return records
}

/** RFC 4180-ish split of one record (may already include internal newlines from framing). */
function splitDelimitedLine(line: string, delim: string): string[] {
  const out: string[] = []
  let cur = ''
  let inQuotes = false
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          cur += '"'
          i++
        } else {
          inQuotes = false
        }
      } else {
        cur += ch
      }
    } else if (ch === '"') {
      inQuotes = true
    } else if (ch === delim) {
      out.push(cur)
      cur = ''
    } else {
      cur += ch
    }
  }
  out.push(cur)
  return out
}

function formatDelimitedField(value: string, delim: string): string {
  const needsQuote =
    value.includes(delim) || value.includes('"') || value.includes('\n') || value.includes('\r')
  if (!needsQuote) return value
  return `"${value.replace(/"/g, '""')}"`
}

function sanitizeDelimitedTable(text: string, delim: string): StructuredSanitizeResult {
  const format: StructuredLogFormat = delim === '\t' ? 'tsv' : 'csv'
  const nl = lineEnding(text)
  const endsWithNl = /[\r\n]$/.test(text)
  const records = splitDelimitedRecords(text, delim)
  if (records.length === 0) {
    return { text, stats: emptyStats(format) }
  }
  const headerCells = splitDelimitedLine(records[0]!, delim)
  const secretCols = new Set<number>()
  for (let i = 0; i < headerCells.length; i++) {
    const name = headerCells[i]!.trim().replace(/^"|"$/g, '')
    if (isSecretStructuredKey(name)) secretCols.add(i)
  }
  let recordsTotal = 0
  let recordsSanitized = 0
  let recordsMalformed = 0
  let secretFieldsMasked = 0
  const out: string[] = [records[0]!]
  for (let r = 1; r < records.length; r++) {
    const line = records[r]!
    if (line.length === 0) {
      out.push('')
      continue
    }
    recordsTotal++
    const cells = splitDelimitedLine(line, delim)
    if (cells.length !== headerCells.length) {
      out.push(line)
      recordsMalformed++
      continue
    }
    for (const idx of secretCols) {
      const raw = cells[idx]!
      if (raw.length === 0) continue
      cells[idx] = maskTextPreservingLength(raw)
      secretFieldsMasked++
    }
    out.push(cells.map((c) => formatDelimitedField(c, delim)).join(delim))
    recordsSanitized++
  }
  let joined = out.join(nl)
  if (endsWithNl) joined += nl
  return {
    text: joined,
    stats: {
      format,
      recordsTotal,
      recordsSanitized,
      recordsMalformed,
      secretFieldsMasked,
    },
  }
}

function sanitizeCefFamily(text: string, format: 'cef' | 'leef'): StructuredSanitizeResult {
  const { lines, nl, endsWithNl } = splitPhysicalLines(text)
  let recordsTotal = 0
  let recordsSanitized = 0
  let recordsMalformed = 0
  let secretFieldsMasked = 0
  const out: string[] = []
  const prefixRe = format === 'cef' ? CEF_PREFIX : LEEF_PREFIX
  for (const line of lines) {
    if (line.length === 0) {
      out.push('')
      continue
    }
    recordsTotal++
    if (!prefixRe.test(line.trim())) {
      out.push(line)
      recordsMalformed++
      continue
    }
    const pipeParts = splitCefPipes(line)
    if (pipeParts.length < 2) {
      out.push(line)
      recordsMalformed++
      continue
    }
    const header = pipeParts.slice(0, -1).join('|')
    const ext = pipeParts[pipeParts.length - 1] ?? ''
    const { text: newExt, masked } = sanitizeCefExtensions(ext)
    secretFieldsMasked += masked
    out.push(`${header}|${newExt}`)
    recordsSanitized++
  }
  let joined = out.join(nl)
  if (endsWithNl) joined += nl
  return {
    text: joined,
    stats: { format, recordsTotal, recordsSanitized, recordsMalformed, secretFieldsMasked },
  }
}

/** Split CEF on unescaped `|` (backslash-escaped pipes stay inside fields). */
function splitCefPipes(line: string): string[] {
  const parts: string[] = []
  let cur = ''
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '\\' && i + 1 < line.length) {
      cur += line[i]! + line[i + 1]!
      i++
      continue
    }
    if (line[i] === '|') {
      parts.push(cur)
      cur = ''
      continue
    }
    cur += line[i]!
  }
  parts.push(cur)
  return parts
}

function sanitizeCefExtensions(ext: string): { text: string; masked: number } {
  // CEF: key=value pairs separated by space; `\=` and `\\` escapes
  const tokens: Array<{ key: string; value: string; raw: string }> = []
  let i = 0
  let masked = 0
  while (i < ext.length) {
    while (i < ext.length && ext[i] === ' ') i++
    if (i >= ext.length) break
    const keyStart = i
    while (i < ext.length && ext[i] !== '=' && ext[i] !== ' ') i++
    if (i >= ext.length || ext[i] !== '=') {
      // trailing garbage — keep remainder
      tokens.push({ key: '', value: '', raw: ext.slice(keyStart) })
      break
    }
    const key = ext.slice(keyStart, i)
    i++ // =
    let value = ''
    let rawValue = ''
    while (i < ext.length) {
      if (ext[i] === '\\' && i + 1 < ext.length) {
        rawValue += ext[i]! + ext[i + 1]!
        value += ext[i + 1]!
        i += 2
        continue
      }
      if (ext[i] === ' ') {
        // lookahead: space then key=
        const rest = ext.slice(i + 1)
        if (/^[A-Za-z][\w.-]*=/.test(rest)) break
      }
      rawValue += ext[i]!
      value += ext[i]!
      i++
    }
    let outValue = rawValue
    if (isSecretStructuredKey(key)) {
      outValue = escapeCefValue(maskTextPreservingLength(value))
      masked++
    }
    tokens.push({ key, value: outValue, raw: `${key}=${outValue}` })
  }
  return { text: tokens.map((t) => t.raw).join(' '), masked }
}

function escapeCefValue(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\|/g, '\\|')
}

function sanitizeLogfmt(text: string): StructuredSanitizeResult {
  const { lines, nl, endsWithNl } = splitPhysicalLines(text)
  let recordsTotal = 0
  let recordsSanitized = 0
  let recordsMalformed = 0
  let secretFieldsMasked = 0
  const out: string[] = []
  for (const line of lines) {
    if (line.length === 0) {
      out.push('')
      continue
    }
    recordsTotal++
    if (!looksLikeLogfmtLine(line)) {
      out.push(line)
      recordsMalformed++
      continue
    }
    const { text: rewritten, masked } = rewriteLogfmtLine(line)
    secretFieldsMasked += masked
    out.push(rewritten)
    recordsSanitized++
  }
  let joined = out.join(nl)
  if (endsWithNl) joined += nl
  return {
    text: joined,
    stats: {
      format: 'logfmt',
      recordsTotal,
      recordsSanitized,
      recordsMalformed,
      secretFieldsMasked,
    },
  }
}

function rewriteLogfmtLine(line: string): { text: string; masked: number } {
  let masked = 0
  const re = /([A-Za-z_][\w.-]*)=("(?:\\.|[^"\\])*"|[^\s]+)/g
  const rewritten = line.replace(re, (full, key: string, rawVal: string) => {
    if (!isSecretStructuredKey(key)) return full
    masked++
    if (rawVal.startsWith('"') && rawVal.endsWith('"')) {
      const inner = rawVal.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\')
      const maskedInner = maskTextPreservingLength(inner)
      return `${key}="${maskedInner.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
    }
    return `${key}=${maskTextPreservingLength(rawVal)}`
  })
  return { text: rewritten, masked }
}

function sanitizeAccessCombined(text: string): StructuredSanitizeResult {
  const { lines, nl, endsWithNl } = splitPhysicalLines(text)
  let recordsTotal = 0
  let recordsSanitized = 0
  let recordsMalformed = 0
  let secretFieldsMasked = 0
  const out: string[] = []
  for (const line of lines) {
    if (line.length === 0) {
      out.push('')
      continue
    }
    recordsTotal++
    const m = ACCESS_COMBINED_RE.exec(line)
    if (!m) {
      out.push(line)
      recordsMalformed++
      continue
    }
    const ip = m[1]!
    const ident = m[2]!
    let user = m[3]!
    const time = m[4]!
    let req = m[5]!
    const status = m[6]!
    const bytes = m[7]!
    const referer = m[8]
    const ua = m[9]
    if (user !== '-') {
      user = maskTextPreservingLength(user)
      secretFieldsMasked++
    }
    const reqSan = sanitizeAccessRequest(req)
    secretFieldsMasked += reqSan.masked
    req = reqSan.text
    let rebuilt = `${ip} ${ident} ${user} [${time}] "${req}" ${status} ${bytes}`
    if (referer !== undefined && ua !== undefined) {
      rebuilt += ` "${referer}" "${ua}"`
    }
    out.push(rebuilt)
    recordsSanitized++
  }
  let joined = out.join(nl)
  if (endsWithNl) joined += nl
  return {
    text: joined,
    stats: {
      format: 'access-combined',
      recordsTotal,
      recordsSanitized,
      recordsMalformed,
      secretFieldsMasked,
    },
  }
}

function sanitizeAccessRequest(req: string): { text: string; masked: number } {
  // METHOD path[?query] PROTO
  const parts = req.split(' ')
  if (parts.length < 2) return { text: req, masked: 0 }
  const method = parts[0]!
  const pathProto = parts.slice(1)
  const proto = pathProto.length >= 2 ? pathProto[pathProto.length - 1]! : ''
  const path = pathProto.length >= 2 ? pathProto.slice(0, -1).join(' ') : pathProto.join(' ')
  const q = path.indexOf('?')
  if (q < 0) return { text: req, masked: 0 }
  const base = path.slice(0, q)
  const query = path.slice(q + 1)
  let masked = 0
  const pairs = query.split('&').map((pair) => {
    const eq = pair.indexOf('=')
    if (eq < 0) return pair
    const k = pair.slice(0, eq)
    const v = pair.slice(eq + 1)
    if (isSecretStructuredKey(decodeURIComponentSafe(k))) {
      masked++
      return `${k}=${maskTextPreservingLength(v)}`
    }
    return pair
  })
  const newPath = `${base}?${pairs.join('&')}`
  const text = proto ? `${method} ${newPath} ${proto}` : `${method} ${newPath}`
  return { text, masked }
}

function decodeURIComponentSafe(s: string): string {
  try {
    return decodeURIComponent(s)
  } catch {
    return s
  }
}
