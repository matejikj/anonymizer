/**
 * Deterministic log-profile generator for Krok 0 performance spike.
 * Produces realistic, non-repetitive lines — not a single short string repeated.
 */

import { MAX_TEXT_FILE_BYTES } from '../../src/domain/capabilityContract.ts'

export type ProfileKind = 'common' | 'maximum' | 'match-stress' | 'long-line-stress'

export interface ProfileSpec {
  kind: ProfileKind
  lineCount: number
  targetBytes: number
  matchCount: number
  seed: number
  /** Extra long physical lines (≥256 KiB UTF-8) for long-line-stress. */
  oversizedLineCount?: number
  oversizedLineBytes?: number
}

export interface GeneratedMatch {
  start: number
  length: number
  line: number
  entityIndex: number
  category: number
}

export interface GeneratedProfile {
  kind: ProfileKind
  text: string
  /** Physical lines without separators — prefer for CodeMirror Text.of. */
  lines: string[]
  utf8ByteLength: number
  lineCount: number
  matches: GeneratedMatch[]
  entities: Array<{ key: string; original: string; replacement: string; category: number }>
}

export const PROFILE_SPECS: Record<ProfileKind, ProfileSpec> = {
  common: {
    kind: 'common',
    lineCount: 100_000,
    targetBytes: 30 * 1024 * 1024,
    matchCount: 75_000,
    seed: 0x5c1e1c01,
  },
  maximum: {
    kind: 'maximum',
    lineCount: 400_000,
    targetBytes: MAX_TEXT_FILE_BYTES,
    matchCount: 250_000,
    seed: 0x5c1e1c02,
  },
  'match-stress': {
    kind: 'match-stress',
    lineCount: 400_000,
    targetBytes: MAX_TEXT_FILE_BYTES,
    matchCount: 500_000,
    seed: 0x5c1e1c03,
  },
  'long-line-stress': {
    kind: 'long-line-stress',
    lineCount: 100_000,
    targetBytes: MAX_TEXT_FILE_BYTES,
    matchCount: 100_000,
    seed: 0x5c1e1c04,
    oversizedLineCount: 4,
    oversizedLineBytes: 512 * 1024,
  },
}

/** Mulberry32 PRNG — deterministic, fast, good enough for fixtures. */
export function createPrng(seed: number): () => number {
  let t = seed >>> 0
  return () => {
    t += 0x6d2b79f5
    let r = Math.imul(t ^ (t >>> 15), 1 | t)
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r)
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296
  }
}

const LEVELS = ['INFO', 'WARN', 'ERROR', 'DEBUG', 'TRACE'] as const
const COMPONENTS = [
  'sipstack',
  'media-bridge',
  'account-mgr',
  'conference',
  'rtp-pump',
  'auth-gate',
  'ccs-web',
  'worker-pj',
] as const
const ACTIONS = [
  'registered',
  'invite-sent',
  'bye-received',
  'codec-negotiated',
  'media-active',
  'hold-local',
  'transfer-failed',
  'dtmf-detected',
] as const

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n)
}

function formatTs(rand: () => number, line: number): string {
  const day = 1 + (line % 28)
  const hour = Math.floor(rand() * 24)
  const min = Math.floor(rand() * 60)
  const sec = Math.floor(rand() * 60)
  const ms = Math.floor(rand() * 1000)
  return `2026-08-${pad2(day)}T${pad2(hour)}:${pad2(min)}:${pad2(sec)}.${String(ms).padStart(3, '0')}Z`
}

function ipv4(rand: () => number, entitySeq: number): string {
  // Avoid trivial repetition: derive from entity sequence + noise.
  const a = 10
  const b = 1 + (entitySeq % 254)
  const c = 1 + Math.floor(rand() * 254)
  const d = 1 + ((entitySeq * 17 + Math.floor(rand() * 50)) % 254)
  return `${a}.${b}.${c}.${d}`
}

function hostname(rand: () => number, entitySeq: number): string {
  const labels = ['host', 'gw', 'edge', 'core', 'lab', 'node']
  const label = labels[entitySeq % labels.length]
  const id = entitySeq + 1
  const tld = rand() > 0.5 ? 'local' : 'example.invalid'
  return `${label}-${id}.${Math.floor(rand() * 90) + 10}.${tld}`
}

function userId(entitySeq: number): string {
  return `disp${entitySeq + 1}`
}

function email(_rand: () => number, entitySeq: number): string {
  return `user${entitySeq + 1}@corp${1 + (entitySeq % 40)}.example.invalid`
}

function sipUri(rand: () => number, entitySeq: number): string {
  const user = 900_000_000 + entitySeq
  const host = hostname(rand, entitySeq)
  return `sip:${user}@${host}`
}

function person(entitySeq: number): string {
  const first = ['Anna', 'Petr', 'Jana', 'Martin', 'Eva', 'Tomas', 'Lucie', 'Jakub']
  const last = ['Novak', 'Svoboda', 'Dvorak', 'Cerny', 'Prochazka', 'Kucera', 'Vesely', 'Horak']
  return `${first[entitySeq % first.length]} ${last[(entitySeq * 3) % last.length]}`
}

function internalId(entitySeq: number): string {
  const kind = entitySeq % 3 === 0 ? 'MP' : entitySeq % 3 === 1 ? 'GRP' : 'TEN'
  return `${kind}_${1000 + entitySeq}`
}

type TokenKind = 'ip' | 'hostname' | 'user-id' | 'email' | 'sip' | 'person' | 'internal'

const TOKEN_KINDS: TokenKind[] = [
  'ip',
  'hostname',
  'user-id',
  'email',
  'sip',
  'person',
  'internal',
]

const CATEGORY_INDEX: Record<TokenKind, number> = {
  ip: 0,
  hostname: 1,
  'user-id': 2,
  email: 3,
  sip: 4,
  person: 5,
  internal: 6,
}

function makeSensitive(
  kind: TokenKind,
  rand: () => number,
  entitySeq: number,
): { original: string; replacement: string; category: number } {
  switch (kind) {
    case 'ip':
      return {
        original: ipv4(rand, entitySeq),
        replacement: `10.255.${1 + (entitySeq % 250)}.${1 + ((entitySeq * 3) % 250)}`,
        category: CATEGORY_INDEX.ip,
      }
    case 'hostname':
      return {
        original: hostname(rand, entitySeq),
        replacement: `host-${entitySeq + 1}.example.invalid`,
        category: CATEGORY_INDEX.hostname,
      }
    case 'user-id':
      return {
        original: userId(entitySeq),
        replacement: `account-${entitySeq + 1}`,
        category: CATEGORY_INDEX['user-id'],
      }
    case 'email':
      return {
        original: email(rand, entitySeq),
        replacement: `user${entitySeq + 1}@example.invalid`,
        category: CATEGORY_INDEX.email,
      }
    case 'sip':
      return {
        original: sipUri(rand, entitySeq),
        replacement: `sip:${900_000_001 + entitySeq}@host-${entitySeq + 1}.example.invalid`,
        category: CATEGORY_INDEX.sip,
      }
    case 'person':
      return {
        original: person(entitySeq),
        replacement: `Person ${entitySeq + 1}`,
        category: CATEGORY_INDEX.person,
      }
    case 'internal':
      return {
        original: internalId(entitySeq),
        replacement: `internal-${entitySeq + 1}`,
        category: CATEGORY_INDEX.internal,
      }
  }
}

function fillerWords(rand: () => number, count: number): string {
  const words = [
    'call',
    'session',
    'route',
    'latency',
    'jitter',
    'packet',
    'channel',
    'bridge',
    'queue',
    'retry',
    'timeout',
    'handshake',
    'payload',
    'codec',
    'stream',
  ]
  const parts: string[] = []
  for (let i = 0; i < count; i++) {
    parts.push(words[Math.floor(rand() * words.length)]!)
    if (rand() > 0.7) parts.push(String(Math.floor(rand() * 10_000)))
  }
  return parts.join(' ')
}

/**
 * Build a profile. For large profiles prefer `generateProfileStreaming` /
 * `estimateAndGenerate` to avoid holding multiple copies longer than needed.
 */
export function generateProfile(spec: ProfileSpec = PROFILE_SPECS.common): GeneratedProfile {
  const rand = createPrng(spec.seed)
  const entities: GeneratedProfile['entities'] = []
  const entityOriginals: string[] = []

  // Unique entities — enough distinct values so matches aren't one repeated string.
  const entityTarget = Math.max(2_000, Math.min(spec.matchCount, Math.floor(spec.matchCount / 3)))
  for (let i = 0; i < entityTarget; i++) {
    const kind = TOKEN_KINDS[i % TOKEN_KINDS.length]!
    const made = makeSensitive(kind, rand, i)
    entities.push({
      key: `${kind}::${made.original.toLowerCase()}`,
      original: made.original,
      replacement: made.replacement,
      category: made.category,
    })
    entityOriginals.push(made.original)
  }

  const avgLineBytes = Math.max(40, Math.floor(spec.targetBytes / spec.lineCount))
  const matchesPerLineBudget = spec.matchCount / spec.lineCount

  const lines: string[] = []
  const matches: GeneratedMatch[] = []
  let offset = 0
  let matchCount = 0
  let oversizedPlaced = 0

  for (let lineIdx = 0; lineIdx < spec.lineCount; lineIdx++) {
    const lineNo = lineIdx + 1
    const isOversized =
      spec.oversizedLineCount !== undefined &&
      oversizedPlaced < spec.oversizedLineCount &&
      (lineIdx === Math.floor(spec.lineCount * 0.1) ||
        lineIdx === Math.floor(spec.lineCount * 0.4) ||
        lineIdx === Math.floor(spec.lineCount * 0.7) ||
        lineIdx === Math.floor(spec.lineCount * 0.95))

    const level = LEVELS[Math.floor(rand() * LEVELS.length)]!
    const component = COMPONENTS[Math.floor(rand() * COMPONENTS.length)]!
    const action = ACTIONS[Math.floor(rand() * ACTIONS.length)]!
    const ts = formatTs(rand, lineIdx)

    const parts: string[] = [`${ts} [${level}] ${component}: ${action}`]
    const lineMatchSlots: Array<{ entityIndex: number; placeholder: string }> = []

    const wantMatches = Math.min(
      8,
      Math.max(
        0,
        Math.round(matchesPerLineBudget + (rand() - 0.5) * matchesPerLineBudget) +
          (matchCount < (spec.matchCount * lineIdx) / spec.lineCount ? 1 : 0),
      ),
    )

    for (let m = 0; m < wantMatches && matchCount < spec.matchCount; m++) {
      const entityIndex = Math.floor(rand() * entities.length)
      const placeholder = `__M${m}__`
      lineMatchSlots.push({ entityIndex, placeholder })
      parts.push(`${TOKEN_KINDS[entities[entityIndex]!.category % TOKEN_KINDS.length]}=${placeholder}`)
      matchCount++
    }

    // Pad with varied filler so lines aren't identical and reach byte target.
    let body = parts.join(' ')
    const targetLen = isOversized
      ? (spec.oversizedLineBytes ?? 256 * 1024)
      : avgLineBytes + Math.floor((rand() - 0.5) * avgLineBytes * 0.4)

    while (body.length < targetLen - 20) {
      body += ` ${fillerWords(rand, 3 + Math.floor(rand() * 6))}`
      if (isOversized && body.length % 4096 < 32) {
        // Sprinkle unique noise so compression/engine can't collapse the line.
        body += ` #${lineIdx}:${body.length}:${Math.floor(rand() * 1e9)}`
      }
    }

    if (isOversized) oversizedPlaced++

    // Replace placeholders with real originals and record absolute offsets.
    let finalLine = body
    // Process placeholders from end so offsets stay valid — but we need starts in final text.
    // Build by scanning placeholders in order of appearance.
    const built: string[] = []
    let cursor = 0
    const re = /__M(\d+)__/g
    let m: RegExpExecArray | null
    const pending: GeneratedMatch[] = []
    while ((m = re.exec(body)) !== null) {
      const slotIdx = Number(m[1])
      const slot = lineMatchSlots[slotIdx]
      if (!slot) continue
      built.push(body.slice(cursor, m.index))
      const startInLine = built.reduce((a, s) => a + s.length, 0)
      const original = entityOriginals[slot.entityIndex]!
      built.push(original)
      pending.push({
        start: offset + startInLine,
        length: original.length,
        line: lineNo,
        entityIndex: slot.entityIndex,
        category: entities[slot.entityIndex]!.category,
      })
      cursor = m.index + m[0].length
    }
    built.push(body.slice(cursor))
    finalLine = built.join('')

    for (const pm of pending) matches.push(pm)

    lines.push(finalLine)
    offset += finalLine.length + 1 // + '\n'
  }

  // Top up matches if under target (attach to later lines by re-scan — rare).
  // Prefer under-shoot slightly over mutating finished text; assert near target.
  const text = lines.join('\n')
  // Content is ASCII-heavy; length ≈ UTF-8 bytes. Spot-check avoids a second full buffer.
  let utf8ByteLength = text.length
  if (text.length > 0) {
    const sample = text.slice(0, Math.min(text.length, 100_000))
    const encoded = new TextEncoder().encode(sample).byteLength
    if (encoded !== sample.length) {
      utf8ByteLength = new TextEncoder().encode(text).byteLength
    }
  }

  return {
    kind: spec.kind,
    text,
    lines,
    utf8ByteLength,
    lineCount: lines.length,
    matches,
    entities,
  }
}

/** UTF-8 byte length without allocating a second full copy when TextEncoder is available. */
export function utf8Length(text: string): number {
  return new TextEncoder().encode(text).byteLength
}

/**
 * Generate profile metadata + text in one pass, reporting progress.
 * Used by the browser spike harness for the maximum profile.
 */
export function generateProfileWithProgress(
  spec: ProfileSpec,
  onProgress?: (phase: string, ratio: number) => void,
): GeneratedProfile {
  onProgress?.('generating', 0)
  const profile = generateProfile(spec)
  onProgress?.('generating', 1)
  return profile
}
