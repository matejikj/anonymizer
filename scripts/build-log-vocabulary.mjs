#!/usr/bin/env node
/**
 * T70 — build offline free-text vocabulary artifact.
 *
 * Sources (offline only — never fetches):
 *  1. Bundled technical EN/CZ scaffolding (this file)
 *  2. Optional local repos via VOCAB_SOURCE_ROOTS / sibling dirs (konos-as, rgw-server, flexcd)
 *  3. Optional local template logs: logs/template-*.log, anonym/template-*.log
 *
 * Exclusions: given-name/surname denylist; tokens ≤2 chars except SHORT_WHITELIST.
 * Output: src/engine/freeText/vocabulary.<hash12>.bin + vocabulary.generated.ts
 *         + vocabulary.license.json (SBOM / attribution)
 *
 * Words only — never values. Format-string placeholders (%s, {0}, …) are stripped.
 */
import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
  unlinkSync,
} from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const outDir = path.join(root, 'src/engine/freeText')
const VOCAB_VERSION = 't70-1'
const MAX_ARTIFACT_AGE_DAYS = 180

/** ≤2-char tokens allowed through (T70 carve-out). */
const SHORT_WHITELIST = new Set([
  'a', 'i', 'o', 'u', 'v', 'k', 's', 'z',
  'na', 'do', 'od', 'po', 'za', 'se', 'si', 'to', 'ta', 'ty', 'je', 'js', 'by', 'az', 'uz',
  'an', 'as', 'at', 'be', 'by', 'do', 'if', 'in', 'is', 'it', 'me', 'my',
  'no', 'of', 'on', 'or', 'so', 'to', 'up', 'us', 'we', 'id', 'ip', 'ok', 'or',
])

/**
 * Common given names / surnames (CZ/SK/EN) — must NEVER enter the vocabulary.
 * Kept deliberately incomplete; absence from this list does not mean a token is safe
 * (unknown tokens are free-token / mask via T69).
 */
const NAME_DENYLIST = new Set(
  [
    // EN given
    'james', 'john', 'robert', 'michael', 'william', 'david', 'richard', 'joseph',
    'thomas', 'charles', 'mary', 'patricia', 'jennifer', 'linda', 'elizabeth',
    'barbara', 'susan', 'jessica', 'sarah', 'karen', 'nancy', 'lisa', 'betty',
    'margaret', 'sandra', 'ashley', 'kimberly', 'emily', 'donna', 'michelle',
    'dorothy', 'carol', 'amanda', 'melissa', 'deborah', 'stephanie', 'rebecca',
    'sharon', 'laura', 'cynthia', 'kathleen', 'amy', 'angela', 'shirley', 'anna',
    'brenda', 'pamela', 'emma', 'nicole', 'helen', 'samantha', 'catherine', 'debra',
    'rachel', 'carolyn', 'janet', 'virginia', 'maria', 'heather', 'diane', 'julie',
    'joyce', 'victoria', 'kelly', 'christina', 'joan', 'evelyn', 'judith', 'megan',
    'cheryl', 'andrea', 'hannah', 'jacqueline', 'martha', 'gloria', 'teresa', 'ann',
    'sara', 'madison', 'frances', 'kathryn', 'janice', 'jean', 'abigail', 'alice',
    'judy', 'sophia', 'grace', 'denise', 'amber', 'doris', 'marilyn', 'danielle',
    'beverly', 'isabella', 'theresa', 'diana', 'natalie', 'brittany', 'charlotte',
    'marie', 'kayla', 'alexis', 'lori',
    'peter', 'paul', 'mark', 'donald', 'george', 'kenneth', 'steven', 'edward',
    'brian', 'ronald', 'anthony', 'kevin', 'jason', 'matthew', 'gary', 'timothy',
    'jose', 'larry', 'jeffrey', 'frank', 'scott', 'eric', 'stephen', 'andrew',
    'raymond', 'gregory', 'joshua', 'jerry', 'dennis', 'walter', 'patrick', 'peter',
    'harold', 'douglas', 'henry', 'carl', 'arthur', 'ryan', 'roger', 'joe', 'juan',
    'jack', 'albert', 'jonathan', 'justin', 'terry', 'gerald', 'keith', 'samuel',
    'willie', 'ralph', 'lawrence', 'nicholas', 'roy', 'benjamin', 'bruce', 'brandon',
    'adam', 'harry', 'fred', 'wayne', 'billy', 'steve', 'louis', 'jeremy', 'aaron',
    'randy', 'howard', 'eugene', 'carlos', 'russell', 'bobby', 'victor', 'martin',
    'ernest', 'philip', 'todd', 'craig', 'alan', 'shannon', 'jesse', 'philip',
    // CZ/SK given (ASCII fold)
    'jan', 'jana', 'petr', 'petra', 'martin', 'martina', 'tomas', 'tomáš', 'tomas',
    'jiri', 'jiří', 'jiri', 'pavel', 'eva', 'lucie', 'katerina', 'kateřina',
    'lenka', 'hana', 'vera', 'věra', 'alena', 'ivana', 'monika', 'barbora',
    'nikola', 'tereza', 'klara', 'klára', 'adela', 'adelá', 'eliska', 'eliška',
    'michal', 'jakub', 'lukas', 'lukáš', 'ondrej', 'ondřej', 'david', 'marek',
    'adam', 'filip', 'vojtech', 'vojtěch', 'matej', 'matěj', 'daniel', 'roman',
    'radek', 'milan', 'jaroslav', 'miroslav', 'ladislav', 'frantisek', 'františek',
    'vaclav', 'václav', 'stanislav', 'zdenek', 'zdeněk', 'josef', 'antonin',
    'antonín', 'karel', 'iveta', 'simona', 'andrea', 'renata', 'dagmar', 'bozena',
    'božena', 'libuse', 'libuše', 'viera', 'zuzana', 'michaela', 'veronika',
    'kristyna', 'kristýna', 'aneta', 'dominik', 'patrik', 'samuel', 'sebastian',
    // Common surnames
    'smith', 'johnson', 'williams', 'brown', 'jones', 'garcia', 'miller', 'davis',
    'rodriguez', 'martinez', 'anderson', 'taylor', 'thomas', 'hernandez', 'moore',
    'martin', 'jackson', 'thompson', 'white', 'lopez', 'lee', 'gonzalez', 'harris',
    'clark', 'lewis', 'robinson', 'walker', 'hall', 'allen', 'young', 'king',
    'novak', 'novák', 'svoboda', 'svobodova', 'novotny', 'novotný', 'dvorak',
    'dvořák', 'cerny', 'černý', 'prochazka', 'procházka', 'kucera', 'kučera',
    'vesely', 'veselý', 'horak', 'horák', 'nemec', 'němec', 'marek', 'pospisil',
    'hájek', 'hajek', 'jelinek', 'jelínek', 'kral', 'král', 'benes', 'beneš',
    'fiala', 'sedlacek', 'sedláček', 'dolezal', 'doležal', 'zeman', 'kolář',
    'kolar', 'navratil', 'navrátil', 'cernova', 'novakova',
  ].map((s) => s.normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase()),
)

/** Core technical scaffolding — authored in-repo (no third-party corpus licence). */
const TECHNICAL_SEED = `
get put post head patch delete options trace connect
invite ack bye cancel register refer notify subscribe publish message prack update info
http https sip sips rtp rtcp tcp udp tls dtls sctp ws wss mqtt amqp kafka nats stomp xmpp coap
dns dhcp snmp icmp igmp arp lldp ssdp sdp rtp rtsp ftp sftp ssh smtp imap pop3 ldap radius
diameter gtp pfcp ngap s1ap diameter diameter diameter
ok error warn warning debug trace fatal critical success failed failure timeout retry retries attempt
started stopped starting stopping running idle busy connected disconnected connecting listening
closed closing request response reply status code reason cause session dialog transaction
packet frame payload header headers body content length encoding charset mime
application json xml text plain octet stream form data multipart
the and for not are was were been have has had will can may must should would could did
does doing into from with without about after before between under over again once only same
other some any all each every both few more most such than too very just also then when
where what which who whom how why yes no on off up down out via per new old first last
next prev previous current local remote public private internal external incoming outgoing
inbound outbound source destination src dst client server peer node device endpoint channel
queue topic group message event action state mode level version build config configuration
param params parameter parameters value values key keys field fields record records
file files path paths line lines number count total size bytes kb mb gb ms sec secs min mins
hour hours day days time date timestamp duration address addresses hostname domain uri url urn
protocol service method function module component process thread worker task job schedule
scheduled enabled disabled active inactive available unavailable allowed denied accepted
rejected pending complete completed partial full empty missing unknown invalid valid verified
unverified authorized unauthorized continue break return throw catch finally try await async
true false null undefined none default admin root info test user host name type port call
chyba varovani informace ladici spusteno zastaveno pripojeno odpojeno pozadavek odpoved
stav kod duvod relace hovor paket ramec hlavicka telo delka konfigurace parametr hodnota
klic pole zaznam soubor cesta radek cislo pocet velikost cas datum trvani adresa protokol
sluzba metoda modul proces uloha povolen zakazan aktivni neaktivni dostupny nedostupny
prijat odmitnut ceka dokonceno neplatny platny uzivatel stanice system server klient
hlaseni zprava spojeni odchozi prichozi interni externi lokalni vzdaleny verejny soukromy
continue retrying reconnect reconnected authentication authorization authorized unauthorized
forbidden notfound conflict gone lengthrequired payloadtoolarge toomanyrequests unavailable
badrequest unauthorized paymentrequired forbidden methodnotallowed notacceptable
proxyauthenticationrequired requesttimeout conflict gone lengthrequired preconditionfailed
payloadtoolarge uritoolong unsupportedmediatype rangenotsatisfiable expectationfailed
imiservererror notimplemented badgateway serviceunavailable gatewaytimeout
trying ringing progress forwarded queued sessionprogress requestterminated
busyhere requestdeclined temporarilyunavailable calldoesnotexist intervaltoobrief
dialog busy everywhere declined decline
registering registered unregister unregistering invitee inviteer
media audio video image application text
codec pcmul pcma g711 g729 opus silk amr amrwb telephone-event
branch tag call-id cseq via from to contact route record-route max-forwards
user-agent server content-type content-length content-encoding transfer-encoding
authorization www-authenticate proxy-authenticate proxy-authorization
expires allow supported require unsupported session-expires min-se
received rport maddr ttl transport
offer answer sdp ice stun turn dtls-srtp
candidate foundation component protocol priority address
rtpmap fmtp ptime maxptime sendrecv sendonly recvonly inactive
connection owner session name timing media attribute bandwidth
encryption encrypted ciphertext plaintext cleartext
database query select insert update delete transaction commit rollback
cache redis memcached elasticsearch
container kubernetes pod namespace service ingress
certificate cert privatekey publickey fingerprint thumbprint
serial number revision checksum crc hash sha256 sha1 md5
interface ethernet vlan bridge tunnel gre vxlan geneve
multicast broadcast unicast anycast loopback localhost
`

function fold(s) {
  return s.normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase()
}

function isWordChar(code) {
  return (
    (code >= 0x30 && code <= 0x39)
    || (code >= 0x41 && code <= 0x5a)
    || (code >= 0x61 && code <= 0x7a)
    || code === 0x5f
    || (code >= 0xc0 && code <= 0xff && code !== 0xd7 && code !== 0xf7)
  )
}

function tokenizeWords(text) {
  const out = []
  let i = 0
  while (i < text.length) {
    const code = text.charCodeAt(i)
    if (isWordChar(code)) {
      const start = i
      i++
      while (i < text.length && isWordChar(text.charCodeAt(i))) i++
      out.push(text.slice(start, i))
    } else {
      i++
    }
  }
  return out
}

function acceptToken(raw) {
  const key = fold(raw.trim())
  if (key.length === 0) return null
  if (key.length <= 2) return SHORT_WHITELIST.has(key) ? key : null
  if (NAME_DENYLIST.has(key)) return null
  // Pure digits / hex ids are values, not vocabulary.
  if (/^\d+$/.test(key)) return null
  if (/^[0-9a-f]{8,}$/.test(key)) return null
  return key
}

function addWords(set, text) {
  for (const tok of tokenizeWords(text)) {
    const w = acceptToken(tok)
    if (w) set.add(w)
  }
}

/** Strip printf / format placeholders before tokenization. */
function stripFormatPlaceholders(s) {
  return s
    .replace(/%[-+0 #]*\d*(?:\.\d+)?[sdifuoxXeEgGcspn%]/g, ' ')
    .replace(/\{+\d*\}+/g, ' ')
    .replace(/\$\{[^}]+\}/g, ' ')
}

/**
 * Extract string literals that look like log format templates from source text.
 * Conservative: only double/single quoted strings containing a letter and a space
 * or format placeholder — avoids harvesting identifiers as "vocabulary".
 */
function extractLogFormatStrings(source) {
  const out = []
  const re = /(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)')/g
  let m
  while ((m = re.exec(source)) !== null) {
    const body = (m[1] ?? m[2] ?? '').replace(/\\(.)/g, '$1')
    if (body.length < 4 || body.length > 400) continue
    if (!/[A-Za-zÀ-ž]/.test(body)) continue
    if (!(/[%{]/.test(body) || /\s/.test(body))) continue
    // Skip obvious paths / URLs / emails.
    if (/https?:\/\//i.test(body) || /@/.test(body) || /[\\/]/.test(body)) continue
    out.push(stripFormatPlaceholders(body))
  }
  return out
}

function walkSourceFiles(dir, out = [], depth = 0) {
  if (depth > 12) return out
  let entries
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return out
  }
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist' || entry.name === 'build') {
      continue
    }
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      walkSourceFiles(full, out, depth + 1)
    } else if (entry.isFile() && /\.(c|cc|cpp|h|hpp|java|kt|go|rs|py|cs|ts|js|mjs)$/i.test(entry.name)) {
      out.push(full)
    }
  }
  return out
}

function collectFromRepo(repoRoot, words) {
  if (!existsSync(repoRoot) || !statSync(repoRoot).isDirectory()) return 0
  const files = walkSourceFiles(repoRoot)
  let added = 0
  const before = words.size
  for (const file of files) {
    let text
    try {
      const st = statSync(file)
      if (st.size > 2_000_000) continue
      text = readFileSync(file, 'utf8')
    } catch {
      continue
    }
    for (const fmt of extractLogFormatStrings(text)) {
      addWords(words, fmt)
    }
  }
  added = words.size - before
  return added
}

function collectFromTemplates(words) {
  const globs = [
    path.join(root, 'logs'),
    path.join(root, 'anonym'),
  ]
  let added = 0
  for (const dir of globs) {
    if (!existsSync(dir)) continue
    let entries
    try {
      entries = readdirSync(dir)
    } catch {
      continue
    }
    for (const name of entries) {
      if (!/^template-.*\.log$/i.test(name)) continue
      const full = path.join(dir, name)
      try {
        const text = readFileSync(full, 'utf8')
        // Templates may contain sample values — only take alphabetic tokens ≥3 that
        // are not denylisted; short whitelist handled in acceptToken.
        const before = words.size
        addWords(words, stripFormatPlaceholders(text))
        added += words.size - before
      } catch {
        /* skip */
      }
    }
  }
  return added
}

function resolveSourceRoots() {
  const roots = []
  const env = process.env.VOCAB_SOURCE_ROOTS
  if (env) {
    for (const part of env.split(path.delimiter)) {
      const p = part.trim()
      if (p) roots.push(path.resolve(p))
    }
  }
  const parent = path.dirname(root)
  for (const name of ['konos-as', 'rgw-server', 'flexcd', 'konos-as-web']) {
    roots.push(path.join(parent, name))
    roots.push(path.join(root, '..', name))
  }
  return [...new Set(roots)]
}

function encodeBin(version, wordsSorted) {
  const enc = new TextEncoder()
  const versionBytes = enc.encode(version)
  let size = 4 + 2 + versionBytes.length + 4
  const wordBytes = wordsSorted.map((w) => enc.encode(w))
  for (const b of wordBytes) size += 2 + b.length
  const buf = new Uint8Array(size)
  const view = new DataView(buf.buffer)
  buf[0] = 0x46 // F
  buf[1] = 0x54 // T
  buf[2] = 0x56 // V
  buf[3] = 0x31 // 1
  let o = 4
  view.setUint16(o, versionBytes.length, false)
  o += 2
  buf.set(versionBytes, o)
  o += versionBytes.length
  view.setUint32(o, wordsSorted.length, false)
  o += 4
  for (const b of wordBytes) {
    view.setUint16(o, b.length, false)
    o += 2
    buf.set(b, o)
    o += b.length
  }
  return buf
}

function main() {
  const words = new Set()
  addWords(words, TECHNICAL_SEED)
  for (const w of SHORT_WHITELIST) words.add(w)

  const roots = resolveSourceRoots()
  const repoStats = []
  for (const r of roots) {
    const n = collectFromRepo(r, words)
    if (n > 0 || existsSync(r)) repoStats.push({ root: r, added: n, present: existsSync(r) })
  }
  const templateAdded = collectFromTemplates(words)

  // Final exclusion pass
  for (const w of [...words]) {
    if (NAME_DENYLIST.has(w)) words.delete(w)
    if (w.length <= 2 && !SHORT_WHITELIST.has(w)) words.delete(w)
  }

  const sorted = [...words].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
  const bin = encodeBin(VOCAB_VERSION, sorted)
  const hash = createHash('sha256').update(bin).digest('hex').slice(0, 12)
  const binName = `vocabulary.${hash}.bin`
  const binPath = path.join(outDir, binName)

  mkdirSync(outDir, { recursive: true })
  // Remove previous vocabulary.*.bin artifacts
  for (const name of readdirSync(outDir)) {
    if (/^vocabulary\.[0-9a-f]+\.bin$/i.test(name) && name !== binName) {
      unlinkSync(path.join(outDir, name))
    }
  }
  writeFileSync(binPath, bin)

  const generated = `/**
 * AUTO-GENERATED by scripts/build-log-vocabulary.mjs — do not edit.
 * T70 offline free-text vocabulary (${VOCAB_VERSION}).
 */
export const FREE_TEXT_VOCABULARY_VERSION = ${JSON.stringify(VOCAB_VERSION)} as const
export const FREE_TEXT_VOCABULARY_HASH = ${JSON.stringify(hash)} as const
export const FREE_TEXT_VOCABULARY_WORD_COUNT = ${sorted.length} as const
/** Null-separated lowercase words (sorted). */
export const FREE_TEXT_VOCABULARY_BLOB = ${JSON.stringify(sorted.join('\0'))} as const
export const FREE_TEXT_VOCABULARY_BIN_NAME = ${JSON.stringify(binName)} as const
export const FREE_TEXT_VOCABULARY_BUILT_AT = ${JSON.stringify(new Date().toISOString())} as const
export const FREE_TEXT_VOCABULARY_MAX_AGE_DAYS = ${MAX_ARTIFACT_AGE_DAYS} as const
`

  writeFileSync(path.join(outDir, 'vocabulary.generated.ts'), generated)

  const license = {
    name: 'squelch-free-text-vocabulary',
    version: VOCAB_VERSION,
    hash,
    bin: binName,
    wordCount: sorted.length,
    builtAt: new Date().toISOString(),
    license: 'LicenseRef-Internal-Technical-Scaffolding',
    comment:
      'In-repo technical EN/CZ scaffolding authored for Squelch; optional extracts from local KONOS/RGW/flexcd format strings are words only (no values). Not a third-party wordlist corpus.',
    maxAgeDays: MAX_ARTIFACT_AGE_DAYS,
  }
  writeFileSync(path.join(outDir, 'vocabulary.license.json'), `${JSON.stringify(license, null, 2)}\n`)

  console.log(`build-log-vocabulary: OK`)
  console.log(`  version: ${VOCAB_VERSION}`)
  console.log(`  words:   ${sorted.length}`)
  console.log(`  hash:    ${hash}`)
  console.log(`  bin:     ${path.relative(root, binPath)}`)
  console.log(`  templates added≈ ${templateAdded}`)
  for (const s of repoStats.filter((x) => x.present)) {
    console.log(`  repo ${path.relative(parentOf(s.root), s.root) || s.root}: +${s.added}`)
  }
}

function parentOf(p) {
  return path.dirname(p)
}

main()
