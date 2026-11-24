/**
 * T54 — MRCPv2 speech control canaries (channel, transcript, grammar, voiceprint, URI).
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { SEMANTIC_SERVICE_PORTS } from '../../../src/pcap/anonymization/portPolicy'
import { sanitizePacket, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpTcp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'

function packetInput(data: Uint8Array) {
  return {
    index: 0,
    data,
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
  }
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function latin1(buf: Uint8Array): string {
  return new TextDecoder('latin1').decode(buf)
}

/** Build a length-correct MRCPv2 message (message-length = whole message). */
function encodeMrcp(restOfStart: string, headerLines: string[], body: string): Uint8Array {
  const headers = headerLines.length > 0 ? `${headerLines.join('\r\n')}\r\n\r\n` : '\r\n'
  let lenDigits = 3
  for (let i = 0; i < 6; i++) {
    const placeholder = '0'.repeat(lenDigits)
    const draft = `MRCP/2.0 ${placeholder} ${restOfStart}\r\n${headers}${body}`
    const lenStr = String(draft.length)
    if (lenStr.length === lenDigits) {
      return new TextEncoder().encode(`MRCP/2.0 ${lenStr} ${restOfStart}\r\n${headers}${body}`)
    }
    lenDigits = lenStr.length
  }
  throw new Error('mrcp length unstable')
}

describe('T54 registry', () => {
  it('registers mrcp handler, family, port, and engine 2.35.0', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toContain('mrcp')
    expect(familyForProtocol('mrcp').familyId).toBe('mrcp')
    expect(familyForProtocol('mrcp-body').familyId).toBe('mrcp')
    expect(SEMANTIC_SERVICE_PORTS.has(3242)).toBe(true)
    expect(PCAP_ENGINE_VERSION).toBe('2.35.0')
  })
})

describe('T54 RECOGNIZE / NLSML', () => {
  it('maps Channel-Identifier session, preserves @speechrecog and method; masks Interpret-Text and NLSML', () => {
    const nlsml = [
      '<?xml version="1.0"?>',
      '<result>',
      '<interpretation>',
      '<input mode="speech">CANARY-TRANSCRIPT-SECRET</input>',
      '<instance>42</instance>',
      '</interpretation>',
      '</result>',
    ].join('')
    const payload = encodeMrcp(
      'RECOGNIZE 7',
      [
        'Channel-Identifier: sess-CANARY-CH@speechrecog',
        'Interpret-Text: spoken canary phrase leak',
        'Content-Type: application/nlsml+xml',
        `Content-Length: ${nlsml.length}`,
      ],
      nlsml,
    )
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 3242, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't54-recog' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('mrcp'))).toBe(true)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('RECOGNIZE')).toBe(true)
    expect(out.includes('@speechrecog')).toBe(true)
    expect(out.includes('sess-CANARY-CH')).toBe(false)
    expect(out.includes('spoken canary phrase leak')).toBe(false)
    expect(out.includes('CANARY-TRANSCRIPT-SECRET')).toBe(false)
    expect(result.issues.some((i) => i.includes('mrcp'))).toBe(true)
  })
})

describe('T54 SPEAK / SSML', () => {
  it('preserves request-state/Completion-Cause; masks SSML prompt and Waveform-URI', () => {
    const ssml = '<speak>Please say CANARY-SSML-PROMPT</speak>'
    const payload = encodeMrcp(
      '1 200 COMPLETE',
      [
        'Channel-Identifier: synth-1@speechsynth',
        'Completion-Cause: 000 success',
        'Waveform-URI: <http://media.example.com/rec/TOKEN-WF-CANARY.wav>',
        'Content-Type: application/ssml+xml',
        `Content-Length: ${ssml.length}`,
      ],
      ssml,
    )
    const pkt = buildEthIpTcp([192, 0, 2, 2], [192, 0, 2, 1], 3242, 40_000, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't54-speak' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('200 COMPLETE')).toBe(true)
    expect(out.includes('Completion-Cause: 000 success')).toBe(true)
    expect(out.includes('@speechsynth')).toBe(true)
    expect(out.includes('CANARY-SSML-PROMPT')).toBe(false)
    expect(out.includes('TOKEN-WF-CANARY')).toBe(false)
    expect(out.includes('media.example.com')).toBe(false)
  })
})

describe('T54 voiceprint / unknown resource', () => {
  it('masks Voiceprint header and unknown @resource suffix', () => {
    const payload = encodeMrcp(
      'VERIFY 3',
      [
        'Channel-Identifier: vp-sess-9@custom-biometric-res',
        'Voiceprint: VP-TEMPLATE-CANARY-SECRET',
        'Content-Length: 0',
      ],
      '',
    )
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 50_000, 3242, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't54-vp' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('VP-TEMPLATE-CANARY-SECRET')).toBe(false)
    expect(out.includes('custom-biometric-res')).toBe(false)
    expect(out.includes('VERIFY')).toBe(true)
    expect(result.issues.some((i) => i.includes('voiceprint'))).toBe(true)
  })
})

describe('T54 grammar / XXE', () => {
  it('masks ABNF grammar literals and rejects XXE body', () => {
    const abnf = '#ABNF 1.0 UTF-8;\nprivate $name = "CANARY-ABNF-LITERAL";\n'
    const ok = encodeMrcp(
      'DEFINE-GRAMMAR 2',
      [
        'Channel-Identifier: g1@speechrecog',
        'Content-Type: application/srgs+xml',
        `Content-Length: ${abnf.length}`,
      ],
      abnf,
    )
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 3242, 1, ok)
    const mapping = new SessionMapping(undefined, { seed: 't54-gram' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('CANARY-ABNF-LITERAL')).toBe(false)

    const xxe = '<!DOCTYPE foo [<!ENTITY xxe "leak">]><a>&xxe;</a>'
    const bad = encodeMrcp(
      'DEFINE-GRAMMAR 9',
      [
        'Channel-Identifier: g2@speechrecog',
        'Content-Type: application/srgs+xml',
        `Content-Length: ${xxe.length}`,
      ],
      xxe,
    )
    const pkt2 = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_001, 3242, 2, bad)
    const result2 = sanitizePacket(packetInput(pkt2), DIAGNOSTIC_POLICY, mapping)
    const out2 = latin1(applyPatches(pkt2, result2))
    expect(out2.includes('ENTITY')).toBe(false)
    expect(result2.issues.some((i) => i.includes('xxe'))).toBe(true)
  })
})

/** Independent oracle: different algorithm than production tokenizer (no tree walk). */
function oracleExtractXmlSecrets(xml: string): string[] {
  const found: string[] = []
  let i = 0
  while (i < xml.length) {
    const cdata = xml.indexOf('<![CDATA[', i)
    const lt = xml.indexOf('<', i)
    if (cdata >= 0 && (lt < 0 || cdata <= lt)) {
      const end = xml.indexOf(']]>', cdata + 9)
      if (end < 0) break
      const inner = xml.slice(cdata + 9, end).trim()
      if (inner) found.push(inner)
      i = end + 3
      continue
    }
    if (lt < 0) break
    if (xml.startsWith('</', lt) || xml.startsWith('<?', lt) || xml.startsWith('<!', lt)) {
      const gt = xml.indexOf('>', lt)
      if (gt < 0) break
      i = gt + 1
      continue
    }
    const gt = xml.indexOf('>', lt)
    if (gt < 0) break
    // Attribute values in this start tag
    const tag = xml.slice(lt, gt + 1)
    const attrRe = /=\s*(["'])([\s\S]*?)\1/g
    let am: RegExpExecArray | null
    while ((am = attrRe.exec(tag)) !== null) {
      const v = (am[2] ?? '').trim()
      if (v && v !== 'speech' && !/^(?:[\d.]+|true|false)$/i.test(v) && !v.startsWith('http://www.w3')) {
        if (v.length >= 8) found.push(v)
      }
    }
    if (tag.endsWith('/>')) {
      i = gt + 1
      continue
    }
    const next = xml.indexOf('<', gt + 1)
    if (next < 0) break
    const text = xml.slice(gt + 1, next).trim()
    if (text && !/^[\d.]+$/.test(text)) found.push(text)
    i = next
  }
  return found
}

describe('T54 V05 NLSML CDATA transcript (both levels)', () => {
  const speechBody =
    '<result><interpretation><input>masked phrase</input><instance><![CDATA[AUDIT_SPEECH_CDATA_77319]]></instance></interpretation></result>'

  for (const policy of [DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY]) {
    it(`masks CDATA instance transcript (${policy.preset})`, () => {
      const payload = encodeMrcp(
        'RECOGNIZE 7',
        [
          'Channel-Identifier: session@speechrecog',
          'Content-Type: application/nlsml+xml',
          `Content-Length: ${speechBody.length}`,
        ],
        speechBody,
      )
      const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 3242, 1, payload)
      const mapping = new SessionMapping(undefined, { seed: `t54-v05-${policy.preset}` })
      const result = sanitizePacket(packetInput(pkt), policy, mapping)
      const out = latin1(applyPatches(pkt, result))
      expect(out.includes('AUDIT_SPEECH_CDATA_77319')).toBe(false)
      expect(out.includes('masked phrase')).toBe(false)

      // Independent decode oracle on the MRCP body region
      const bodyStart = out.indexOf('<result>')
      expect(bodyStart).toBeGreaterThanOrEqual(0)
      const bodyEnd = out.indexOf('</result>') + '</result>'.length
      const bodyXml = out.slice(bodyStart, bodyEnd)
      const leaked = oracleExtractXmlSecrets(bodyXml).filter((s) =>
        s.includes('AUDIT_SPEECH_CDATA') || s.includes('masked phrase'),
      )
      expect(leaked).toEqual([])
    })
  }
})
