/**
 * T44 — ZIP/TAR support bundles: path safety, bomb/encrypt reject, expand + output ZIP.
 */
import { describe, expect, it } from 'vitest'
import { crc32 } from '../../src/crypto/crc32.ts'
import { validateArchivePath, safeEntryAlias } from '../../src/correlation/archive/pathSafety.ts'
import { buildZipStoreArchive } from '../../src/correlation/archive/zipWriter.ts'
import { readZipArchive, ZipReadError } from '../../src/correlation/archive/zipReader.ts'
import { readTarArchive, TarReadError } from '../../src/correlation/archive/tarReader.ts'
import {
  buildSupportBundleOutputZip,
  expandSupportBundle,
} from '../../src/correlation/archive/supportBundle.ts'
import { classifyForbiddenBundleContent } from '../../src/correlation/archive/contentGuard.ts'
import { MAPPING_BUNDLE_FORMAT } from '../../src/mapping/bundle/formatConstants.ts'
import { buildStagingItemsFromFiles, clearStagingItems, getLastSupportBundleOmissions } from '../../src/correlation/import/stagingModel.ts'

function ustarHeader(name: string, size: number, typeflag = 0x30): Uint8Array {
  const block = new Uint8Array(512)
  const enc = new TextEncoder()
  const nameBytes = enc.encode(name)
  block.set(nameBytes.subarray(0, Math.min(100, nameBytes.length)), 0)
  const mode = enc.encode('0000644\0')
  block.set(mode, 100)
  const sizeOct = `${size.toString(8).padStart(11, '0')}\0`
  block.set(enc.encode(sizeOct), 124)
  block.set(enc.encode('ustar\0'), 257)
  block.set(enc.encode('00'), 263)
  block[156] = typeflag
  // checksum
  for (let i = 148; i < 156; i++) block[i] = 0x20
  let sum = 0
  for (let i = 0; i < 512; i++) sum += block[i]!
  const chk = `${sum.toString(8).padStart(6, '0')}\0 `
  block.set(enc.encode(chk), 148)
  return block
}

function buildTar(files: Array<{ name: string; data: Uint8Array }>): Uint8Array {
  const parts: Uint8Array[] = []
  for (const f of files) {
    parts.push(ustarHeader(f.name, f.data.byteLength))
    parts.push(f.data)
    const pad = (512 - (f.data.byteLength % 512)) % 512
    if (pad) parts.push(new Uint8Array(pad))
  }
  parts.push(new Uint8Array(512))
  parts.push(new Uint8Array(512))
  let total = 0
  for (const p of parts) total += p.byteLength
  const out = new Uint8Array(total)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.byteLength
  }
  return out
}

describe('T44 path safety', () => {
  it('rejects traversal and absolute paths', () => {
    expect(validateArchivePath('../etc/passwd').ok).toBe(false)
    expect(validateArchivePath('/etc/passwd').ok).toBe(false)
    expect(validateArchivePath('C:\\windows\\a.log').ok).toBe(false)
    expect(validateArchivePath('logs/app.log').ok).toBe(true)
    expect(safeEntryAlias(1, 2, 'text')).toBe('d0/e01.log')
  })
})

describe('T44 ZIP roundtrip', () => {
  it('writes and reads store ZIP; CRC verified', async () => {
    const payload = new TextEncoder().encode('user=alice password=secret\n')
    const zip = buildZipStoreArchive([{ path: 'e01.log', data: payload }])
    expect(zip[0]).toBe(0x50)
    const members = await readZipArchive(zip)
    expect(members).toHaveLength(1)
    expect(members[0]!.relativePath).toBe('e01.log')
    expect(crc32(members[0]!.data)).toBe(crc32(payload))
    expect(new TextDecoder().decode(members[0]!.data)).toContain('password=secret')
  })

  it('rejects path traversal members', async () => {
    const zip = buildZipStoreArchive([{ path: '../evil.log', data: new Uint8Array([1]) }])
    // Writer allows any path — reader must reject
    await expect(readZipArchive(zip)).rejects.toMatchObject({ code: 'zip-path' })
  })

  it('rejects declared oversized entry as zip-bomb', async () => {
    const payload = new Uint8Array([0x61])
    const zip = buildZipStoreArchive([{ path: 'a.log', data: payload }])
    // Central directory uncompressed size at CD+24 — claim huge inflate.
    let cd = -1
    for (let i = 0; i < zip.byteLength - 4; i++) {
      if (zip[i] === 0x50 && zip[i + 1] === 0x4b && zip[i + 2] === 0x01 && zip[i + 3] === 0x02) {
        cd = i
        break
      }
    }
    expect(cd).toBeGreaterThan(0)
    const view = new DataView(zip.buffer, zip.byteOffset, zip.byteLength)
    view.setUint32(cd + 24, 0x7fffffff, true)
    await expect(readZipArchive(zip)).rejects.toMatchObject({ code: 'zip-bomb' })
  })

  it('rejects encrypted flag', async () => {
    // Craft minimal central+local with encrypt flag — easier: mutate a valid ZIP's GP bit
    const payload = new Uint8Array([0x61])
    const zip = buildZipStoreArchive([{ path: 'a.log', data: payload }])
    // Local header flags at offset 6
    zip[6] = 0x01
    zip[7] = 0x00
    // Also need central directory flags — find central sig
    let cd = -1
    for (let i = 0; i < zip.byteLength - 4; i++) {
      if (zip[i] === 0x50 && zip[i + 1] === 0x4b && zip[i + 2] === 0x01 && zip[i + 3] === 0x02) {
        cd = i
        break
      }
    }
    expect(cd).toBeGreaterThan(0)
    zip[cd + 8] = 0x01
    await expect(readZipArchive(zip)).rejects.toBeInstanceOf(ZipReadError)
    await expect(readZipArchive(zip)).rejects.toMatchObject({ code: 'zip-encrypted' })
  })
})

describe('T44 TAR', () => {
  it('reads ustar regular file', () => {
    const data = new TextEncoder().encode('hello\n')
    const tar = buildTar([{ name: 'var/log/app.log', data }])
    const members = readTarArchive(tar)
    expect(members.some((m) => m.relativePath === 'var/log/app.log')).toBe(true)
  })

  it('rejects symlink type', () => {
    const header = ustarHeader('link', 0, 0x32) // symlink
    const tar = new Uint8Array(512 + 512 + 512)
    tar.set(header, 0)
    expect(() => readTarArchive(tar)).toThrow(TarReadError)
  })
})

describe('T44 expand + omit', () => {
  it('expands ZIP with text+pcap; omits mapping bundle content', async () => {
    const log = new TextEncoder().encode('line one\n')
    // Minimal classic PCAP LE magic
    const pcap = new Uint8Array(24)
    pcap[0] = 0xd4
    pcap[1] = 0xc3
    pcap[2] = 0xb2
    pcap[3] = 0xa1
    pcap[16] = 1 // network ethernet
    const mapping = new TextEncoder().encode(
      JSON.stringify({ format: MAPPING_BUNDLE_FORMAT, schemaVersion: 1, identities: [] }),
    )
    const zip = buildZipStoreArchive([
      { path: 'logs/a.log', data: log },
      { path: 'cap/b.pcap', data: pcap },
      { path: 'secret.mapping.json', data: mapping },
    ])
    const file = new File([zip], 'bundle.zip', { type: 'application/zip' })
    const result = await expandSupportBundle(file)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.accepted.length).toBe(2)
    expect(result.omitted.some((o) => o.reason === 'forbidden-content')).toBe(true)
    expect(result.accepted.every((a) => !a.safeAlias.includes('secret'))).toBe(true)
    expect(classifyForbiddenBundleContent(mapping)).toBe('mapping-bundle')
  })

  it('output ZIP has REPORT.json and no original names', () => {
    const out = buildSupportBundleOutputZip({
      format: 'zip',
      anonymizedEntries: [{ alias: 'e01.log', data: new TextEncoder().encode('x=1\n') }],
      omitted: [{ safeAlias: 'e02.bin', reason: 'binary' }],
      partial: true,
    })
    const text = new TextDecoder().decode(out)
    expect(text).toContain('REPORT.json')
    expect(text).toContain('rnd-log-anonymizer-support-bundle-report')
    expect(text).not.toContain('customer')
    expect(text).not.toContain(MAPPING_BUNDLE_FORMAT)
  })
})

describe('T44 staging integration', () => {
  it('buildStagingItemsFromFiles expands ZIP into safe-aliased ready items', async () => {
    clearStagingItems()
    const log = new TextEncoder().encode('alpha\n')
    const zip = buildZipStoreArchive([{ path: 'nested/customer-id-999.log', data: log }])
    const file = new File([zip], 'diag.zip')
    const items = await buildStagingItemsFromFiles([file])
    const ready = items.filter((i) => i.status === 'ready')
    expect(ready.length).toBe(1)
    expect(ready[0]!.fileName).toMatch(/^e\d+\.log$|^d\d+\/e\d+\.log$/)
    expect(ready[0]!.fileName).not.toContain('customer')
    expect(ready[0]!.sourceFileName).toBe('diag.zip')
    expect(getLastSupportBundleOmissions().length).toBeGreaterThanOrEqual(0)
  })
})
