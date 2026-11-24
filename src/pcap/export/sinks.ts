/**
 * Export output sinks — Blob (portable) and File System Access (streaming).
 */

export type ExportSinkKind = 'blob' | 'file-system-access'

export interface ExportSink {
  readonly kind: ExportSinkKind
  write(chunk: ArrayBuffer): Promise<void>
  finalize(): Promise<{ blob?: Blob; fileName: string; byteLength: number }>
  abort(): Promise<void>
}

export class BlobExportSink implements ExportSink {
  readonly kind: ExportSinkKind = 'blob'
  readonly fileName: string
  private readonly _chunks: BlobPart[] = []
  private _bytes = 0
  private _aborted = false

  constructor(fileName: string) {
    this.fileName = fileName
  }

  async write(chunk: ArrayBuffer): Promise<void> {
    if (this._aborted) throw new Error('Export aborted')
    // PF-09: every chunk reaching this sink is a freshly allocated buffer (each pcap/pcapng
    // record writer allocates its own ArrayBuffer — see pcapWriter.ts/pcapngWriter.ts — and
    // export already transfers ownership across the worker boundary rather than cloning), so
    // there is nothing else holding a reference to defensively copy away from.
    this._chunks.push(chunk)
    this._bytes += chunk.byteLength
  }

  async finalize(): Promise<{ blob: Blob; fileName: string; byteLength: number }> {
    if (this._aborted) throw new Error('Export aborted')
    const blob = new Blob(this._chunks, { type: 'application/octet-stream' })
    return { blob, fileName: this.fileName, byteLength: this._bytes }
  }

  async abort(): Promise<void> {
    this._aborted = true
    this._chunks.length = 0
  }
}

export interface FileSystemAccessSinkOptions {
  writable: FileSystemWritableFileStream
  fileName: string
}

export class FileSystemAccessExportSink implements ExportSink {
  readonly kind: ExportSinkKind = 'file-system-access'
  readonly fileName: string
  private readonly _writable: FileSystemWritableFileStream
  private _bytes = 0
  private _aborted = false
  private _closed = false

  constructor(writable: FileSystemWritableFileStream, fileName: string) {
    this._writable = writable
    this.fileName = fileName
  }

  async write(chunk: ArrayBuffer): Promise<void> {
    if (this._aborted || this._closed) throw new Error('Export aborted')
    await this._writable.write(chunk)
    this._bytes += chunk.byteLength
  }

  async finalize(): Promise<{ fileName: string; byteLength: number }> {
    if (this._aborted) throw new Error('Export aborted')
    await this._writable.close()
    this._closed = true
    return { fileName: this.fileName, byteLength: this._bytes }
  }

  async abort(): Promise<void> {
    this._aborted = true
    try {
      await this._writable.abort()
    } catch {
      // Browser may reject abort on already-closed stream
    }
    this._closed = true
  }
}

export function triggerBlobDownload(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = fileName
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 30_000)
}

export function supportsFileSystemAccess(): boolean {
  return typeof window !== 'undefined' && 'showSaveFilePicker' in window
}

export async function pickExportFile(fileName: string, format: 'pcap' | 'pcapng'): Promise<FileSystemAccessExportSink | null> {
  if (!supportsFileSystemAccess()) return null
  try {
    const handle = await (window as unknown as { showSaveFilePicker: (opts: unknown) => Promise<FileSystemFileHandle> }).showSaveFilePicker({
      suggestedName: fileName,
      types: [
        {
          description: format === 'pcapng' ? 'PCAPNG capture' : 'PCAP capture',
          accept: { 'application/octet-stream': [format === 'pcapng' ? '.pcapng' : '.pcap'] },
        },
      ],
    })
    const writable = await handle.createWritable()
    return new FileSystemAccessExportSink(writable, fileName)
  } catch {
    return null
  }
}

export function supportsDirectoryPicker(): boolean {
  return typeof window !== 'undefined' && 'showDirectoryPicker' in window
}

export async function pickExportDirectory(): Promise<FileSystemDirectoryHandle | null> {
  if (!supportsDirectoryPicker()) return null
  try {
    return await (window as unknown as { showDirectoryPicker: () => Promise<FileSystemDirectoryHandle> }).showDirectoryPicker()
  } catch {
    return null
  }
}

export async function createDirectoryFileSink(
  directory: FileSystemDirectoryHandle,
  fileName: string,
): Promise<FileSystemAccessExportSink> {
  const handle = await directory.getFileHandle(fileName, { create: true })
  const writable = await handle.createWritable()
  return new FileSystemAccessExportSink(writable, fileName)
}

export async function writeBlobToDirectory(
  directory: FileSystemDirectoryHandle,
  fileName: string,
  blob: Blob,
): Promise<{ fileName: string; byteLength: number }> {
  const sink = await createDirectoryFileSink(directory, fileName)
  try {
    await writeBlobToSinkStreaming(sink, blob)
    return sink.finalize()
  } catch (err) {
    await sink.abort()
    throw err
  }
}

/**
 * Stream a Blob into a sink without materializing the whole file via `blob.arrayBuffer()`.
 */
export async function writeBlobToSinkStreaming(sink: ExportSink, blob: Blob): Promise<void> {
  const chunkSize = 256 * 1024
  if (typeof blob.stream === 'function') {
    const reader = blob.stream().getReader()
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        if (!value || value.byteLength === 0) continue
        const copy = new Uint8Array(value.byteLength)
        copy.set(value)
        await sink.write(copy.buffer)
      }
    } finally {
      reader.releaseLock()
    }
    return
  }
  for (let offset = 0; offset < blob.size; offset += chunkSize) {
    const end = Math.min(offset + chunkSize, blob.size)
    const part = await blob.slice(offset, end).arrayBuffer()
    await sink.write(part)
  }
}

export async function writeTextToDirectory(
  directory: FileSystemDirectoryHandle,
  fileName: string,
  text: string,
): Promise<{ fileName: string; byteLength: number }> {
  const blob = new Blob([text], { type: 'application/json;charset=utf-8' })
  return writeBlobToDirectory(directory, fileName, blob)
}
