declare module 'bz2' {
  export function decompress(data: Uint8Array, checkCRC?: boolean): Uint8Array
}

declare module 'xz-decompress' {
  export class XzReadableStream extends ReadableStream<Uint8Array> {
    constructor(compressedStream: ReadableStream<Uint8Array>)
  }
}
