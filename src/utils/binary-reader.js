/**
 * Binary Reader — Structured binary data parsing utility
 * Wraps DataView with offset tracking and typed reads
 */
export class BinaryReader {
  constructor(buffer, littleEndian = true) {
    if (buffer instanceof ArrayBuffer) {
      this.view = new DataView(buffer);
      this.bytes = new Uint8Array(buffer);
    } else if (buffer instanceof Uint8Array) {
      this.view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
      this.bytes = buffer;
    } else {
      throw new Error('BinaryReader: expected ArrayBuffer or Uint8Array');
    }
    this.offset = 0;
    this.littleEndian = littleEndian;
  }

  get remaining() { return this.bytes.length - this.offset; }
  get length() { return this.bytes.length; }
  get eof() { return this.offset >= this.bytes.length; }

  seek(pos) { this.offset = pos; return this; }
  skip(n) { this.offset += n; return this; }
  tell() { return this.offset; }

  uint8() {
    const v = this.view.getUint8(this.offset);
    this.offset += 1;
    return v;
  }

  uint16(le) {
    const v = this.view.getUint16(this.offset, le ?? this.littleEndian);
    this.offset += 2;
    return v;
  }

  uint32(le) {
    const v = this.view.getUint32(this.offset, le ?? this.littleEndian);
    this.offset += 4;
    return v;
  }

  int32(le) {
    const v = this.view.getInt32(this.offset, le ?? this.littleEndian);
    this.offset += 4;
    return v;
  }

  readBytes(n) {
    const slice = this.bytes.slice(this.offset, this.offset + n);
    this.offset += n;
    return slice;
  }

  peekBytes(n) {
    return this.bytes.slice(this.offset, this.offset + n);
  }

  readString(n) {
    const bytes = this.readBytes(n);
    return new TextDecoder('ascii').decode(bytes);
  }

  /** Read a uint24 (3 bytes big-endian) */
  uint24BE() {
    const b0 = this.uint8();
    const b1 = this.uint8();
    const b2 = this.uint8();
    return (b0 << 16) | (b1 << 8) | b2;
  }

  /** Create a sub-reader for a slice of bytes */
  slice(length) {
    const sub = new BinaryReader(this.readBytes(length), this.littleEndian);
    return sub;
  }

  /** Read remaining bytes */
  readRemaining() {
    return this.readBytes(this.remaining);
  }
}
