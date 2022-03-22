import BigNumber from "bignumber.js";
import { bytes_t, size_t, UINT16_MAX, UINT32_MAX, uint8_t } from "../types";

export const VAR_INT16_HEADER = 0xfd;
export const VAR_INT32_HEADER = 0xfe;
export const VAR_INT64_HEADER = 0xff;
export const MAX_SCRIPT_LENGTH = 0x100; // scripts over this size will not be parsed for an address

const zero = new BigNumber(0);
const one = new BigNumber(1);
const n256 = new BigNumber(256);

export class ByteStream {
  private buffer: Uint8Array;
  private position: number;

  public constructor(buffer?: Buffer) {
    if (!buffer) {
      this.reset();
    } else {
      this.buffer = Buffer.concat([buffer]);
      this.position = buffer.length;
    }
  }

  /* public static wrap(buffer: Buffer): ByteBuffer {
        let bytes = new Uint8Array(buffer);
        for (let i = 0; i < buffer.length; ++i) {
            bytes[i] = buffer[i];

        }
        return new ByteBuffer(bytes);
    } */

  public reset() {
    this.buffer = new Uint8Array(0);
    this.position = 0;
  }

  public hasRemaining(): boolean {
    return this.size() > this.position;
  }

  /**
   * Actual bytes written
   */
  public size() {
    return this.buffer.length;
  }

  /**
   * Increases the available space available for writing more bytes to the buffer.
   */
  public reallocate(addedBytes = 50) {
    const new_array = new Uint8Array(this.size() + addedBytes);
    new_array.set(this.buffer);
    this.buffer = new_array;
  }

  /**
   * Reduces the buffer size to the real number of written bytes.
   */
  public shrink(): Uint8Array {
    this.buffer = this.buffer.subarray(0, this.position);
    return this.buffer;
  }

  /**
   * Move the position forward without reading or writing.
   */
  public skip(count: number) {
    this.position += count;
  }

  /**
   * Shrinks and returns the actual bytes in the buffer, as Buffer.
   */
  public getBytes(): Buffer {
    return Buffer.from(this.shrink());
  }

  public writeBytes(bytes: Buffer) {
    bytes.forEach((b) => this.writeByte(b));
  }

  public writeByte(b: uint8_t) {
    this.writeUInt8(b);
  }

  public writeUInt8(b: number) {
    if (b > 0xff) {
      throw b + " is over byte value";
    }

    if (this.buffer.length < this.position + 1) {
      this.reallocate();
    }
    this.buffer[this.position++] = b;
  }

  public readUInt8(index: number = null): number | null {
    if (index == null) index = this.position;

    if (this.buffer.length < index + 1) return null;

    this.position += 1;

    return this.buffer[index];
  }

  public readByte(): uint8_t {
    return this.readUInt8();
  }

  public writeUInt16(num: number) {
    if (num > 0xffff) {
      throw num + " is over short value";
    }
    const lower = 0x00ff & num;
    const upper = (0xff00 & num) >> 8;
    this.writeUInt8(lower);
    this.writeUInt8(upper);
  }

  public readUInt16(index: number = null): number {
    if (index == null) {
      index = this.position;
      this.position += 2;
    }
    if (this.buffer.length < index + 2) {
      return 0;
    }
    const lower = this.buffer[index];
    const upper = this.buffer[index + 1];
    return (upper << 8) + lower;
  }

  // Write integer to buffer by little endian
  public writeUInt32(num: number) {
    if (num > 0xffffffff) {
      throw num + " is over uint32 value";
    }

    const b0 = 0x000000ff & num;
    const b1 = (0x0000ff00 & num) >> 8;
    const b2 = (0x00ff0000 & num) >> 16;
    const b3 = (0xff000000 & num) >> 24;
    this.writeUInt8(b0);
    this.writeUInt8(b1);
    this.writeUInt8(b2);
    this.writeUInt8(b3);
  }

  public readUInt32(index: number = null): number {
    if (index > this.size() + 4) {
      throw new Error("OutOfBoundException");
    }
    if (index == null) {
      index = this.position;
      this.position += 4;
    }
    if (this.buffer.length < index + 4) {
      return 0;
    }
    const b0 = this.buffer[index];
    const b1 = this.buffer[index + 1];
    const b2 = this.buffer[index + 2];
    const b3 = this.buffer[index + 3];
    return (b3 << 24) + (b2 << 16) + (b1 << 8) + b0;
  }

  public readUInt64(index: number = null): number {
    if (index > this.size() + 8) {
      throw new Error("OutOfBoundException");
    }
    if (index == null) {
      index = this.position;
      this.position += 8;
    }
    if (this.buffer.length < index + 8) {
      return 0;
    }
    const b0 = this.buffer[index];
    const b1 = this.buffer[index + 1];
    const b2 = this.buffer[index + 2];
    const b3 = this.buffer[index + 3];
    const b4 = this.buffer[index + 4];
    const b5 = this.buffer[index + 5];
    const b6 = this.buffer[index + 6];
    const b7 = this.buffer[index + 7];
    return (
      (b7 << 56) +
      (b6 << 48) +
      (b5 << 40) +
      (b4 << 32) +
      (b3 << 24) +
      (b2 << 16) +
      (b1 << 8) +
      b0
    );
  }

  /**
   * Writes a bignumber in the buffer, taking bytes bytes of space.
   */
  // https://stackoverflow.com/questions/48521840/biginteger-to-a-uint8array-of-bytes
  public writeBNAsUIntOfSize(bn: BigNumber, bytes: number) {
    let i = 0;
    while (i < bytes) {
      // Write bytes one by one - 32 bytes for a uint256
      this.writeUInt8(bn.mod(n256).toNumber());
      bn = bn.dividedBy(n256);
      i += 1;
    }
  }

  public writeBigNumber(bn: BigNumber) {
    while (bn.gt(0)) {
      // Write bytes one by one until there is nothing left to write
      this.writeUInt8(bn.mod(n256).toNumber());
      bn = bn.dividedBy(n256);
    }
  }

  /**
   * Reads bytes bytes in the buffer to recompose a big number.
   */
  public readUIntOfBytesAsBN(bytes: number): BigNumber | null {
    let result = zero;
    let base = one;

    let index = this.position;
    for (let i = 0; i < bytes; i++) {
      let byte = this.buffer[index];
      result = result.plus(base.multipliedBy(byte));
      base = base.multipliedBy(n256);
    }
    return result;
  }

  /**
   * Writes a variable number of bytes, with their size
   */
  public writeVarBytes(bytes: bytes_t) {
    this.writeVarUInt(bytes.length); // WAS (uint64_t) bytes.size()
    this.writeBytes(bytes);
  }

  // TODO: C++ version can read bytes or various uint sizes. Let's try to focus bytes for bytes and
  // use other methods for uints
  public readVarBytes(bytes: bytes_t): boolean {
    let length = this.readVarUInt().toNumber(); // length is never a large number
    return this.readBytes(bytes, length);
  }

  /**
   * @param bytes Output buffer. If not enough space, more space will be allocated
   * @param length Number of bytes to read
   */
  public readBytes(bytes: bytes_t, length: size_t): boolean {
    // TODO: alloc buffer "bytes" ?
    for (let i = 0; i < length; i++) bytes[i] = this.buffer[this.position++];
    return true;
  }

  /**
   * Writes a number that can spare a various number of bytes in the buffer
   * depending on its value.
   *
   * 64 bits number max.
   *
   * @return the number of written bytes.
   */
  public writeVarUInt(len: number | BigNumber): size_t {
    if (!(len instanceof BigNumber)) len = new BigNumber(len);

    let count: size_t;
    if (len.lt(VAR_INT16_HEADER)) {
      this.writeUInt8(len.toNumber()); // WAS _buf.push_back((uint8_t) len);
      count = 1;
    } else if (len.lte(UINT16_MAX)) {
      this.writeUInt8(VAR_INT16_HEADER); // WAS _buf.push_back(VAR_INT16_HEADER);
      this.writeUInt16(len.toNumber()); // WAS _buf += bytes_t((unsigned char *) &len, 2);
      count = 2;
    } else if (len.lte(UINT32_MAX)) {
      this.writeUInt8(VAR_INT32_HEADER); // WAS _buf.push_back(VAR_INT32_HEADER);
      this.writeUInt32(len.toNumber()); // WAS _buf += bytes_t((unsigned char *) &len, 4);
      count = 4;
    } else {
      this.writeUInt8(VAR_INT64_HEADER); // WAS _buf.push_back(VAR_INT64_HEADER);
      this.writeBNAsUIntOfSize(len, 8); // WAS _buf += bytes_t((unsigned char *) & len, 8);
      count = 8;
    }
    return count;
  }

  public readVarUInt(): BigNumber {
    let h = this.readUInt8();

    switch (h) {
      case VAR_INT16_HEADER:
        return new BigNumber(this.readUInt16());
      case VAR_INT32_HEADER:
        return new BigNumber(this.readUInt32());
      case VAR_INT64_HEADER:
        return this.readUIntOfBytesAsBN(8);
      default:
        return new BigNumber(h);
    }
  }

  public writeVarString(str: string) {
    this.writeVarBytes(Buffer.from(str, "utf8"));
  }

  /**
   * Reads a size-prefixed string in a buffer without knowing its size.
   * The number of bytes to read is stored in that prefix.
   */
  public readVarString(): string | null {
    let bytes = Buffer.alloc(0);
    if (!this.readVarBytes(bytes)) {
      return null;
    }
    return bytes.toString();
  }

  public writeAsciiString(str: string) {
    let len = str.length;
    if (this.position + len < this.buffer.byteLength) this.reallocate(len);

    for (let i = 0; i < len; i++)
      this.buffer[this.position + i] = str.charCodeAt(i);

    this.position += len;
  }
}
