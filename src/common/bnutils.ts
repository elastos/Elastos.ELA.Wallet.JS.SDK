import BigNumber from "bignumber.js";
import { ByteStream } from "./bytestream";

/**
 * TODO - VERIFY
 * Returns the Buffer representing the big number as a base 16 (hex) STRING.
 * Eg: Big number 100 (base 10) = 64 (base 16) -> Buffer contains string "64"
 */
export const getBNHexBytes = (bn: BigNumber): Buffer => {
  let stream = new ByteStream();
  let bnStr = bn.toString(16);
  stream.writeAsciiString(bnStr);
  return stream.getBytes();
}

/**
 * TODO: VERIFY
 * Convert a hex string in a buffer into a big number
 */
export const newBNFromHexBytes = (bytes: Buffer): BigNumber => {
  return new BigNumber(bytes.toString("hex"));
}

/**
 * TODO - VERIFY
 * Returns the Buffer representing the big number in memory.
 * (standard integer encoding such as 0xABCD with 'AB' being one byte).
 */
export const getBNBytes = (bn: BigNumber): Buffer => {
  let stream = new ByteStream();
  stream.writeBigNumber(bn);
  return stream.getBytes();
}

/**
 * Size in bytes needed to represent a big number value encoded as memory number.
 * Eg: 100 (base 10) => 0x64 in memory
 */
export const getBNsize = (bn: BigNumber): number => {
  let bnBytes = getBNBytes(bn);
  return bnBytes.length;
}

/**
 * Rebuilds a big number from a buffer that represents a long decimal number.
 */
export const newBNFromBuffer = (buffer: Buffer): BigNumber => {
  let bytestream = new ByteStream(buffer);
  return bytestream.readUIntOfBytesAsBN(buffer.length);
}