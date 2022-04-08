import { Prefix } from "../walletcore/Address";

/**
 * NOTE: Attempt to reproduce a uint168 class in JS to deal with byte buffers.
 * Not looking for performance.
 */
export class uint168 {
  private buffer: Uint8Array;

  public static newFrom21BytesBuffer(payload: Buffer): uint168 {
    if (payload.length != 21)
      throw new Error(
        `uint168: Invalid payload size ${payload.length}. 21 expected`
      );

    let int = new uint168();
    int.buffer = Buffer.alloc(21);
    payload.copy(int.buffer);

    return int;
  }

  /**
   * @param prefix 1 byte prefix
   * @param hash 20 bytes hash
   */
  public static newFromPrefixAndHash(prefix: Prefix, hash: Buffer): uint168 {
    let int = new uint168();
    int.buffer = Buffer.alloc(1 + hash.length);
    int.buffer[0] = prefix;
    hash.copy(int.buffer, 1);

    return int;
  }

  public prefix(): Prefix {
    return this.buffer[0];
  }

  public bytes(): Buffer {
    return Buffer.from(this.buffer);
  }
}
