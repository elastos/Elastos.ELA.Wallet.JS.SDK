/*
 * Copyright (c) 2021 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// NOTE: Ideally the nodejs build should use the native buffer, browser should use the polyfill.
// Buf haven't found a way to make this work for typescript files at the rollup build level.
import { Buffer } from "buffer";
import { keccak256 } from "js-sha3";
import { Base58, Base58Check } from "./base58";
import { DeterministicKey, Version } from "./deterministickey";
import { Mnemonic } from "./mnemonic";
import { SHA256 } from "./sha256";

export const SEQUENCE_GAP_LIMIT_EXTERNAL = 10;
export const SEQUENCE_GAP_LIMIT_INTERNAL = 5;
export const SEQUENCE_EXTERNAL_CHAIN = 0;
export const SEQUENCE_INTERNAL_CHAIN = 1;

export enum KeySpec {
  Elastos = 1,
  Bitcoin = 2,
  Ethereum = 3
}

export class HDKey {
  public static SEED_BYTES = 64;
  public static PUBLICKEY_BYTES = 33;
  public static PRIVATEKEY_BYTES = 32;
  public static EXTENDED_KEY_BYTES = DeterministicKey.LEN + 4;
  public static EXTENDED_PRIVATEKEY_BYTES = HDKey.EXTENDED_KEY_BYTES;
  public static EXTENDED_PUBLICKEY_BYTES = HDKey.EXTENDED_KEY_BYTES;

  /*
    private static bip32HeaderP2PKHpub = 0x0488b21e; // The 4 byte header that serializes in base58 to "xpub".
    private static bip32HeaderP2PKHpriv = 0x0488ade4; // The 4 byte header that serializes in base58 to "xprv"
    private static bip32HeaderP2WPKHpub = 0x04b24746; // The 4 byte header that serializes in base58 to "zpub".
    private static bip32HeaderP2WPKHpriv = 0x04b2430c; // The 4 byte header that serializes in base58 to "zprv"
    */

  // Derive path: m/44'/0'/0'/0/index
  public static ELASTOS_ACCOUNT_DERIVATION_PATH_PREFIX = "m/44'/0'/0'/0/"; //"44H/0H/kH/0/i";
  // Pre-derive publickey path: m/44'/0'/0'
  public static ELASTOS_ACCOUNT_PUBLICKEY_PREDERIVATION_PATH = "m/44'/0'/0'"; //"44H/0H/0H";

  public static BITCOIN_ACCOUNT_DERIVATION_PATH_PREFIX = "m/44'/0'/0'/0/"; //"44H/0H/kH/0/i";
  public static BITCOIN_ACCOUNT_PUBLICKEY_PREDERIVATION_PATH = "m/44'/0'/0'"; //"44H/0H/0H";

  public static ETHEREUM_ACCOUNT_DERIVATION_PATH_PREFIX = "m/44'/60'/0'/0/"; //"44H/60H/kH/0/i";
  public static ETHEREUM_ACCOUNT_PUBLICKEY_PREDERIVATION_PATH = "m/44'/60'/0'"; //"44H/60H/0H";

  private key: DeterministicKey;
  private spec: KeySpec;

  public static fromMnemonic(
    mnemonic: string,
    passphrase: string,
    spec?: KeySpec
  ): HDKey {
    let seed = Mnemonic.toSeed(mnemonic, passphrase);
    return HDKey.fromMasterSeed(seed, spec);
  }

  private static toVersion(spec?: KeySpec): Version {
    let version = DeterministicKey.ELASTOS_VERSIONS;
    if (spec) {
      switch (spec) {
        case KeySpec.Elastos:
          version = DeterministicKey.ELASTOS_VERSIONS;
          break;
        case KeySpec.Bitcoin:
          version = DeterministicKey.BITCOIN_VERSIONS;
          break;
        case KeySpec.Ethereum:
          version = DeterministicKey.ETHEREUM_VERSIONS;
          break;
        default:
          throw new RangeError("Unknown key spec");
      }
    }

    return version;
  }

  public static fromMasterSeed(seed: Buffer, spec?: KeySpec): HDKey {
    return HDKey.fromKey(
      DeterministicKey.fromMasterSeed(seed, HDKey.toVersion(spec)),
      spec
    );
  }

  public static fromKey(key: DeterministicKey, spec?: KeySpec): HDKey {
    return new HDKey(key, spec);
  }

  private constructor(key: DeterministicKey, spec?: KeySpec) {
    this.key = key;
    this.spec = spec || KeySpec.Elastos;
  }

  public getPrivateKeyBytes(): Buffer {
    return this.key.privateKey;
  }

  public getPrivateKeyBase58(): string {
    return Base58.encode(this.getPrivateKeyBytes());
  }

  public getPublicKeyBytes(): Buffer {
    return this.key.publicKey;
  }

  public getPublicKeyBase58(): string {
    return Base58.encode(this.getPublicKeyBytes());
  }

  public serialize(): Buffer {
    return Base58.decode(this.serializeBase58());
  }

  public serializeBase58(): string {
    let buffer = Base58.decode(this.key.privateExtendedKey);
    let base58Buffer = Buffer.alloc(82);
    buffer.copy(base58Buffer);
    let hash = SHA256.hashTwice(buffer);
    hash.copy(base58Buffer, 78, 0, 4);
    return Base58.encode(base58Buffer);
  }

  public serializePublicKey(): Buffer {
    return Base58.decode(this.serializePublicKeyBase58());
  }

  public serializePublicKeyBase58(): string {
    let buffer = Base58.decode(this.key.publicExtendedKey);
    let base58Buffer = Buffer.alloc(82);
    buffer.copy(base58Buffer);
    let hash = SHA256.hashTwice(buffer);
    hash.copy(base58Buffer, 78, 0, 4);
    return Base58.encode(base58Buffer);
  }

  public static deserialize(keyData: Buffer, spec?: KeySpec): HDKey {
    return this.deserializeBase58(Base58.encode(keyData), spec);
  }

  public static deserializeBase58(keyData: string, spec?: KeySpec): HDKey {
    return new HDKey(
      DeterministicKey.fromExtendedKey(keyData, HDKey.toVersion(spec)),
      spec
    );
  }

  public deriveWithPath(path: string): HDKey {
    return new HDKey(this.key.derive(path), this.spec);
  }

  public deriveWithIndex(index: number, hardened = false): HDKey {
    if (hardened) index += DeterministicKey.HARDENED_OFFSET;
    return new HDKey(this.key.deriveChild(index), this.spec);
  }

  // Bitcoin address
  private static BITCOIN_NETWORK = {
    messagePrefix: "\x18Bitcoin Signed Message:\n",
    bech32: "bc",
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80
  };

  private getBitcoinAddress(): string {
    const pkh = SHA256.sha256ripemd160(this.getPublicKeyBytes());

    const payload = Buffer.allocUnsafe(21);
    payload.writeUInt8(HDKey.BITCOIN_NETWORK.pubKeyHash, 0);
    pkh.copy(payload, 1);
    return Base58Check.encode(payload);
  }

  // Ethereum Address
  private getEthereumAddress(): string {
    //let pk = this.key.publicKeyUncompressed;
    //let bi = new BN(pk.slice(1, pk.length));
    //let bytes = Buffer.from(bi.toString("hex", 128), "hex");
    //let address = keccak256(bytes);

    let address = Buffer.from(
      keccak256(Buffer.from(this.key.publicKeyHex, "hex")),
      "hex"
    )
      .slice(-20)
      .toString("hex");

    //let addressHash = keccak256(address.slice(address.length - 40));
    let addressHash = keccak256(address);
    let checksumAddress = "0x";
    for (let i = 0; i < 40; i++)
      checksumAddress +=
        parseInt(addressHash[i], 16) > 7
          ? address[i].toUpperCase()
          : address[i];
    return checksumAddress;
  }

  // Elatos Addresses

  private static PADDING_STANDARD = 0x21;
  private static PADDING_IDENTITY = 0x67;

  private static SIGN_STANDARD = 0xac;
  private static SIGN_IDENTITY = 0xad;

  private static getElastosAddressFromBuffer(pk: Buffer): Buffer {
    let script = Buffer.alloc(35);
    script[0] = 33;
    pk.copy(script, 1);
    script[34] = HDKey.SIGN_STANDARD;

    let hash = SHA256.sha256ripemd160(script);
    let programHash = Buffer.alloc(hash.length + 1);
    programHash[0] = HDKey.PADDING_STANDARD;
    hash.copy(programHash, 1);

    hash = SHA256.hashTwice(programHash);
    let binAddress = Buffer.alloc(programHash.length + 4);
    programHash.copy(binAddress, 0);
    hash.copy(binAddress, programHash.length, 0, 4);

    return binAddress;
  }

  private getElastosAddress(): string {
    let binAddress = HDKey.getElastosAddressFromBuffer(
      this.getPublicKeyBytes()
    );
    return Base58.encode(binAddress);
  }

  private static getElastosDidAddressFromBuffer(pk: Buffer): Buffer {
    let script = Buffer.alloc(35);
    script[0] = 33;
    pk.copy(script, 1);
    script[34] = HDKey.SIGN_IDENTITY;

    let hash = SHA256.sha256ripemd160(script);
    let programHash = Buffer.alloc(hash.length + 1);
    programHash[0] = HDKey.PADDING_IDENTITY;
    hash.copy(programHash, 1);

    hash = SHA256.hashTwice(programHash);
    let binAddress = Buffer.alloc(programHash.length + 4);
    programHash.copy(binAddress, 0);
    hash.copy(binAddress, programHash.length, 0, 4);

    return binAddress;
  }

  // Public address methods

  public getAddress(): string {
    switch (this.spec) {
      case KeySpec.Elastos:
        return this.getElastosAddress();
      case KeySpec.Bitcoin:
        return this.getBitcoinAddress();
      case KeySpec.Ethereum:
        return this.getEthereumAddress();
    }
  }

  public getDidAddress(): string {
    if (this.spec != KeySpec.Elastos)
      throw new TypeError("Only available for Elastos keys");

    let binAddress = HDKey.getElastosDidAddressFromBuffer(
      this.getPublicKeyBytes()
    );
    return Base58.encode(binAddress);
  }

  public static toDidAddress(pk: Buffer): string {
    if (pk.length == HDKey.PUBLICKEY_BYTES)
      return Base58.encode(this.getElastosDidAddressFromBuffer(pk));
    else if (pk.length == HDKey.EXTENDED_PUBLICKEY_BYTES)
      return HDKey.deserialize(pk, KeySpec.Elastos).getDidAddress();
    else throw new RangeError("Invalid public key");
  }
}
