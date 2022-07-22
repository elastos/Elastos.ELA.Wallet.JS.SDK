// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { ByteStream } from "../common/bytestream";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { Log } from "../common/Log";
import { uint168 } from "../common/uint168";
import { bytes_t, UINT8_MAX, uint8_t } from "../types";
import { Base58Check } from "./base58";
import { SHA256 } from "./sha256";

export const ELA_SIDECHAIN_DESTROY_ADDR = "1111111111111111111114oLvT2";
export const OP_0 = 0x00;
export const OP_PUSHDATA1 = 0x4c;
export const OP_PUSHDATA2 = 0x4d;
export const OP_PUSHDATA4 = 0x4e;
export const OP_1NEGATE = 0x4f;
export const OP_1 = 0x51;
export const OP_16 = 0x60;
export const OP_DUP = 0x76;
export const OP_EQUAL = 0x87;
export const OP_EQUALVERIFY = 0x88;
export const OP_HASH160 = 0xa9;
export const OP_CHECKSIG = 0xac;

export enum SignType {
  SignTypeInvalid = 0,
  SignTypeStandard = 0xac,
  SignTypeDID = 0xad,
  SignTypeMultiSign = 0xae,
  SignTypeCrossChain = 0xaf,
  SignTypeDestroy = 0xaa
}

export enum Prefix {
  PrefixStandard = 0x21,
  PrefixMultiSign = 0x12,
  PrefixCrossChain = 0x4b,
  PrefixCRExpenses = 0x1c,
  PrefixDeposit = 0x1f,
  PrefixIDChain = 0x67,
  PrefixDestroy = 0,
  PrefixDPoSV2 = 0x3f
}

export type AddressArray = Address[];

export class Address {
  private _programHash: uint168;
  private _code: bytes_t;
  private _isValid = false;

  public static newFromAddressString(address: string): Address {
    let addr = new Address();

    if (!address) {
      addr._isValid = false;
    } else {
      let payload: bytes_t = Base58Check.decode(address);
      if (payload) {
        // _programHash includes a byte of prefix and 20 bytes of hash
        addr._programHash = uint168.newFrom21BytesBuffer(payload);
        addr.checkValid();
      } else {
        Log.error("invalid address {}", address);
        addr._isValid = false;
      }
    }
    return addr;
  }

  public static newFromAddress(address: Address): Address {
    let addr = new Address();
    addr._programHash = uint168.newFrom21BytesBuffer(
      address._programHash.bytes()
    );
    addr._code = Buffer.alloc(address._code.length);
    address._code.copy(addr._code);
    addr._isValid = address._isValid;
    return addr;
  }

  public static newWithPubKey(
    prefix: Prefix,
    pubKey: bytes_t,
    did = false
  ): Address {
    return Address.newWithPubKeys(prefix, [pubKey], 1, did);
  }

  public static newWithPubKeys(
    prefix: Prefix,
    pubkeys: bytes_t[],
    m: uint8_t, // number of requested signatures
    did = false
  ) {
    let address = new Address();
    if (pubkeys.length == 0) {
      address._isValid = false;
    } else {
      address.generateCode(prefix, pubkeys, m, did);
      address.generateProgramHash(prefix);
      address.checkValid();
    }
    return address;
  }

  public static newFromProgramHash(programHash: uint168) {
    let address = new Address();
    address._programHash = programHash;
    address.checkValid();
    return address;
  }

  public valid(): boolean {
    return this._isValid;
  }

  isIDAddress(): boolean {
    return this._isValid && this._programHash.prefix() == Prefix.PrefixIDChain;
  }

  public string(): string {
    return Base58Check.encode(this._programHash.bytes());
  }

  public programHash(): uint168 {
    return this._programHash;
  }

  setProgramHash(programHash: uint168) {
    this._programHash = programHash;
    this.checkValid();
  }

  public prefixToSignType(prefix: Prefix): SignType {
    let type: SignType;

    switch (prefix) {
      case Prefix.PrefixIDChain:
      case Prefix.PrefixStandard:
      case Prefix.PrefixDeposit:
      case Prefix.PrefixDPoSV2:
        type = SignType.SignTypeStandard;
        break;
      case Prefix.PrefixCrossChain:
        type = SignType.SignTypeCrossChain;
        break;
      case Prefix.PrefixMultiSign:
        type = SignType.SignTypeMultiSign;
        break;
      case Prefix.PrefixDestroy:
        type = SignType.SignTypeDestroy;
        break;
      default:
        Log.error("invalid prefix {}", prefix);
        type = SignType.SignTypeInvalid;
        break;
    }

    return type;
  }

  public setRedeemScript(prefix: Prefix, code: bytes_t) {
    this._code = Buffer.alloc(code.length);
    code.copy(this._code);
    this.generateProgramHash(prefix);
    this.checkValid();
    ErrorChecker.checkCondition(
      !this._isValid,
      Error.Code.InvalidArgument,
      "redeemscript is invalid"
    );
  }

  public changePrefix(prefix: Prefix): boolean {
    ErrorChecker.checkCondition(
      !this._isValid,
      Error.Code.Address,
      "can't change prefix with invalid addr"
    );
    let oldSignType = this._code[this._code.length - 1] as SignType;
    if (
      oldSignType == SignType.SignTypeMultiSign ||
      this.prefixToSignType(prefix) == SignType.SignTypeMultiSign
    )
      ErrorChecker.throwLogicException(
        Error.Code.Address,
        "can't change to or from multi-sign prefix"
      );

    this.generateProgramHash(prefix);
    return true;
  }

  convertToDID() {
    if (
      this._code.length !== 0 &&
      this._programHash.prefix() == Prefix.PrefixIDChain
    ) {
      this._code[this._code.length - 1] = SignType.SignTypeDID;
      this.generateProgramHash(Prefix.PrefixIDChain);
    }
  }

  public redeemScript(): bytes_t {
    if (this._code.length === 0)
      ErrorChecker.throwLogicException(
        Error.Code.Address,
        "can't call redeemScript, code not set"
      );

    return this._code;
  }

  public isLessThan(address: Address): boolean {
    const rs = this._programHash.bytes().compare(address._programHash.bytes());
    return rs == -1;
  }

  public equals(address: Address | string): boolean {
    if (typeof address === "string")
      return this._isValid && this.string() === address;
    else
      return (
        this._isValid == address._isValid &&
        this._programHash.bytes().equals(address._programHash.bytes())
      );
  }

  private generateCode(
    prefix: Prefix,
    pubkeys: bytes_t[],
    m: uint8_t,
    did: boolean
  ) {
    ErrorChecker.checkLogic(
      typeof m !== "number" || m > pubkeys.length || m == 0,
      Error.Code.MultiSignersCount,
      "Invalid m"
    );

    let bytes = new ByteStream();
    if (m == 1 && pubkeys.length == 1) {
      bytes.writeUInt8(pubkeys[0].length);
      bytes.writeBytes(pubkeys[0]);
      if (did) {
        bytes.writeUInt8(SignType.SignTypeDID);
      } else {
        bytes.writeUInt8(this.prefixToSignType(prefix));
      }
    } else {
      ErrorChecker.checkCondition(
        pubkeys.length >= UINT8_MAX - OP_1,
        Error.Code.MultiSignersCount,
        `Signers should less than ${UINT8_MAX - OP_1}.`
      );

      let sortedSigners: bytes_t[] = Array.from(pubkeys);
      sortedSigners.sort((a, b) => {
        return a.toString("hex").localeCompare(b.toString("hex"));
      });

      bytes.writeUInt8(OP_1 + m - 1);
      for (let i = 0; i < sortedSigners.length; i++) {
        bytes.writeUInt8(sortedSigners[i].length);
        bytes.writeBytes(sortedSigners[i]);
      }
      bytes.writeUInt8(OP_1 + sortedSigners.length - 1);
      if (prefix === Prefix.PrefixDPoSV2) {
        bytes.writeUInt8(SignType.SignTypeMultiSign);
      } else {
        bytes.writeUInt8(this.prefixToSignType(prefix));
      }
    }
    this._code = bytes.getBytes();
  }

  private generateProgramHash(prefix: Prefix) {
    let hash: bytes_t = SHA256.sha256ripemd160(this._code);
    this._programHash = uint168.newFromPrefixAndHash(prefix, hash);
  }

  private programHashPrefix(): Prefix {
    return this._programHash.prefix();
  }

  private checkValid(): boolean {
    if (
      this.programHashPrefix() == Prefix.PrefixDeposit ||
      this.programHashPrefix() == Prefix.PrefixStandard ||
      this.programHashPrefix() == Prefix.PrefixCrossChain ||
      this.programHashPrefix() == Prefix.PrefixMultiSign ||
      this.programHashPrefix() == Prefix.PrefixIDChain ||
      this.programHashPrefix() == Prefix.PrefixDestroy ||
      this.programHashPrefix() == Prefix.PrefixCRExpenses ||
      this.programHashPrefix() == Prefix.PrefixDPoSV2
    ) {
      this._isValid = true;
    } else {
      this._isValid = false;
    }

    return this._isValid;
  }
}
