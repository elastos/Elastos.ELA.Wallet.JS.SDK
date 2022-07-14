// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import BigNumber from "bignumber.js";
import { Buffer } from "buffer";
import {
  size_t,
  uint8_t,
  bytes_t,
  sizeof_uint256_t,
  uint256,
  uint32_t,
  sizeof_uint32_t
} from "../../types";
import { Payload } from "./Payload";
import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";
import { get32BytesOfBNAsHexString } from "../../common/bnutils";

export type SideChainPowInfo = {
  SideBlockHash: string;
  SideGenesisHash: string;
  BlockHeight: number;
  SignedData: string;
};

export class SideChainPow extends Payload {
  private _sideBlockHash: uint256;
  private _sideGenesisHash: uint256;
  private _blockHeight: uint32_t;
  private _signedData: bytes_t;
  constructor() {
    super();
    this._blockHeight = 0;
  }

  static newFromSideChainPow(payload: SideChainPow) {
    const sideChainPow = new SideChainPow();
    sideChainPow.copySideChainPow(payload);
    return sideChainPow;
  }

  static newFromParams(
    sideBlockHash: uint256,
    sideGensisHash: uint256,
    height: uint32_t,
    signedData: bytes_t
  ) {
    const sideChainPow = new SideChainPow();
    sideChainPow._sideBlockHash = sideBlockHash;
    sideChainPow._sideGenesisHash = sideGensisHash;
    sideChainPow._blockHeight = height;
    sideChainPow._signedData = signedData;
    return sideChainPow;
  }

  setSideBlockHash(sideBlockHash: uint256) {
    this._sideBlockHash = sideBlockHash;
  }

  setSideGenesisHash(sideGensisHash: uint256) {
    this._sideGenesisHash = sideGensisHash;
  }

  setBlockHeight(height: uint32_t) {
    this._blockHeight = height;
  }

  setSignedData(signedData: bytes_t) {
    this._signedData = signedData;
  }

  getSideBlockHash(): uint256 {
    return this._sideBlockHash;
  }

  getSideGenesisHash(): uint256 {
    return this._sideGenesisHash;
  }

  getBlockHeight(): uint32_t {
    return this._blockHeight;
  }

  getSignedData(): bytes_t {
    return this._signedData;
  }

  estimateSize(version: uint8_t): size_t {
    let size = 0;
    let stream = new ByteStream();

    size += sizeof_uint256_t();
    size += sizeof_uint256_t();
    size += sizeof_uint32_t();
    size += stream.writeVarUInt(this._signedData.length);
    size += this._signedData.length;

    return size;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    ostream.writeBNAsUIntOfSize(this._sideBlockHash, 32);
    ostream.writeBNAsUIntOfSize(this._sideGenesisHash, 32);
    ostream.writeUInt32(this._blockHeight);
    ostream.writeVarBytes(this._signedData);
  }

  deserialize(istream: ByteStream, version: uint8_t) {
    let sideBlockHash = istream.readUIntOfBytesAsBN(32);
    if (!sideBlockHash) return false;
    this._sideBlockHash = sideBlockHash;

    let sideGenesisHash = istream.readUIntOfBytesAsBN(32);
    if (!sideGenesisHash) return false;
    this._sideGenesisHash = sideGenesisHash;

    let blockHeight = istream.readUInt32();
    if (!blockHeight) return false;
    this._blockHeight = blockHeight;

    let signedData: bytes_t;
    signedData = istream.readVarBytes(signedData);
    if (!signedData) return false;
    this._signedData = signedData;
    return true;
  }

  toJson(version: uint8_t): SideChainPowInfo {
    let j = <SideChainPowInfo>{};

    j["SideBlockHash"] = get32BytesOfBNAsHexString(this._sideBlockHash);
    j["SideGenesisHash"] = get32BytesOfBNAsHexString(this._sideGenesisHash);
    j["BlockHeight"] = this._blockHeight;
    j["SignedData"] = this._signedData.toString("hex");

    return j;
  }

  fromJson(j: SideChainPowInfo, version: uint8_t) {
    this._sideBlockHash = new BigNumber(j["SideBlockHash"], 16);
    this._sideGenesisHash = new BigNumber(j["SideGenesisHash"], 16);
    this._blockHeight = j["BlockHeight"];
    this._signedData = Buffer.from(j["SignedData"], "hex");
  }

  copyPayload(payload: Payload) {
    try {
      const payloadSideMining = payload as SideChainPow;
      this.copySideChainPow(payloadSideMining);
    } catch (e) {
      Log.error("payload is not instance of SideChainPow");
    }

    return this;
  }

  copySideChainPow(payload: SideChainPow) {
    this._sideBlockHash = payload._sideBlockHash;
    this._sideGenesisHash = payload._sideGenesisHash;
    this._blockHeight = payload._blockHeight;
    this._signedData = Buffer.alloc(payload._signedData.length);
    payload._signedData.copy(this._signedData);

    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as SideChainPow;
      return (
        this._sideBlockHash.eq(p._sideBlockHash) &&
        this._sideGenesisHash.eq(p._sideGenesisHash) &&
        this._blockHeight == p._blockHeight &&
        this._signedData.equals(p._signedData)
      );
    } catch (e) {
      Log.error("payload is not instance of SideChainPow");
    }

    return false;
  }
}
