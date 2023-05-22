// Copyright (c) 2017-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import BigNumber from "bignumber.js";
import { Log } from "../../common/Log";
import { get32BytesOfBNAsHexString } from "../../common/bnutils";
import { ByteStream } from "../../common/bytestream";
import { size_t, sizeof_uint256_t, uint256 } from "../../types";
import { Payload } from "./Payload";


export type CreateNFTInfo = {
  // Referkey is the hash of detailed vote information
  // NFT ID: hash of (detailed vote information + createNFT tx hash).
  ReferKey: string,

  // stake address of detailed vote.
  StakeAddress: string,

  // genesis block hash of side chain.
  GenesisBlockHash: string
 };

export class CreateNFT extends Payload {
  private _referKey: uint256;
  private _stakeAddress: string; // address of stake owner，begin with 'S'
  private _genesisBlockHash: uint256;

  static newFromParams(referKey: uint256, stakeAddress: string, genesisBlockHash: uint256) {
    let createNFT = new CreateNFT();
    createNFT._referKey = referKey;
    createNFT._stakeAddress = stakeAddress;
    createNFT._genesisBlockHash = genesisBlockHash;
    return createNFT;
  }

  estimateSize(): size_t {
    let size = 0;

    size += sizeof_uint256_t();

    let stream = new ByteStream();
    let stakeAddress = Buffer.from(this._stakeAddress, "utf8");
    size += stream.writeVarUInt(stakeAddress.length);
    size += stakeAddress.length;

    size += sizeof_uint256_t();

    return size;
  }

  serialize(stream: ByteStream) {
    stream.writeBNAsUIntOfSize(this._referKey, 32);
    stream.writeVarString(this._stakeAddress);
    stream.writeBNAsUIntOfSize(this._genesisBlockHash, 32);
  }

  deserialize(stream: ByteStream): boolean {
    this._referKey = stream.readUIntOfBytesAsBN(32);
    if (!this._referKey) {
      Log.error("CreateNFT deserialize refer key failed");
      return false;
    }

    let stakeAddress;
    stakeAddress = stream.readVarString();
    if (!stakeAddress) {
      Log.error("CreateNFT deserialize stake address failed");
      return false;
    }
    this._stakeAddress = stakeAddress;

    let genesisBlockHash = stream.readUIntOfBytesAsBN(32);
    if (!genesisBlockHash) {
      Log.error("CreateNFT deserialize genesis block hash failed");
      return false;
    }
    this._genesisBlockHash = genesisBlockHash;
    return true;
  }

  toJson(): CreateNFTInfo {
    let j = <CreateNFTInfo>{};

    j["ReferKey"] = get32BytesOfBNAsHexString(this._referKey);
    j["StakeAddress"] = this._stakeAddress;
    j["GenesisBlockHash"] = get32BytesOfBNAsHexString(this._genesisBlockHash);

    return j;
  }

  fromJson(j: CreateNFTInfo) {
    this._referKey = new BigNumber(j["ReferKey"], 16);
    this._stakeAddress = j["StakeAddress"];
    this._genesisBlockHash = new BigNumber(j["GenesisBlockHash"], 16);
  }

  copyPayload(payload: Payload) {
    try {
      let p = payload as CreateNFT;
      this.copyCreateNFT(p);
    } catch (e) {
      Log.error("payload is not instance of CreateNFT");
    }

    return this;
  }

  copyCreateNFT(payload: CreateNFT) {
    this._referKey = payload._referKey;
    this._stakeAddress = payload._stakeAddress;
    this._genesisBlockHash = payload._genesisBlockHash;
    return this;
  }

  equals(payload: Payload): boolean {
    try {
      let p = payload as CreateNFT;
      return (
        this._referKey == p._referKey &&
        this._stakeAddress == p._stakeAddress &&
        this._genesisBlockHash == p._genesisBlockHash
      );
    } catch (e) {
      Log.error("payload is not instance of CreateNFT");
    }

    return false;
  }
}
