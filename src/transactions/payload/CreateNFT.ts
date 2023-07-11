// Copyright (c) 2017-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import BigNumber from "bignumber.js";
import { Log } from "../../common/Log";
import { get32BytesOfBNAsHexString } from "../../common/bnutils";
import { ByteStream } from "../../common/bytestream";
import { bytes_t, size_t, sizeof_uint256_t, sizeof_uint32_t, sizeof_uint64_t, uint256, uint32_t, uint64_t } from "../../types";
import { Payload } from "./Payload";


export type CreateNFTInfo = {
  // Referkey is the hash of detailed vote information
  // NFT ID: hash of (detailed vote information + createNFT tx hash).
  ReferKey: string,
  // stake address of detailed vote.
  StakeAddress: string,
  // genesis block hash of side chain.
  GenesisBlockHash: string,
  // the start height of votes
  StartHeight: number,
  // End height of stake voting
  EndHeight: number,
  // the DPoS 2.0 votes.
  Votes: string,
  // the DPoS 2.0 vote rights.
  VoteRights: string,
  // the votes to the producer, and TargetOwnerPublicKey is the producer's owner key.
  TargetOwnerKey: string,
 };

export class CreateNFT extends Payload {
  private _referKey: uint256;
  private _stakeAddress: string; // address of stake owner，begin with 'S'
  private _genesisBlockHash: uint256;

  private _startHeight: uint32_t;
  private _endHeight: uint32_t;
  private _votes: uint64_t;
  private _voteRights: uint64_t;

  private _targetOwnerKey: bytes_t

  static newFromParams(referKey: uint256, stakeAddress: string, genesisBlockHash: uint256,
      startHeight: number, endHeight: number, votes: uint64_t, voteRright: uint64_t, targetOwnerKey: bytes_t) {
    let createNFT = new CreateNFT();
    createNFT._referKey = referKey;
    createNFT._stakeAddress = stakeAddress;
    createNFT._genesisBlockHash = genesisBlockHash;
    createNFT._startHeight = startHeight;
    createNFT._endHeight = endHeight;
    createNFT._votes = votes;
    createNFT._voteRights = voteRright;
    createNFT._targetOwnerKey = targetOwnerKey;
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

    size += sizeof_uint32_t(); // startHeight
    size += sizeof_uint32_t(); // endHeight

    size += sizeof_uint64_t(); // Votes
    size += sizeof_uint64_t(); // VoteRights

    size += stream.writeVarUInt(this._targetOwnerKey.length);
    size += this._targetOwnerKey.length;

    return size;
  }

  serialize(stream: ByteStream) {
    stream.writeBNAsUIntOfSize(this._referKey, 32);
    stream.writeVarString(this._stakeAddress);
    stream.writeBNAsUIntOfSize(this._genesisBlockHash, 32);

    stream.writeUInt32(this._startHeight);
    stream.writeUInt32(this._endHeight);

    stream.writeBNAsUIntOfSize(this._votes, 8);
    stream.writeBNAsUIntOfSize(this._voteRights, 8);

    stream.writeVarBytes(this._targetOwnerKey);
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

    let startHeight = stream.readUInt32();
    if (!startHeight) {
      Log.error("CreateNFT deserialize: read startHeight");
      return false;
    }
    this._startHeight = startHeight;

    let endHeight = stream.readUInt32();
    if (!endHeight) {
      Log.error("CreateNFT deserialize: end startHeight");
      return false;
    }
    this._endHeight = endHeight;


    let votes = stream.readUIntOfBytesAsBN(8);
    if (!votes) {
      Log.error("CreateNFTd eserialize: read votes key");
      return false;
    }
    this._votes = votes;

    let voteRights = stream.readUIntOfBytesAsBN(8);
    if (!voteRights) {
      Log.error("CreateNFT deserialize: read voteRights key");
      return false;
    }
    this._voteRights = voteRights;

    let targetOwnerKey: bytes_t;
    targetOwnerKey = stream.readVarBytes(targetOwnerKey);
    if (!targetOwnerKey) {
      Log.error("CreateNFT deserialize: read targetOwnerKey");
      return false;
    }
    this._targetOwnerKey = targetOwnerKey;
    return true;
  }

  toJson(): CreateNFTInfo {
    let j = <CreateNFTInfo>{};

    j["ReferKey"] = get32BytesOfBNAsHexString(this._referKey);
    j["StakeAddress"] = this._stakeAddress;
    j["GenesisBlockHash"] = get32BytesOfBNAsHexString(this._genesisBlockHash);
    j["StartHeight"] = this._startHeight;
    j["EndHeight"] = this._endHeight;
    j["Votes"] = this._votes.toString();
    j["VoteRights"] = this._voteRights.toString();
    j["OwnerPublicKey"] = this._targetOwnerKey.toString("hex");

    return j;
  }

  fromJson(j: CreateNFTInfo) {
    this._referKey = new BigNumber(j["ReferKey"], 16);
    this._stakeAddress = j["StakeAddress"];
    this._genesisBlockHash = new BigNumber(j["GenesisBlockHash"], 16);
    this._startHeight = j["StartHeight"];
    this._endHeight = j["EndHeight"];
    this._votes = new BigNumber(j["Votes"]);
    this._voteRights = new BigNumber(j["VoteRights"]);
    this._targetOwnerKey = Buffer.from(j["TargetOwnerKey"], "hex");
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
    this._startHeight = payload._startHeight;
    this._endHeight = payload._endHeight;
    this._votes = payload._votes;
    this._voteRights = payload._voteRights;
    this._targetOwnerKey = payload._targetOwnerKey;
    return this;
  }

  equals(payload: Payload): boolean {
    try {
      let p = payload as CreateNFT;
      return (
        this._referKey == p._referKey &&
        this._stakeAddress == p._stakeAddress &&
        this._genesisBlockHash == p._genesisBlockHash &&
        this._startHeight == p._startHeight &&
        this._endHeight == p._endHeight &&
        this._votes.eq(p._votes) &&
        this._voteRights.eq(p._voteRights) &&
        this._targetOwnerKey.equals(p._targetOwnerKey)
      );
    } catch (e) {
      Log.error("payload is not instance of CreateNFT");
    }

    return false;
  }
}
