// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import BigNumber from "bignumber.js";
import {
  size_t,
  uint8_t,
  sizeof_uint256_t,
  uint256,
  uint32_t,
  sizeof_uint32_t
} from "../../types";
import { Payload } from "./Payload";
import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";
import { get32BytesOfBNAsHexString } from "../../common/bnutils";

export type WithdrawFromSideChainInfo = {
  BlockHeight: number;
  GenesisBlockAddress: string;
  SideChainTransactionHash: string[];
};

export class WithdrawFromSideChain extends Payload {
  private _blockHeight: uint32_t;
  private _genesisBlockAddress: string;
  private _sideChainTransactionHash: uint256[];

  consturctor() {
    this._blockHeight = 0;
    this._genesisBlockAddress = "";
  }

  static newFromWithdrawFromSideChain(payload: WithdrawFromSideChain) {
    const rs = new WithdrawFromSideChain();
    rs.copyWithdrawFromSideChain(payload);
    return rs;
  }

  static newFromParams(
    blockHeight: uint32_t,
    genesisBlockAddress: string,
    sideChainTransactionHash: uint256[]
  ) {
    const rs = new WithdrawFromSideChain();
    rs._blockHeight = blockHeight;
    rs._genesisBlockAddress = genesisBlockAddress;
    rs._sideChainTransactionHash = sideChainTransactionHash;
    return rs;
  }

  setBlockHeight(blockHeight: uint32_t) {
    this._blockHeight = blockHeight;
  }

  getBlockHeight(): uint32_t {
    return this._blockHeight;
  }

  setGenesisBlockAddress(genesisBlockAddress: string) {
    this._genesisBlockAddress = genesisBlockAddress;
  }

  getGenesisBlockAddress(): string {
    return this._genesisBlockAddress;
  }

  setSideChainTransacitonHash(sideChainTransactionHash: uint256[]) {
    this._sideChainTransactionHash = sideChainTransactionHash;
  }

  getSideChainTransacitonHash() {
    return this._sideChainTransactionHash;
  }

  estimateSize(version: uint8_t): size_t {
    let size = 0;
    let stream = new ByteStream();

    size += sizeof_uint32_t();
    size += stream.writeVarUInt(this._genesisBlockAddress.length);
    size += this._genesisBlockAddress.length;
    size += stream.writeVarUInt(this._sideChainTransactionHash.length);

    for (let i = 0; i < this._sideChainTransactionHash.length; ++i)
      size += sizeof_uint256_t();

    return size;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    ostream.writeUInt32(this._blockHeight);
    ostream.writeVarString(this._genesisBlockAddress);
    ostream.writeVarUInt(this._sideChainTransactionHash.length);

    for (let i = 0; i < this._sideChainTransactionHash.length; ++i) {
      ostream.writeBNAsUIntOfSize(this._sideChainTransactionHash[i], 32);
    }
  }

  deserialize(istream: ByteStream, version: uint8_t) {
    let blockHeight = istream.readUInt32();
    if (!blockHeight) {
      Log.error("Payload with draw asset deserialize block height fail");
      return false;
    }
    this._blockHeight = blockHeight;

    let genesisBlockAddress = istream.readVarString();
    if (!genesisBlockAddress) {
      Log.error(
        "Payload with draw asset deserialize genesis block address fail"
      );
      return false;
    }
    this._genesisBlockAddress = genesisBlockAddress;

    let len = istream.readVarUInt();
    if (!len) {
      Log.error(
        "Payload with draw asset deserialize side chain tx hash len fail"
      );
      return false;
    }

    this._sideChainTransactionHash = [];
    for (let i = 0; i < len.toNumber(); ++i) {
      let hash = istream.readUIntOfBytesAsBN(32);
      if (!hash) {
        Log.error(
          "Payload with draw asset deserialize side chain tx hash[{}] fail",
          i
        );
        return false;
      }
      this._sideChainTransactionHash.push(hash);
    }

    return true;
  }

  toJson(version: uint8_t): WithdrawFromSideChainInfo {
    let j = <WithdrawFromSideChainInfo>{};

    j["BlockHeight"] = this._blockHeight;
    j["GenesisBlockAddress"] = this._genesisBlockAddress;
    let hashes = [];
    for (let i = 0; i < this._sideChainTransactionHash.length; ++i) {
      hashes.push(get32BytesOfBNAsHexString(this._sideChainTransactionHash[i]));
    }
    j["SideChainTransactionHash"] = hashes;

    return j;
  }

  fromJson(j: WithdrawFromSideChainInfo, version: uint8_t) {
    this._blockHeight = j["BlockHeight"];
    this._genesisBlockAddress = j["GenesisBlockAddress"];

    let hashes = j["SideChainTransactionHash"];
    this._sideChainTransactionHash = [];
    for (let i = 0; i < hashes.length; ++i) {
      this._sideChainTransactionHash.push(new BigNumber(hashes[i], 16));
    }
  }

  copyPayload(payload: Payload) {
    try {
      const payloadWithDrawAsset = payload as WithdrawFromSideChain;
      this.copyWithdrawFromSideChain(payloadWithDrawAsset);
    } catch (e) {
      Log.error("payload is not instance of WithdrawFromSideChain");
    }

    return this;
  }

  copyWithdrawFromSideChain(payload: WithdrawFromSideChain) {
    this._blockHeight = payload._blockHeight;
    this._genesisBlockAddress = payload._genesisBlockAddress;
    this._sideChainTransactionHash = payload._sideChainTransactionHash;

    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as WithdrawFromSideChain;
      let equal = false;
      for (let i = 0; i < p._sideChainTransactionHash.length; ++i) {
        for (let j = 0; j < this._sideChainTransactionHash.length; ++j) {
          if (
            this._sideChainTransactionHash[j].eq(p._sideChainTransactionHash[i])
          ) {
            equal = true;
            break;
          } else {
            equal = false;
          }
        }
        if (equal === false) {
          return false;
        }
      }

      return (
        equal &&
        this._blockHeight == p._blockHeight &&
        this._genesisBlockAddress == p._genesisBlockAddress
      );
    } catch (e) {
      Log.error("payload is not instance of WithdrawFromSideChain");
    }

    return false;
  }
}
