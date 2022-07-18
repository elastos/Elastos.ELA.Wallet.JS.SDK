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
  uint256
} from "../../types";
import { Payload } from "./Payload";
import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";
import { get32BytesOfBNAsHexString } from "../../common/bnutils";

export enum RechargeToSideChainVersion {
  V0,
  V1
}

export type RechargeToSideChainInfo = {
  MerkleProof?: string;
  MainChainTransaction?: string;
  MainChainTxHash?: string;
};

export class RechargeToSideChain extends Payload {
  private _merkeProof: bytes_t;
  private _mainChainTransaction: bytes_t;
  private _mainChainTxHash: uint256;

  static newFromParams(
    merkeProof: bytes_t,
    mainChainTransaction: bytes_t,
    hash: uint256
  ) {
    const rechargeToSideChain = new RechargeToSideChain();
    rechargeToSideChain._merkeProof = merkeProof;
    rechargeToSideChain._mainChainTransaction = mainChainTransaction;
    rechargeToSideChain._mainChainTxHash = hash;
    return rechargeToSideChain;
  }

  static newFromRechargeToSideChain(payload: RechargeToSideChain) {
    const rechargeToSideChain = new RechargeToSideChain();
    rechargeToSideChain.copyRechargeToSideChain(payload);
    return rechargeToSideChain;
  }

  estimateSize(version: uint8_t): size_t {
    let size = 0;
    let stream = new ByteStream();

    if (version == RechargeToSideChainVersion.V0) {
      size += stream.writeVarUInt(this._merkeProof.length);
      size += this._merkeProof.length;
      size += stream.writeVarUInt(this._mainChainTransaction.length);
      size += this._mainChainTransaction.length;
    } else if (version == RechargeToSideChainVersion.V1) {
      size += sizeof_uint256_t();
    }

    return size;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    if (version == RechargeToSideChainVersion.V0) {
      ostream.writeVarBytes(this._merkeProof);
      ostream.writeVarBytes(this._mainChainTransaction);
    } else if (version == RechargeToSideChainVersion.V1) {
      ostream.writeBNAsUIntOfSize(this._mainChainTxHash, 32);
    } else {
      Log.error(
        "Serialize: invalid recharge to side chain payload version = {}",
        version
      );
    }
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    if (version == RechargeToSideChainVersion.V0) {
      let merkeProof: bytes_t;
      merkeProof = istream.readVarBytes(merkeProof);
      if (!merkeProof) {
        Log.error(
          "Deserialize: recharge to side chain payload read merkle proof"
        );
        return false;
      }
      this._merkeProof = merkeProof;

      let mainChainTransaction: bytes_t;
      mainChainTransaction = istream.readVarBytes(mainChainTransaction);
      if (!mainChainTransaction) {
        Log.error("Deserialize: recharge to side chain payload read tx");
        return false;
      }
      this._mainChainTransaction = mainChainTransaction;
    } else if (version == RechargeToSideChainVersion.V1) {
      let mainChainTxHash = istream.readUIntOfBytesAsBN(32);
      if (!mainChainTxHash) {
        Log.error("Deserialize: recharge to side chain payload read tx hash");
        return false;
      }
      this._mainChainTxHash = mainChainTxHash;
    } else {
      Log.error(
        "Deserialize: invalid recharge to side chain payload versin = {}",
        version
      );
      return false;
    }

    return true;
  }

  toJson(version: uint8_t): RechargeToSideChainInfo {
    let j = <RechargeToSideChainInfo>{};

    if (version == RechargeToSideChainVersion.V0) {
      j["MerkleProof"] = this._merkeProof.toString("hex");
      j["MainChainTransaction"] = this._mainChainTransaction.toString("hex");
    } else if (version == RechargeToSideChainVersion.V1) {
      j["MainChainTxHash"] = get32BytesOfBNAsHexString(this._mainChainTxHash);
    } else {
      Log.error(
        "toJson: invalid recharge to side chain payload version = {}",
        version
      );
    }

    return j;
  }

  fromJson(j: RechargeToSideChainInfo, version: uint8_t) {
    if (version == RechargeToSideChainVersion.V0) {
      this._merkeProof = Buffer.from(j["MerkleProof"], "hex");
      this._mainChainTransaction = Buffer.from(
        j["MainChainTransaction"],
        "hex"
      );
    } else if (version == RechargeToSideChainVersion.V1) {
      this._mainChainTxHash = new BigNumber(j["MainChainTxHash"], 16);
    } else {
      Log.error(
        "fromJson: invalid recharge to side chain payload version = {}",
        version
      );
    }
  }

  copyPayload(payload: Payload) {
    try {
      const payloadRecharge = payload as RechargeToSideChain;
      this.copyRechargeToSideChain(payloadRecharge);
    } catch (e) {
      Log.error("payload is not instance of RechargeToSideChain");
    }

    return this;
  }

  copyRechargeToSideChain(payload: RechargeToSideChain) {
    this._merkeProof = Buffer.alloc(payload._merkeProof.length);
    payload._merkeProof.copy(this._merkeProof);

    this._mainChainTransaction = Buffer.alloc(
      payload._mainChainTransaction.length
    );
    payload._mainChainTransaction.copy(this._mainChainTransaction);

    this._mainChainTxHash = payload._mainChainTxHash;

    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as RechargeToSideChain;

      if (version == RechargeToSideChainVersion.V0)
        return (
          this._merkeProof.equals(p._merkeProof) &&
          this._mainChainTransaction.equals(p._mainChainTransaction)
        );

      if (version == RechargeToSideChainVersion.V1)
        return this._mainChainTxHash.eq(p._mainChainTxHash);

      return false;
    } catch (e) {
      Log.error("payload is not instance of RechargeToSideChain");
    }

    return false;
  }
}
