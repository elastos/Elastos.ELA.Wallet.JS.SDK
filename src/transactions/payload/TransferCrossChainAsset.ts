// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { Log } from "../../common/Log";
import { Address } from "../../walletcore/Address";
import BigNumber from "bignumber.js";
import { uint16_t, uint8_t, size_t, sizeof_uint64_t } from "../../types";
import { ByteStream } from "../../common/bytestream";
import { Payload } from "./Payload";

export const TransferCrossChainVersion = 0x00;
export const TransferCrossChainVersionV1 = 0x01;

export type TransferInfoJson = {
  CrossChainAddress?: string;
  OutputIndex?: number;
  CrossChainAmount?: string;
};

export class TransferInfo {
  private _crossChainAddress: string;
  private _outputIndex: uint16_t;
  private _crossChainAmount: BigNumber;

  constructor() {
    this._crossChainAddress = "";
    this._outputIndex = 0;
    this._crossChainAmount = new BigNumber(0);
  }

  static newFromParams(address: string, index: uint16_t, amount: BigNumber) {
    const info = new TransferInfo();
    info._crossChainAddress = address;
    info._outputIndex = index;
    info._crossChainAmount = amount;
    return info;
  }

  setCrossChainAddress(address: string) {
    this._crossChainAddress = address;
  }

  getCrossChainAddress(): string {
    return this._crossChainAddress;
  }

  setOutputIndex(index: uint16_t) {
    this._outputIndex = index;
  }

  getOutputIndex(): uint16_t {
    return this._outputIndex;
  }

  setCrossChainAmount(amount: BigNumber) {
    this._crossChainAmount = amount;
  }

  getCrossChainAmount(): BigNumber {
    return this._crossChainAmount;
  }

  toJson(version: uint8_t): TransferInfoJson {
    let j = <TransferInfoJson>{};

    if (version == TransferCrossChainVersion) {
      j["CrossChainAddress"] = this._crossChainAddress;
      j["OutputIndex"] = this._outputIndex;
      j["CrossChainAmount"] = this._crossChainAmount.toString();
    } else if (version == TransferCrossChainVersionV1) {
    }

    return j;
  }

  fromJson(j: TransferInfoJson, version: uint8_t) {
    if (version == TransferCrossChainVersion) {
      this._crossChainAddress = j["CrossChainAddress"];
      this._outputIndex = j["OutputIndex"];
      this._crossChainAmount = new BigNumber(j["CrossChainAmount"]);
    } else if (version == TransferCrossChainVersionV1) {
    }
  }

  equals(info: TransferInfo): boolean {
    return (
      this._crossChainAddress == info._crossChainAddress &&
      this._outputIndex == info._outputIndex &&
      this._crossChainAmount.eq(info._crossChainAmount)
    );
  }
}

export class TransferCrossChainAsset extends Payload {
  private _info: TransferInfo[];

  static newFromTransferCrossChainAsset() {
    const transferCrossChainAsset = new TransferCrossChainAsset();
    transferCrossChainAsset.copyTransferCrossChainAsset(
      transferCrossChainAsset
    );
    return transferCrossChainAsset;
  }

  static newFromParams(info: TransferInfo[]) {
    const transferCrossChainAsset = new TransferCrossChainAsset();
    transferCrossChainAsset._info = info;
    return transferCrossChainAsset;
  }

  isValid(version: uint8_t): boolean {
    if (version == TransferCrossChainVersion) {
      if (this._info.length === 0) return false;

      for (let i = 0; i < this._info.length; ++i) {
        let addr = Address.newFromAddressString(
          this._info[i].getCrossChainAddress()
        );
        if (!addr.valid()) return false;

        if (this._info[i].getCrossChainAmount().isZero()) return false;
      }
    } else if (version == TransferCrossChainVersionV1) {
    }

    return true;
  }

  info(): TransferInfo[] {
    return this._info;
  }

  estimateSize(version: uint8_t): size_t {
    let size: size_t = 0;
    if (version == TransferCrossChainVersion) {
      let stream = new ByteStream();

      size += stream.writeVarUInt(this._info.length);
      for (let i = 0; i < this._info.length; ++i) {
        size += stream.writeVarUInt(
          this._info[i].getCrossChainAddress().length
        );
        size += this._info[i].getCrossChainAddress().length;
        size += stream.writeVarUInt(this._info[i].getOutputIndex());
        size += sizeof_uint64_t();
      }
    } else if (version == TransferCrossChainVersionV1) {
    }

    return size;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    if (version == TransferCrossChainVersion) {
      // size_t len = _info.size();
      // ostream.WriteVarUint((uint64_t) len);
      ostream.writeVarUInt(this._info.length);
      for (let i = 0; i < this._info.length; ++i) {
        ostream.writeVarString(this._info[i].getCrossChainAddress());
        ostream.writeVarUInt(this._info[i].getOutputIndex());
        // ostream.WriteUint64(_info[i]._crossChainAmount.getUint64());
        ostream.writeBNAsUIntOfSize(this._info[i].getCrossChainAmount(), 8);
      }
    } else if (version == TransferCrossChainVersionV1) {
    }
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    if (version == TransferCrossChainVersion) {
      let len = istream.readVarUInt();
      if (!len) {
        Log.error("Payload transfer cross chain asset deserialize fail");
        return false;
      }

      this._info = [];
      for (let i = 0; i < len.toNumber(); ++i) {
        let info = new TransferInfo();
        let address = istream.readVarString();
        if (!address) {
          Log.error(
            "Payload transfer cross chain asset deserialize cross chain address fail"
          );
          return false;
        }
        info.setCrossChainAddress(address);

        let index = istream.readVarUInt();
        if (!index) {
          Log.error(
            "Payload transfer cross chain asset deserialize output index fail"
          );
          return false;
        }
        info.setOutputIndex(index.toNumber());

        let amount = istream.readUIntOfBytesAsBN(8);
        if (!amount) {
          Log.error(
            "Payload transfer cross chain asset deserialize cross chain amount fail"
          );
          return false;
        }
        info.setCrossChainAmount(amount);

        this._info.push(info);
      }
    } else if (version == TransferCrossChainVersionV1) {
    }

    return true;
  }

  toJson(version: uint8_t): TransferInfoJson[] {
    let j: TransferInfoJson[] = [];

    if (version == TransferCrossChainVersion) {
      for (let i = 0; i < this._info.length; ++i) {
        j.push(this._info[i].toJson(version));
      }
    } else if (version == TransferCrossChainVersionV1) {
    }

    return j;
  }

  fromJson(j: TransferInfoJson[], version: uint8_t) {
    if (version == TransferCrossChainVersion) {
      if (!Array.isArray(j)) {
        Log.error("cross chain info json should be an array");
        return;
      }

      for (let i = 0; i < j.length; ++i) {
        let info = new TransferInfo();
        info.fromJson(j[i], version);
        this._info.push(info);
      }
    } else if (version == TransferCrossChainVersionV1) {
    }
  }

  copyTransferCrossChainAsset(payload: TransferCrossChainAsset) {
    try {
      this._info = payload._info;
    } catch (e) {
      Log.error("payload is not instance of TransferCrossChainAsset");
    }

    return this;
  }

  private isEqualTransferInfos(infos: TransferInfo[]): boolean {
    if (this._info.length !== infos.length) {
      return false;
    }

    let equal = false;
    for (let i = 0; i < infos.length; ++i) {
      for (let j = 0; j < this._info.length; ++j) {
        if (this._info[j].equals(infos[i])) {
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
    return equal;
  }

  equals(payload: TransferCrossChainAsset, version: uint8_t): boolean {
    try {
      if (version == TransferCrossChainVersion) {
        return this.isEqualTransferInfos(payload._info);
      } else if (version == TransferCrossChainVersionV1) {
        return true;
      }
    } catch (e) {
      Log.error("payload is not instance of TransferCrossChainAsset");
    }

    return false;
  }
}
