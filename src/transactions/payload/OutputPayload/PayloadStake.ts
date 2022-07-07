// Copyright (c) 2017-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { ByteStream } from "../../../common/bytestream";
import { bytes_t, size_t, uint8_t } from "../../../types";
import { Log } from "../../../common/Log";
import { uint168 } from "../../../common/uint168";
import { sizeof_uint8_t } from "../../../types";
import { Address } from "../../../walletcore/Address";
import { OutputPayload } from "./OutputPayload";

export type PayloadStakeInfo = { Version: number; StakeAddress: string };

export class PayloadStake extends OutputPayload {
  private _version: uint8_t;
  private _stakeAddress: uint168; // address of stake owner，begin with 'S'

  static newFromParams(version: uint8_t, stakeAddress: uint168) {
    let payloadStake = new PayloadStake();
    payloadStake._version = version;
    payloadStake._stakeAddress = stakeAddress;
    return payloadStake;
  }

  estimateSize(): size_t {
    let size = 0;

    size += sizeof_uint8_t();
    size += this._stakeAddress.bytes().length;

    return size;
  }

  serialize(stream: ByteStream) {
    stream.writeUInt8(this._version);
    stream.writeBytes(this._stakeAddress.bytes());
  }

  deserialize(stream: ByteStream): boolean {
    this._version = stream.readUInt8();
    if (!this._version) {
      Log.error("output payload stake deserialize version");
      return false;
    }

    let bytes: bytes_t;
    bytes = stream.readBytes(bytes, 21);
    if (!bytes) {
      Log.error("output payload stake deserialize stake address");
      return false;
    }
    this._stakeAddress = uint168.newFrom21BytesBuffer(bytes);

    return true;
  }

  toJson(): PayloadStakeInfo {
    let j = <PayloadStakeInfo>{};

    j["Version"] = this._version;
    j["StakeAddress"] = Address.newFromProgramHash(this._stakeAddress).string();

    return j;
  }

  fromJson(j: PayloadStakeInfo) {
    this._version = j["Version"];

    let addr = j["StakeAddress"];
    this._stakeAddress = Address.newFromAddressString(addr).programHash();
  }

  copyFromOutputPayload(payload: OutputPayload) {
    try {
      let p = payload as PayloadStake;
      this.newFromPayloadStake(p);
    } catch (e) {
      Log.error("payload is not instance of PayloadStake");
    }

    return this;
  }

  newFromPayloadStake(payload: PayloadStake) {
    this._version = payload._version;
    this._stakeAddress = payload._stakeAddress;

    return this;
  }

  equals(payload: OutputPayload): boolean {
    try {
      let p = payload as PayloadStake;
      return (
        this._version == p._version &&
        this._stakeAddress.bytes().equals(p._stakeAddress.bytes())
      );
    } catch (e) {
      Log.error("payload is not instance of PayloadStake");
    }

    return false;
  }
}
