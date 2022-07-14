// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { Buffer } from "buffer";
import { bytes_t, size_t, uint8_t } from "../../types";
import { ByteStream } from "../../common/bytestream";
import { Payload } from "./Payload";
import { Log } from "../../common/Log";

export type CoinBaseInfo = { CoinBaseData: string };

export class CoinBase extends Payload {
  private _coinBaseData: bytes_t;

  static newFromParams(coinBaseData: bytes_t) {
    let coinBase = new CoinBase();
    coinBase._coinBaseData = coinBaseData;
    return coinBase;
  }

  static newFromCoinBase(payload: CoinBase) {
    let coinBase = new CoinBase();
    return coinBase.copyCoinbase(payload);
  }

  setCoinBaseData(coinBaseData: bytes_t) {
    this._coinBaseData = coinBaseData;
  }

  getCoinBaseData(): bytes_t {
    return this._coinBaseData;
  }

  public estimateSize(version: uint8_t): size_t {
    let size = 0;
    let stream = new ByteStream();

    size += stream.writeVarUInt(this._coinBaseData.length);
    size += this._coinBaseData.length;

    return size;
  }

  public serialize(ostream: ByteStream, version: uint8_t) {
    ostream.writeVarBytes(this._coinBaseData);
  }

  public deserialize(istream: ByteStream, version: uint8_t): boolean {
    this._coinBaseData = istream.readVarBytes(this._coinBaseData);
    return !!this._coinBaseData;
  }

  public toJson(version: uint8_t): CoinBaseInfo {
    return {
      CoinBaseData: this._coinBaseData.toString("hex")
    };
  }

  public fromJson(j: CoinBaseInfo, version: uint8_t) {
    this._coinBaseData = Buffer.from(j["CoinBaseData"], "hex");
  }

  public copyPayload(payload: Payload) {
    try {
      const payloadCoinBase = payload as CoinBase;
      this.copyCoinbase(payloadCoinBase);
    } catch (e) {
      Log.error("payload is not instance of CoinBase");
    }

    return this;
  }

  public copyCoinbase(payload: CoinBase): CoinBase {
    this._coinBaseData = payload._coinBaseData;
    return this;
  }

  public equals(payload: Payload, version: uint8_t): boolean {
    if (!(payload instanceof CoinBase)) return false;

    return this._coinBaseData.equals(payload._coinBaseData);
  }
}
