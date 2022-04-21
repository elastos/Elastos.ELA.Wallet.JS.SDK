// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { json, size_t, uint8_t, uint64_t, bytes_t } from "../../types";
import { Payload } from "./Payload";
import { Log } from "../../common/Log";
import { Asset, MaxPrecision } from "../Asset";
import { uint168 } from "../../common/uint168";
import { ByteStream } from "../../common/bytestream";
import BigNumber from "bignumber.js";

export class RegisterAsset extends Payload {
  private _asset: Asset;
  private _amount: uint64_t;
  private _controller: uint168;

  constructor() {
    super();
    this._amount = new BigNumber(0);
    this._asset = new Asset();
  }

  newFromParams(asset: Asset, amount: uint64_t, controller: uint168) {
    this._amount = amount;
    this._asset = asset;
    this._controller = controller;
  }

  newFromRegisterAsset(payload: RegisterAsset) {
    this.copyRegisterAsset(payload);
  }

  isValid(version: uint8_t): boolean {
    return this._asset.getPrecision() <= MaxPrecision;
  }

  estimateSize(version: uint8_t): size_t {
    let size: size_t = 0;

    size += this._asset.estimateSize();
    size += 8;
    size += this._controller.bytes().length;

    return size;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    this._asset.serialize(ostream);
    ostream.writeBigNumber(this._amount);
    ostream.writeBytes(this._controller.bytes());
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    if (!this._asset.deserialize(istream)) {
      Log.error("Payload register asset deserialize asset fail");
      return false;
    }
    this._amount = istream.readUIntOfBytesAsBN(8);
    if (!this._amount) {
      Log.error("Payload register asset deserialize amount fail");
      return false;
    }
    let controller: bytes_t;
    controller = istream.readBytes(controller, 21);
    if (!controller) {
      Log.error("Payload register asset deserialize controller fail");
      return false;
    }
    this._controller = uint168.newFrom21BytesBuffer(controller);
    return true;
  }

  toJson(version: uint8_t): json {
    let j: json = {};

    j["Asset"] = this._asset.toJson();
    j["Amount"] = this._amount.toString();
    j["Controller"] = this._controller.bytes().toString("hex");

    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._asset.fromJson(j["Asset"] as json);
    this._amount = new BigNumber(j["Amount"] as string);
    let buffer = Buffer.from(j["Controller"] as string, "hex");
    this._controller = uint168.newFrom21BytesBuffer(buffer);
  }

  copyPayload(payload: Payload) {
    try {
      const payloadRegisterAsset = payload as RegisterAsset;
      this.copyRegisterAsset(payloadRegisterAsset);
    } catch (e) {
      Log.error("payload is not instance of RegisterAsset");
    }

    return this;
  }

  copyRegisterAsset(payload: RegisterAsset) {
    this._asset = payload._asset;
    this._amount = payload._amount;
    this._controller = payload._controller;

    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as RegisterAsset;
      return (
        this._asset == p._asset &&
        this._amount == p._amount &&
        this._controller == p._controller
      );
    } catch (e) {
      Log.error("payload is not instance of RegisterAsset");
    }

    return false;
  }
}
