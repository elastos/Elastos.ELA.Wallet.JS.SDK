/*
 * Copyright (c) 2021 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import { Log } from "../../../common/Log";
import { OutputPayload } from "./OutputPayload";
import {
  size_t,
  uint8_t,
  bytes_t,
  sizeof_uint8_t,
  sizeof_uint64_t,
  json
} from "../../../types";
import { ByteStream } from "../../../common/bytestream";
import BigNumber from "bignumber.js";

export class PayloadCrossChain extends OutputPayload {
  private _version: uint8_t;
  private _targetAddress: string;
  private _targetAmount: BigNumber;
  private _targetData: bytes_t;

  constructor() {
    super();
  }

  public static newFromParams(
    version: uint8_t,
    addr: string,
    amount: BigNumber,
    data: bytes_t
  ) {
    let payloadCrossChain = new PayloadCrossChain();
    payloadCrossChain._version = version;
    payloadCrossChain._targetAddress = addr;
    payloadCrossChain._targetAmount = amount;
    payloadCrossChain._targetData = data;
  }

  version(): uint8_t {
    return this._version;
  }

  targetAddress(): string {
    return this._targetAddress;
  }

  targetAmount(): BigNumber {
    return this._targetAmount;
  }

  targetData(): bytes_t {
    return this._targetData;
  }

  estimateSize(): size_t {
    let size: size_t = 0;
    let stream = new ByteStream();

    size += sizeof_uint8_t();
    size += stream.writeVarUInt(this._targetAddress.length);
    size += this._targetAddress.length;
    size += sizeof_uint64_t();
    size += stream.writeVarUInt(this._targetData.length);
    size += this._targetData.length;

    return size;
  }

  serialize(stream: ByteStream) {
    stream.writeUInt8(this._version);
    stream.writeVarString(this._targetAddress);
    stream.writeBigNumber(this._targetAmount);
    stream.writeVarBytes(this._targetData);
  }

  deserialize(stream: ByteStream): boolean {
    this._version = stream.readUInt8();
    if (this._version === null) {
      Log.error("deser op version");
      return false;
    }

    this._targetAddress = stream.readVarString();
    if (!this._targetAddress) {
      Log.error("deser op address");
      return false;
    }

    // not sure
    let amount = stream.readUInt64();
    if (!amount) {
      Log.error("deser op amount");
      return false;
    }
    this._targetAmount = new BigNumber(amount);

    if (!stream.readVarBytes(this._targetData)) {
      Log.error("deser op data");
      return false;
    }

    return true;
  }

  toJson() {
    let j: json;
    j["Version"] = this._version;
    j["TargetAddress"] = this._targetAddress;
    j["TargetAmount"] = this._targetAmount.toNumber();
    j["TargetData"] = this._targetData.toString("hex");
    return j;
  }

  fromJson(j: json) {
    this._version = j["Version"] as uint8_t;
    this._targetAddress = j["TargetAddress"] as string;
    this._targetAmount = new BigNumber(j["TargetAmount"] as number);
    this._targetData = Buffer.from(j["TargetData"] as string, "hex");
  }

  copyPayloadCrossChain(payload: PayloadCrossChain) {
    try {
      this._version = payload._version;
      this._targetAddress = payload._targetAddress;
      this._targetAmount = payload._targetAmount;
      this._targetData = payload._targetData;
      return this;
    } catch (err) {
      Log.error("payload is not instance of PayloadCrossChain");
    }
  }

  equals(payload: PayloadCrossChain): boolean {
    try {
      const p = payload;
      return (
        this._version == p._version &&
        this._targetAddress == p._targetAddress &&
        this._targetAmount.isEqualTo(p._targetAmount) &&
        this._targetData.toString() == p._targetData.toString()
      );
    } catch (error) {
      Log.error("payload is not instance of PayloadCrossChain");
    }

    return false;
  }
}
