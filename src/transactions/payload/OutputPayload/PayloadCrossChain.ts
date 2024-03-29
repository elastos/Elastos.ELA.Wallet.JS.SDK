/*
 * Copyright (c) 2022 Elastos Foundation
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
import { Buffer } from "buffer";
import { Log } from "../../../common/Log";
import { OutputPayload } from "./OutputPayload";
import {
  size_t,
  uint8_t,
  bytes_t,
  sizeof_uint8_t,
  sizeof_uint64_t
} from "../../../types";
import { ByteStream } from "../../../common/bytestream";
import BigNumber from "bignumber.js";

export const CrossChainOutputVersion = 0x0;

export type PayloadCrossChainInfo = {
  Version: number;
  TargetAddress: string;
  TargetAmount: string;
  TargetData: string;
};

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
    return payloadCrossChain;
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
    let targetAddress = Buffer.from(this._targetAddress, "utf8");
    size += stream.writeVarUInt(targetAddress.length);
    size += targetAddress.length;
    size += sizeof_uint64_t();
    size += stream.writeVarUInt(this._targetData.length);
    size += this._targetData.length;

    return size;
  }

  serialize(stream: ByteStream) {
    stream.writeUInt8(this._version);
    stream.writeVarString(this._targetAddress);
    stream.writeBNAsUIntOfSize(this._targetAmount, 8);
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

    let amount = stream.readUIntOfBytesAsBN(8);
    if (!amount) {
      Log.error("deser op amount");
      return false;
    }
    this._targetAmount = amount;

    let targetData: bytes_t;
    targetData = stream.readVarBytes(targetData);

    if (!targetData) {
      Log.error("deser op data");
      return false;
    }
    this._targetData = targetData;
    return true;
  }

  toJson(): PayloadCrossChainInfo {
    let j = <PayloadCrossChainInfo>{};
    j["Version"] = this._version;
    j["TargetAddress"] = this._targetAddress;
    j["TargetAmount"] = this._targetAmount.toString();
    j["TargetData"] = this._targetData.toString("hex");
    return j;
  }

  fromJson(j: PayloadCrossChainInfo) {
    this._version = j["Version"];
    this._targetAddress = j["TargetAddress"];
    this._targetAmount = new BigNumber(j["TargetAmount"]);
    this._targetData = Buffer.from(j["TargetData"], "hex");
  }

  public copyOutputPayload(payload: OutputPayload) {
    try {
      const payloadCrossChain = payload as PayloadCrossChain;
      this.copyPayloadCrossChain(payloadCrossChain);
    } catch (e) {
      Log.error("payload is not instance of PayloadVote");
    }

    return this;
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
        this._targetAmount.eq(p._targetAmount) &&
        this._targetData.equals(p._targetData)
      );
    } catch (error) {
      Log.error("payload is not instance of PayloadCrossChain");
    }

    return false;
  }
}
