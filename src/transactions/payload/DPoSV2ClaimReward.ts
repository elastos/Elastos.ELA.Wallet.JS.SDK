/*
 * Copyright (c) 2022 Elastos Foundation LTD.
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

import { BigNumber } from "bignumber.js";
import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";
import {
  bytes_t,
  uint64_t,
  uint8_t,
  size_t,
  sizeof_uint64_t
} from "../../types";
import { SHA256 } from "../../walletcore/sha256";
import { Payload } from "./Payload";

export const DPoSV2ClaimRewardVersion = 0;
export type DPoSV2ClaimRewardInfo = { Amount: string; Signature?: string };

export class DPoSV2ClaimReward extends Payload {
  private _amount: uint64_t;
  private _signature: bytes_t;

  static newFromParams(amount: uint64_t, signature: bytes_t) {
    let claimReward = new DPoSV2ClaimReward();
    claimReward._amount = amount;
    claimReward._signature = signature;
    return claimReward;
  }

  serializeUnsigned(stream: ByteStream, version: uint8_t) {
    stream.writeBNAsUIntOfSize(this._amount, 8);
  }

  deserializeUnsigned(stream: ByteStream, version: uint8_t): boolean {
    let amount = stream.readUIntOfBytesAsBN(8);
    if (!amount) {
      Log.error("DPoSV2ClaimReward deserialize unsigned amount");
      return false;
    }
    this._amount = amount;

    return true;
  }

  toJsonUnsigned(version: uint8_t) {
    let j = <DPoSV2ClaimRewardInfo>{};
    j["Amount"] = this._amount.toString();
    return j;
  }

  fromJsonUnsigned(j: DPoSV2ClaimRewardInfo, version: uint8_t) {
    this._amount = new BigNumber(j["Amount"]);
  }

  digestDPoSV2ClaimReward(version: uint8_t): string {
    let stream = new ByteStream();
    this.serializeUnsigned(stream, version);
    return SHA256.encodeToBuffer(stream.getBytes()).toString("hex");
  }

  estimateSize(version: uint8_t): size_t {
    let size = 0;
    let stream = new ByteStream();

    size += sizeof_uint64_t();
    size += stream.writeVarUInt(this._signature.length);
    size += this._signature.length;

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    this.serializeUnsigned(stream, version);

    stream.writeVarBytes(this._signature);
  }

  deserialize(stream: ByteStream, version: uint8_t) {
    if (!this.deserializeUnsigned(stream, version)) {
      Log.error("deserialize unsigned");
      return false;
    }

    let signature: bytes_t;
    signature = stream.readVarBytes(signature);
    if (!signature) {
      Log.error("DPoSV2ClaimReward deserialize signature");
      return false;
    }
    this._signature = signature;

    return true;
  }

  toJson(version: uint8_t): DPoSV2ClaimRewardInfo {
    let j = this.toJsonUnsigned(version);
    j["Signature"] = this._signature.toString("hex");
    return j;
  }

  fromJson(j: DPoSV2ClaimRewardInfo, version: uint8_t) {
    this.fromJsonUnsigned(j, version);
    this._signature = Buffer.from(j["Signature"], "hex");
  }

  isValid(version: uint8_t): boolean {
    return true;
  }

  copyPayload(payload: Payload) {
    try {
      const p = payload as DPoSV2ClaimReward;
      this.copyDPoSV2ClaimReward(p);
    } catch (e) {
      Log.error("payload is not instance of DPoSV2ClaimReward");
    }

    return this;
  }

  copyDPoSV2ClaimReward(payload: DPoSV2ClaimReward) {
    this._amount = payload._amount;
    this._signature = payload._signature;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as DPoSV2ClaimReward;
      return this._amount.eq(p._amount) && this._signature.equals(p._signature);
    } catch (e) {
      Log.error("payload is not instance of DPoSV2ClaimReward");
    }

    return false;
  }
}
