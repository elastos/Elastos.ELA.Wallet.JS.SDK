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
import { uint168 } from "../../common/uint168";
import {
  bytes_t,
  uint64_t,
  uint8_t,
  size_t,
  sizeof_uint32_t,
  sizeof_uint8_t,
  uint256
} from "../../types";
import { Address } from "../../walletcore/Address";
import { Payload } from "./Payload";

export type UnstakeRealWithdrawInfo = {
  RetVotesTxHash: string;
  StakeAddress: string;
  Value: string;
};

export class UnstakeRealWithdraw extends Payload {
  private _retVotesTxHash: uint256;
  private _stakeAddress: uint168;
  private _value: uint64_t;

  static newFromParams(
    retVotesTxHash: uint256,
    stakeAddress: uint168,
    value: uint64_t
  ) {
    let unstakeRealWithdraw = new UnstakeRealWithdraw();
    unstakeRealWithdraw._retVotesTxHash = retVotesTxHash;
    unstakeRealWithdraw._stakeAddress = stakeAddress;
    unstakeRealWithdraw._value = value;
    return unstakeRealWithdraw;
  }

  estimateSize(version: uint8_t): size_t {
    let size = 0;
    size += sizeof_uint32_t();
    size += this._stakeAddress.bytes().length;
    size += sizeof_uint8_t();
    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    // stream.writeBytes(_retVotesTxHash);
    stream.writeBNAsUIntOfSize(this._retVotesTxHash, 32);
    stream.writeBytes(this._stakeAddress.bytes());
    stream.writeBNAsUIntOfSize(this._value, 8);
  }

  deserialize(stream: ByteStream, version: uint8_t) {
    this._retVotesTxHash = stream.readUIntOfBytesAsBN(32);
    if (!this._retVotesTxHash) {
      Log.error("UnstakeRealWithdraw deserialize retVotesTXHash");
      return false;
    }

    let stakeAddress: bytes_t;
    stakeAddress = stream.readBytes(stakeAddress, 21);
    if (!stakeAddress) {
      Log.error("UnstakeRealWithdraw deserialize stakeAddress");
      return false;
    }
    this._stakeAddress = uint168.newFrom21BytesBuffer(stakeAddress);

    this._value = stream.readUIntOfBytesAsBN(8);
    if (!this._value) {
      Log.error("UnstakeRealWithdraw deserialize value");
      return false;
    }

    return true;
  }

  toJson(version: uint8_t): UnstakeRealWithdrawInfo {
    let j = <UnstakeRealWithdrawInfo>{};

    j["RetVotesTxHash"] = this._retVotesTxHash.toString(16);
    j["StakeAddress"] = Address.newFromProgramHash(this._stakeAddress).string();
    j["Value"] = this._value.toString();
    return j;
  }

  fromJson(j: UnstakeRealWithdrawInfo, version: uint8_t) {
    this._retVotesTxHash = new BigNumber(j["RetVotesTxHash"], 16);
    this._stakeAddress = Address.newFromAddressString(
      j["StakeAddress"]
    ).programHash();
    this._value = new BigNumber(j["Value"]);
  }

  isValid(version: uint8_t): boolean {
    return true;
  }

  copyFromPayload(payload: Payload) {
    try {
      const p = payload as UnstakeRealWithdraw;
      this.newFromUnstakeRealWithdraw(p);
    } catch (e) {
      Log.error("payload is not instance of UnstakeRealWithdraw");
    }

    return this;
  }

  newFromUnstakeRealWithdraw(payload: UnstakeRealWithdraw) {
    this._retVotesTxHash = payload._retVotesTxHash;
    this._stakeAddress = payload._stakeAddress;
    this._value = payload._value;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as UnstakeRealWithdraw;
      return (
        this._retVotesTxHash.eq(p._retVotesTxHash) &&
        this._stakeAddress.bytes().equals(p._stakeAddress.bytes()) &&
        this._value.eq(p._value)
      );
    } catch (e) {
      Log.error("payload is not instance of UnstakeRealWithdraw");
    }

    return false;
  }
}
