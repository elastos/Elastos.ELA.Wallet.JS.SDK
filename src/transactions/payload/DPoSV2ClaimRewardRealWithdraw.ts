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

import { ByteStream } from "../../common/bytestream";
import { uint256, uint8_t, size_t, sizeof_uint256_t } from "../../types";
import { Payload } from "./Payload";
import { Log } from "../../common/Log";
import BigNumber from "bignumber.js";
import { get32BytesOfBNAsHexString } from "../../common/bnutils";

export type DPoSV2ClaimRewardRealWithdrawInfo = {
  WithdrawTxHashes: string[];
};

export class DPoSV2ClaimRewardRealWithdraw extends Payload {
  private _withdrawTxHashes: uint256[];

  newFromParams(withdrawTxHashes: uint256[]) {
    this._withdrawTxHashes = withdrawTxHashes;
  }

  estimateSize(version: uint8_t): size_t {
    let stream = new ByteStream();
    let size = 0;

    size += stream.writeVarUInt(this._withdrawTxHashes.length);
    for (let i = 0; i < this._withdrawTxHashes.length; ++i)
      size += sizeof_uint256_t();

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    stream.writeVarUInt(this._withdrawTxHashes.length);
    for (let hash of this._withdrawTxHashes) {
      // stream.writeBytes(hash);
      stream.writeBNAsUIntOfSize(hash, 32);
    }
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    let size = stream.readVarUInt();
    if (!size) {
      Log.error("DPoSV2ClaimRewardRealWithdraw deserialize size");
      return false;
    }

    this._withdrawTxHashes = [];
    for (let i = 0; i < size.toNumber(); ++i) {
      this._withdrawTxHashes[i] = stream.readUIntOfBytesAsBN(32);
      if (!this._withdrawTxHashes[i]) {
        Log.error("DPoSV2ClaimRewardRealWithdraw deserialize hash[{}]", i);
        return false;
      }
    }

    return true;
  }

  toJson(version: uint8_t) {
    let hashes = [];
    let j = <DPoSV2ClaimRewardRealWithdrawInfo>{};
    for (let hash of this._withdrawTxHashes) {
      hashes.push(get32BytesOfBNAsHexString(hash));
    }
    j["WithdrawTxHashes"] = hashes;
    return j;
  }

  fromJson(j: DPoSV2ClaimRewardRealWithdrawInfo, version: uint8_t) {
    let hashes = j["WithdrawTxHashes"];

    this._withdrawTxHashes = [];
    for (let i = 0; i < hashes.length; ++i) {
      this._withdrawTxHashes.push(new BigNumber(hashes[i], 16));
    }
  }

  isValid(version: uint8_t): boolean {
    return true;
  }

  copyPayload(payload: Payload) {
    try {
      let p = payload as DPoSV2ClaimRewardRealWithdraw;
      this.copyDPoSV2ClaimRewardRealWithdraw(p);
    } catch (e) {
      Log.error("payload is not instance of DPoSV2ClaimRewardRealWithdraw");
    }

    return this;
  }

  copyDPoSV2ClaimRewardRealWithdraw(payload: DPoSV2ClaimRewardRealWithdraw) {
    this._withdrawTxHashes = payload._withdrawTxHashes;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      let p = payload as DPoSV2ClaimRewardRealWithdraw;
      return this._withdrawTxHashes == p._withdrawTxHashes;
    } catch (e) {
      Log.error("payload is not instance of DPoSV2ClaimRewardRealWithdraw");
    }
    return false;
  }
}
