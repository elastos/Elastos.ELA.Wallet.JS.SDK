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
import { sizeof_uint256_t, uint256, uint8_t, size_t } from "../../types";
import { Payload } from "./Payload";
import { Log } from "../../common/Log";

export type CancelVotesInfo = {
  ReferKeys: string[];
};

export class CancelVotes extends Payload {
  private _referKeys: uint256[];

  newFromParams(referKeys: uint256[]) {
    this._referKeys = referKeys;
  }

  estimateSize(version: uint8_t): size_t {
    let stream = new ByteStream();
    let size = 0;

    size += stream.writeVarUInt(this._referKeys.length);
    for (let h of this._referKeys) size += sizeof_uint256_t();

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    stream.writeVarUInt(this._referKeys.length);
    for (let h of this._referKeys) {
      // stream.WriteBytes(h);
      stream.writeBNAsUIntOfSize(h, 32);
    }
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    let size = stream.readVarUInt();

    if (!size) {
      Log.error("CancelVotes deserialize size");
      return false;
    }
    this._referKeys = [];
    for (let i = 0; i < size.toNumber(); ++i) {
      let h = stream.readUIntOfBytesAsBN(32);
      if (!h) {
        Log.error("CancelVotes deserialize referKeys[{}]", i);
        return false;
      }
      this._referKeys.push(h);
    }

    return true;
  }

  toJson(version: uint8_t): CancelVotesInfo {
    let j = <CancelVotesInfo>{};
    let tmp = [];
    for (let i = 0; i < this._referKeys.length; ++i) {
      tmp.push(this._referKeys[i].toString(16));
    }
    j["ReferKeys"] = tmp;
    return j;
  }

  fromJson(j: CancelVotesInfo, version: uint8_t) {
    this._referKeys = [];
    for (let i = 0; i < j["ReferKeys"].length; i++) {
      this._referKeys.push(new BigNumber(j["ReferKeys"][i]));
    }
  }

  isValid(version: uint8_t): boolean {
    return true;
  }

  copyFromPayload(payload: Payload) {
    try {
      const p = payload as CancelVotes;
      this.newFromCancelVotes(p);
    } catch (e) {
      Log.error("payload is not instance of CancelVotes");
    }

    return this;
  }

  newFromCancelVotes(payload: CancelVotes) {
    this._referKeys = payload._referKeys;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as CancelVotes;
      if (this._referKeys.length != p._referKeys.length) {
        return false;
      }

      for (let i = 0; i < this._referKeys.length; ++i) {
        if (!this._referKeys[i].eq(p._referKeys[i])) return false;
      }
    } catch (e) {
      Log.error("payload is not instance of CancelVotes");
      return false;
    }

    return true;
  }
}
