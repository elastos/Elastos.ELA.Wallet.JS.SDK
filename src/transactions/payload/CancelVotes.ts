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
import { get32BytesOfBNAsHexString } from "../../common/bnutils";

export type CancelVotesInfo = {
  ReferKeys: string[];
};

export class CancelVotes extends Payload {
  private _referKeys: uint256[];

  static newFromParams(referKeys: uint256[]) {
    let cancelVotes = new CancelVotes();
    cancelVotes._referKeys = referKeys;
    return cancelVotes;
  }

  estimateSize(version: uint8_t): size_t {
    let stream = new ByteStream();
    let size = 0;

    size += stream.writeVarUInt(this._referKeys.length);
    for (let i = 0; i < this._referKeys.length; i++) {
      size += sizeof_uint256_t();
    }

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
    if (!size || (size && size.isZero())) {
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
      tmp.push(get32BytesOfBNAsHexString(this._referKeys[i]));
    }
    j["ReferKeys"] = tmp;
    return j;
  }

  fromJson(j: CancelVotesInfo, version: uint8_t) {
    this._referKeys = [];
    for (let i = 0; i < j["ReferKeys"].length; i++) {
      this._referKeys.push(new BigNumber(j["ReferKeys"][i], 16));
    }
  }

  isValid(version: uint8_t): boolean {
    return true;
  }

  copyPayload(payload: Payload) {
    try {
      const p = payload as CancelVotes;
      this.copyCancelVotes(p);
    } catch (e) {
      Log.error("payload is not instance of CancelVotes");
    }

    return this;
  }

  copyCancelVotes(payload: CancelVotes) {
    this._referKeys = payload._referKeys;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as CancelVotes;
      if (this._referKeys.length != p._referKeys.length) {
        return false;
      }
      let equal = false;
      for (let i = 0; i < this._referKeys.length; ++i) {
        for (let j = 0; j < p._referKeys.length; ++j) {
          if (this._referKeys[j].eq(p._referKeys[i])) {
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
    } catch (e) {
      Log.error("payload is not instance of CancelVotes");
      return false;
    }

    return true;
  }
}
