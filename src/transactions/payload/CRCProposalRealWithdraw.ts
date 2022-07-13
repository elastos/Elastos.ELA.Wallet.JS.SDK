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
import BigNumber from "bignumber.js";
import { get32BytesOfBNAsHexString } from "../../common/bnutils";
import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";
import { size_t, uint8_t, uint256, sizeof_uint16_t } from "../../types";
import { Payload } from "./Payload";

export type CRCProposalRealWithdrawInfo = { WithdrawTxHashes: string[] };

export class CRCProposalRealWithdraw extends Payload {
  private _withdrawTxHashes: uint256[];

  estimateSize(version: uint8_t): size_t {
    let stream = new ByteStream();
    let size = 0;

    size += sizeof_uint16_t();

    size += stream.writeVarUInt(this._withdrawTxHashes.length);
    size += this._withdrawTxHashes.length * 32;

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    stream.writeVarUInt(this._withdrawTxHashes.length);
    for (let i = 0; i < this._withdrawTxHashes.length; ++i) {
      stream.writeBNAsUIntOfSize(this._withdrawTxHashes[i], 32);
    }
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    let size = stream.readVarUInt();
    if (!size) {
      Log.error("deserialize proposal real withdraw size");
      return false;
    }

    let hash: uint256;
    for (let i = 0; i < size.toNumber(); ++i) {
      hash = stream.readUIntOfBytesAsBN(32);
      if (!hash) {
        Log.error("deserialize proposal real withdraw hash");
        return false;
      }
      this._withdrawTxHashes.push(hash);
    }

    return true;
  }

  toJson(version: uint8_t): CRCProposalRealWithdrawInfo {
    let jarray = [];
    let j = <CRCProposalRealWithdrawInfo>{};

    for (let u of this._withdrawTxHashes) {
      jarray.push(get32BytesOfBNAsHexString(u));
    }

    j["WithdrawTxHashes"] = jarray;
    return j;
  }

  fromJson(j: CRCProposalRealWithdrawInfo, version: uint8_t) {
    let jarray = j["WithdrawTxHashes"];
    if (!Array.isArray(jarray)) {
      Log.error("json is not array");
      return;
    }
    for (let i = 0; i < jarray.length; ++i) {
      this._withdrawTxHashes.push(new BigNumber(jarray[i], 16));
    }
  }

  isValid(version: uint8_t): boolean {
    return this._withdrawTxHashes.length > 0;
  }

  copyPayload(payload: Payload) {
    try {
      const crcProposal = payload as CRCProposalRealWithdraw;
      this.copyCRCProposalRealWithdraw(crcProposal);
    } catch (e) {
      Log.error("payload is not instance of CRCProposalRealWithdraw");
    }
    return this;
  }

  copyCRCProposalRealWithdraw(payload: CRCProposalRealWithdraw) {
    this._withdrawTxHashes = payload._withdrawTxHashes;
    return this;
  }

  private isEqualDPoSPublicKeys(withdrawTxHashes: uint256[]): boolean {
    if (this._withdrawTxHashes.length !== withdrawTxHashes.length) {
      return false;
    }
    let equal = false;
    for (let i = 0; i < withdrawTxHashes.length; ++i) {
      for (let j = 0; j < this._withdrawTxHashes.length; ++j) {
        if (this._withdrawTxHashes[j].eq(withdrawTxHashes[i])) {
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
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as CRCProposalRealWithdraw;
      return this.isEqualDPoSPublicKeys(p._withdrawTxHashes);
    } catch (e) {
      Log.error("payload is not instance of CRCProposalRealWithdraw");
    }

    return false;
  }
}
