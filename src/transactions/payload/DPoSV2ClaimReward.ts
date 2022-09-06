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
  sizeof_uint64_t
} from "../../types";
import { Address } from "../../walletcore/Address";
import { SHA256 } from "../../walletcore/sha256";
import { Payload } from "./Payload";

export const DPoSV2ClaimRewardVersion = 0;
export const DPoSV2ClaimRewardVersion_01 = 0x01;

export type DPoSV2ClaimRewardInfo = {
  Amount: string;
  ToAddress?: string;
  Signature?: string;
};

export class DPoSV2ClaimReward extends Payload {
  private _amount: uint64_t;
  private _signature: bytes_t;
  private _toAddr: uint168;

  static newFromParams(
    amount: uint64_t,
    signature?: bytes_t,
    toAddr?: uint168
  ) {
    let claimReward = new DPoSV2ClaimReward();
    claimReward._amount = amount;
    if (signature.length > 0) {
      claimReward._signature = signature;
    }
    if (toAddr.bytes.length > 0) {
      claimReward._toAddr = toAddr;
    }

    return claimReward;
  }

  serializeUnsigned(stream: ByteStream, version: uint8_t) {
    if (version === DPoSV2ClaimRewardVersion_01) {
      stream.writeBytes(this._toAddr.bytes());
    }
    stream.writeBNAsUIntOfSize(this._amount, 8);
  }

  deserializeUnsigned(stream: ByteStream, version: uint8_t): boolean {
    if (version === DPoSV2ClaimRewardVersion_01) {
      let toAddr: bytes_t;
      toAddr = stream.readBytes(toAddr, 21);
      if (!toAddr) {
        Log.error("DPoSV2ClaimReward deserialize toAddr");
        return false;
      }
      this._toAddr = uint168.newFrom21BytesBuffer(toAddr);
    }

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
    if (version === DPoSV2ClaimRewardVersion_01) {
      j["ToAddress"] = Address.newFromProgramHash(this._toAddr).string();
    }
    j["Amount"] = this._amount.toString();
    return j;
  }

  fromJsonUnsigned(j: DPoSV2ClaimRewardInfo, version: uint8_t) {
    if (version === DPoSV2ClaimRewardVersion_01) {
      this._toAddr = Address.newFromAddressString(j["ToAddress"]).programHash();
    }
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
    if (version === DPoSV2ClaimRewardVersion_01) {
      size += this._toAddr.bytes().length;
    }
    size += sizeof_uint64_t();
    if (version === DPoSV2ClaimRewardVersion) {
      size += stream.writeVarUInt(this._signature.length);
      size += this._signature.length;
    }
    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    this.serializeUnsigned(stream, version);
    if (version === DPoSV2ClaimRewardVersion) {
      stream.writeVarBytes(this._signature);
    }
  }

  deserialize(stream: ByteStream, version: uint8_t) {
    if (!this.deserializeUnsigned(stream, version)) {
      Log.error("deserialize unsigned");
      return false;
    }
    if (version === DPoSV2ClaimRewardVersion) {
      let signature: bytes_t;
      signature = stream.readVarBytes(signature);
      if (!signature) {
        Log.error("DPoSV2ClaimReward deserialize signature");
        return false;
      }
      this._signature = signature;
    }

    return true;
  }

  toJson(version: uint8_t): DPoSV2ClaimRewardInfo {
    let j = this.toJsonUnsigned(version);
    if (version === DPoSV2ClaimRewardVersion) {
      j["Signature"] = this._signature.toString("hex");
    }
    return j;
  }

  fromJson(j: DPoSV2ClaimRewardInfo, version: uint8_t) {
    this.fromJsonUnsigned(j, version);
    if (version === DPoSV2ClaimRewardVersion) {
      this._signature = Buffer.from(j["Signature"], "hex");
    }
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
    if (payload._toAddr) {
      this._toAddr = payload._toAddr;
    }
    if (payload._signature) {
      this._signature = payload._signature;
    }
    this._amount = payload._amount;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as DPoSV2ClaimReward;
      if (version === DPoSV2ClaimRewardVersion_01) {
        return (
          this._toAddr.bytes().equals(p._toAddr.bytes()) &&
          this._amount.eq(p._amount)
        );
      } else {
        return (
          this._amount.eq(p._amount) && this._signature.equals(p._signature)
        );
      }
    } catch (e) {
      Log.error("payload is not instance of DPoSV2ClaimReward");
    }

    return false;
  }
}
