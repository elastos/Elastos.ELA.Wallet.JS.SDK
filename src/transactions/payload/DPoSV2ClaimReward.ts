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

export const DPoSV2ClaimRewardVersionV0 = 0x00;
export const DPoSV2ClaimRewardVersionV1 = 0x01;

export type DPoSV2ClaimRewardInfo = {
  ToAddress: string;
  Value: string;
  Code?: string;
  Signature?: string;
};

export class DPoSV2ClaimReward extends Payload {
  private _toAddr: uint168;
  private _code: bytes_t;
  private _value: uint64_t;
  private _signature: bytes_t;

  static newFromParams(value: uint64_t, signature?: bytes_t, toAddr?: uint168) {
    let claimReward = new DPoSV2ClaimReward();
    claimReward._value = value;
    if (signature.length > 0) {
      claimReward._signature = signature;
    }
    if (toAddr.bytes.length > 0) {
      claimReward._toAddr = toAddr;
    }

    return claimReward;
  }

  serializeUnsigned(stream: ByteStream, version: uint8_t) {
    stream.writeBytes(this._toAddr.bytes());
    if (version === DPoSV2ClaimRewardVersionV0) {
      stream.writeVarBytes(this._code);
    }
    stream.writeBNAsUIntOfSize(this._value, 8);
  }

  deserializeUnsigned(stream: ByteStream, version: uint8_t): boolean {
    let toAddr: bytes_t;
    toAddr = stream.readBytes(toAddr, 21);
    if (!toAddr) {
      Log.error("DPoSV2ClaimReward deserialize toAddr");
      return false;
    }
    this._toAddr = uint168.newFrom21BytesBuffer(toAddr);

    if (version === DPoSV2ClaimRewardVersionV0) {
      let code: bytes_t;
      code = stream.readVarBytes(code);
      if (!code) {
        Log.error("DPoSV2ClaimReward deserialize code");
        return false;
      }
      this._code = code;
    }

    let amount = stream.readUIntOfBytesAsBN(8);
    if (!amount) {
      Log.error("DPoSV2ClaimReward deserialize unsigned amount");
      return false;
    }
    this._value = amount;

    return true;
  }

  toJsonUnsigned(version: uint8_t) {
    let j = <DPoSV2ClaimRewardInfo>{};
    j["ToAddress"] = Address.newFromProgramHash(this._toAddr).string();
    if (version === DPoSV2ClaimRewardVersionV0) {
      j["Code"] = this._code.toString("hex");
    }
    j["Value"] = this._value.toString();
    return j;
  }

  fromJsonUnsigned(j: DPoSV2ClaimRewardInfo, version: uint8_t) {
    this._toAddr = Address.newFromAddressString(j["ToAddress"]).programHash();

    if (version === DPoSV2ClaimRewardVersionV0) {
      this._code = Buffer.from(j["Code"], "hex");
    }
    this._value = new BigNumber(j["Value"]);
  }

  digestDPoSV2ClaimReward(version: uint8_t): string {
    let stream = new ByteStream();
    this.serializeUnsigned(stream, version);
    return SHA256.encodeToBuffer(stream.getBytes()).toString("hex");
  }

  estimateSize(version: uint8_t): size_t {
    let size = 0;
    let stream = new ByteStream();
    size += this._toAddr.bytes().length;
    if (version === DPoSV2ClaimRewardVersionV0) {
      size += stream.writeVarUInt(this._code.length);
      size += this._code.length;
    }
    size += sizeof_uint64_t();
    if (version === DPoSV2ClaimRewardVersionV0) {
      size += stream.writeVarUInt(this._signature.length);
      size += this._signature.length;
    }
    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    this.serializeUnsigned(stream, version);
    if (version === DPoSV2ClaimRewardVersionV0) {
      stream.writeVarBytes(this._signature);
    }
  }

  deserialize(stream: ByteStream, version: uint8_t) {
    if (!this.deserializeUnsigned(stream, version)) {
      Log.error("deserialize unsigned");
      return false;
    }
    if (version === DPoSV2ClaimRewardVersionV0) {
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
    if (version === DPoSV2ClaimRewardVersionV0) {
      j["Signature"] = this._signature.toString("hex");
    }
    return j;
  }

  fromJson(j: DPoSV2ClaimRewardInfo, version: uint8_t) {
    this.fromJsonUnsigned(j, version);
    if (version === DPoSV2ClaimRewardVersionV0) {
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
    this._toAddr = payload._toAddr;
    if (payload._code) {
      this._code = payload._code;
    }
    if (payload._signature) {
      this._signature = payload._signature;
    }
    this._value = payload._value;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as DPoSV2ClaimReward;

      if (version === DPoSV2ClaimRewardVersionV1) {
        return (
          this._toAddr.bytes().equals(p._toAddr.bytes()) &&
          this._value.eq(p._value)
        );
      } else if (version === DPoSV2ClaimRewardVersionV0) {
        return (
          this._toAddr.bytes().equals(p._toAddr.bytes()) &&
          this._code.equals(p._code) &&
          this._value.eq(p._value) &&
          this._signature.equals(p._signature)
        );
      }
    } catch (e) {
      Log.error("payload is not instance of DPoSV2ClaimReward");
    }

    return false;
  }
}
