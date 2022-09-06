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

import BigNumber from "bignumber.js";
import { Address } from "../../walletcore/Address";
import { uint168 } from "../../common/uint168";
import {
  bytes_t,
  sizeof_uint64_t,
  size_t,
  uint64_t,
  uint8_t
} from "../../types";
import { ByteStream } from "../../common/bytestream";
import { Payload } from "./Payload";
import { Log } from "../../common/Log";
import { SHA256 } from "../../walletcore/sha256";

export type UnstakeInfo = {
  ToAddress: string;
  Value: string;
  Code?: string;
  Signature?: string;
};

export const DPoSV2UnstakeVersion = 0;
export const DPoSV2UnstakeVersion_01 = 0x01;

export class Unstake extends Payload {
  private _toAddr: uint168;
  private _code: bytes_t;
  private _value: uint64_t;
  private _signature: bytes_t;

  static newFromParams(
    toAddr: uint168,
    value: uint64_t,
    code?: bytes_t,
    signature?: bytes_t
  ) {
    let unstake = new Unstake();
    unstake._toAddr = toAddr;
    unstake._value = value;
    if (code.length > 0) {
      unstake._code = code;
    }
    if (signature.length > 0) {
      unstake._signature = signature;
    }
    return unstake;
  }

  serializeUnsigned(stream: ByteStream, version: uint8_t) {
    stream.writeBytes(this._toAddr.bytes());
    if (version === DPoSV2UnstakeVersion) {
      stream.writeVarBytes(this._code);
    }
    stream.writeBNAsUIntOfSize(this._value, 8);
  }

  deserializeUnsigned(stream: ByteStream, version: uint8_t): boolean {
    let toAddr: bytes_t;
    toAddr = stream.readBytes(toAddr, 21);
    if (!toAddr) {
      Log.error("Unstake deserialize toAddr");
      return false;
    }
    this._toAddr = uint168.newFrom21BytesBuffer(toAddr);

    if (version === DPoSV2UnstakeVersion) {
      let code: bytes_t;
      code = stream.readVarBytes(code);
      if (!code) {
        Log.error("Unstake deserialize code");
        return false;
      }
      this._code = code;
    }

    let value = stream.readUIntOfBytesAsBN(8);
    if (!value) {
      Log.error("Unstake deserialize value");
      return false;
    }
    this._value = value;

    return true;
  }

  toJsonUnsigned(version: uint8_t): UnstakeInfo {
    let j = <UnstakeInfo>{};
    j["ToAddress"] = Address.newFromProgramHash(this._toAddr).string();
    if (version === DPoSV2UnstakeVersion) {
      j["Code"] = this._code.toString("hex");
    }
    j["Value"] = this._value.toString();
    return j;
  }

  fromJsonUnsigned(j: UnstakeInfo, version: uint8_t) {
    this._toAddr = Address.newFromAddressString(j["ToAddress"]).programHash();
    if (version === DPoSV2UnstakeVersion) {
      this._code = Buffer.from(j["Code"], "hex");
    }
    this._value = new BigNumber(j["Value"]);
  }

  digestUnstake(version: uint8_t): string {
    let stream = new ByteStream();
    this.serializeUnsigned(stream, version);
    return SHA256.encodeToBuffer(stream.getBytes()).toString("hex");
  }

  estimateSize(version: uint8_t): size_t {
    let size = 0;
    let stream = new ByteStream();

    size += this._toAddr.bytes().length;
    if (version === DPoSV2UnstakeVersion) {
      size += stream.writeVarUInt(this._code.length);
      size += this._code.length;
    }
    size += sizeof_uint64_t();
    if (version === DPoSV2UnstakeVersion) {
      size += stream.writeVarUInt(this._signature.length);
      size += this._signature.length;
    }

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    this.serializeUnsigned(stream, version);
    if (version === DPoSV2UnstakeVersion) {
      stream.writeVarBytes(this._signature);
    }
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    if (!this.deserializeUnsigned(stream, version)) {
      Log.error("Unstake deserialize unsigned");
      return false;
    }

    if (version === DPoSV2UnstakeVersion) {
      let signature: bytes_t;
      signature = stream.readVarBytes(signature);
      if (!signature) {
        Log.error("Unstake deserialize signature");
        return false;
      }
      this._signature = signature;
    }

    return true;
  }

  toJson(version: uint8_t): UnstakeInfo {
    let j = this.toJsonUnsigned(version);
    if (version === DPoSV2UnstakeVersion) {
      j["Signature"] = this._signature.toString("hex");
    }
    return j;
  }

  fromJson(j: UnstakeInfo, version: uint8_t) {
    this.fromJsonUnsigned(j, version);
    if (version === DPoSV2UnstakeVersion) {
      this._signature = Buffer.from(j["Signature"], "hex");
    }
  }

  isValid(version: uint8_t): boolean {
    return true;
  }

  copyPayload(payload: Payload) {
    try {
      const p = payload as Unstake;
      this.copyUnstake(p);
    } catch (e) {
      Log.error("payload is not instance of Unstake");
    }

    return this;
  }

  copyUnstake(payload: Unstake) {
    this._toAddr = payload._toAddr;
    this._value = payload._value;
    if (payload._code) {
      this._code = payload._code;
    }
    if (payload._signature) {
      this._signature = payload._signature;
    }
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as Unstake;
      if (version == DPoSV2UnstakeVersion) {
        return (
          this._toAddr.bytes().equals(p._toAddr.bytes()) &&
          this._code.equals(p._code) &&
          this._value.eq(p._value) &&
          this._signature.equals(p._signature)
        );
      } else {
        return (
          this._toAddr.bytes().equals(p._toAddr.bytes()) &&
          this._value.eq(p._value)
        );
      }
    } catch (e) {
      Log.error("payload is not instance of Unstake");
    }

    return false;
  }
}
