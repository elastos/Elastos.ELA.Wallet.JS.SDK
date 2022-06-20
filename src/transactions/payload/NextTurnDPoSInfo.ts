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

import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";
import {
  size_t,
  uint8_t,
  uint32_t,
  bytes_t,
  sizeof_uint32_t
} from "../../types";
import { Payload } from "./Payload";

export type NextTurnDPoSInfoJson = {
  WorkingHeight: number;
  CRPublicKeys: string[];
  DPoSPublicKeys: string[];
};

export class NextTurnDPoSInfo extends Payload {
  private _workingHeight: uint32_t;
  private _crPublicKeys: bytes_t[];
  private _dposPublicKeys: bytes_t[];

  constructor() {
    super();
    this._workingHeight = 0;
  }

  static newFromParams(
    blockHeight: uint32_t,
    crPubkeys: bytes_t[],
    dposPubkeys: bytes_t[]
  ) {
    const nextTurnDPOSInfo = new NextTurnDPoSInfo();
    nextTurnDPOSInfo._workingHeight = blockHeight;
    nextTurnDPOSInfo._crPublicKeys = crPubkeys;
    nextTurnDPOSInfo._dposPublicKeys = dposPubkeys;
    return nextTurnDPOSInfo;
  }

  newFromNextTurnDPoSInfo(payload: NextTurnDPoSInfo) {
    const nextTurnDPOSInfo = new NextTurnDPoSInfo();
    nextTurnDPOSInfo.copyNextTurnDPoSInfo(payload);
    return nextTurnDPOSInfo;
  }

  setWorkingHeight(height: uint32_t) {
    this._workingHeight = height;
  }

  getWorkingHeight(): uint32_t {
    return this._workingHeight;
  }

  setCRPublicKeys(pubkeys) {
    this._crPublicKeys = pubkeys;
  }

  getCRPublicKeys(): bytes_t[] {
    return this._crPublicKeys;
  }

  setDPoSPublicKeys(pubkeys: bytes_t[]) {
    this._dposPublicKeys = pubkeys;
  }

  getDPoSPublicKeys(): bytes_t[] {
    return this._dposPublicKeys;
  }

  estimateSize(version: uint8_t): size_t {
    let size = 0;
    let stream = new ByteStream();

    size += sizeof_uint32_t();
    size += stream.writeVarUInt(this._crPublicKeys.length);
    for (let i = 0; i < this._crPublicKeys.length; ++i) {
      size += stream.writeVarUInt(this._crPublicKeys[i].length);
      size += this._crPublicKeys[i].length;
    }

    size += stream.writeVarUInt(this._dposPublicKeys.length);
    for (let i = 0; i < this._dposPublicKeys.length; ++i) {
      size += stream.writeVarUInt(this._dposPublicKeys[i].length);
      size += this._dposPublicKeys[i].length;
    }

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    stream.writeUInt32(this._workingHeight);
    stream.writeVarUInt(this._crPublicKeys.length);
    for (let i = 0; i < this._crPublicKeys.length; ++i) {
      stream.writeVarBytes(this._crPublicKeys[i]);
    }

    stream.writeVarUInt(this._dposPublicKeys.length);
    for (let i = 0; i < this._dposPublicKeys.length; ++i) {
      stream.writeVarBytes(this._dposPublicKeys[i]);
    }
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    if (!stream.readUInt32(this._workingHeight)) {
      Log.error("deserialize working height");
      return false;
    }

    let len = stream.readVarUInt();
    if (!len) {
      Log.error("deserialize crPubKey length");
      return false;
    }
    for (let i = 0; i < len.toNumber(); ++i) {
      let pubkey: bytes_t;
      pubkey = stream.readVarBytes(pubkey);
      if (!pubkey) {
        Log.error("deserialize crPubKeys");
        return false;
      }
      this._crPublicKeys.push(pubkey);
    }

    len = stream.readVarUInt();
    if (!len) {
      Log.error("deserialize dpos pubkey length");
      return false;
    }
    for (let i = 0; i < len.toNumber(); ++i) {
      let pubkey: bytes_t;
      if (!stream.readVarBytes(pubkey)) {
        Log.error("deserialize dpos pubkey");
        return false;
      }
      this._dposPublicKeys.push(pubkey);
    }
    return true;
  }

  toJson(version: uint8_t) {
    let j = <NextTurnDPoSInfoJson>{};
    let crPubKeys = [];
    let dposPubKeys = [];

    for (let i = 0; i < this._crPublicKeys.length; ++i) {
      crPubKeys.push(this._crPublicKeys[i].toString("hex"));
    }

    for (let i = 0; i < this._dposPublicKeys.length; ++i) {
      dposPubKeys.push(this._dposPublicKeys[i].toString("hex"));
    }

    j["WorkingHeight"] = this._workingHeight;
    j["CRPublicKeys"] = crPubKeys;
    j["DPoSPublicKeys"] = dposPubKeys;

    return j;
  }

  fromJson(j: NextTurnDPoSInfoJson, version: uint8_t) {
    this._workingHeight = j["WorkingHeight"] as number;

    let crPubKeys = j["CRPublicKeys"] as [];
    let dposPubKeys = j["DPoSPublicKeys"] as [];

    for (let i = 0; i != crPubKeys.length; ++i) {
      let pubkey = Buffer.from(crPubKeys[i], "hex");
      this._crPublicKeys.push(pubkey);
    }

    for (let i = 0; i != dposPubKeys.length; ++i) {
      let pubkey = Buffer.from(dposPubKeys[i], "hex");
      this._dposPublicKeys.push(pubkey);
    }
  }

  copyFromPayload(payload: Payload) {
    try {
      const p = payload as NextTurnDPoSInfo;
      this.copyNextTurnDPoSInfo(p);
    } catch (e) {
      Log.error("payload is not instance of NextTurnDPoSInfo");
    }

    return this;
  }

  copyNextTurnDPoSInfo(payload: NextTurnDPoSInfo) {
    this._workingHeight = payload._workingHeight;
    this._crPublicKeys = payload._crPublicKeys;
    this._dposPublicKeys = payload._dposPublicKeys;
    return this;
  }

  private isEqualCRPublicKeys(crPublicKeys: bytes_t[]): boolean {
    if (this._crPublicKeys.length !== crPublicKeys.length) {
      return false;
    }
    this._crPublicKeys.sort((a, b) => a.compare(b));
    crPublicKeys.sort((a, b) => a.compare(b));
    for (let i = 0; i < crPublicKeys.length; ++i) {
      if (!this._crPublicKeys[i].equals(crPublicKeys[i])) {
        return false;
      }
    }
    return true;
  }

  private isEqualDPoSPublicKeys(dposPublicKeys: bytes_t[]): boolean {
    if (this._dposPublicKeys.length !== dposPublicKeys.length) {
      return false;
    }
    this._dposPublicKeys.sort((a, b) => a.compare(b));
    dposPublicKeys.sort((a, b) => a.compare(b));
    for (let i = 0; i < dposPublicKeys.length; ++i) {
      if (!this._dposPublicKeys[i].equals(dposPublicKeys[i])) {
        return false;
      }
    }
    return true;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as NextTurnDPoSInfo;
      return (
        this._workingHeight == p._workingHeight &&
        this.isEqualCRPublicKeys(p._crPublicKeys) &&
        this.isEqualDPoSPublicKeys(p._dposPublicKeys)
      );
    } catch (e) {
      Log.error("payload is not instance of NextTurnDPoSInfo");
    }

    return false;
  }
}
