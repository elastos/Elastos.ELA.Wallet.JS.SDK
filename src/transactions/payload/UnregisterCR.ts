// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { uint168 } from "../../common/uint168";
import { bytes_t, size_t, uint8_t, json } from "../../types";
import { Address } from "../../walletcore/Address";
import { Log } from "../../common/Log";
import { ByteStream } from "../../common/bytestream";
import { Payload } from "./Payload";

export class UnregisterCR extends Payload {
  private _cid: uint168;
  private _signature: bytes_t;

  static newFromParams(cid: uint168, sign: bytes_t) {
    const unregisterCR = new UnregisterCR();
    unregisterCR._cid = cid;
    unregisterCR._signature = sign;
    return unregisterCR;
  }

  setCID(cid: uint168) {
    this._cid = cid;
  }

  getCID(): uint168 {
    return this._cid;
  }

  setSignature(signature: bytes_t) {
    this._signature = signature;
  }

  getSignature(): bytes_t {
    return this._signature;
  }

  estimateSize(version: uint8_t): size_t {
    let size: size_t = 0;
    size += this._cid.bytes().length;

    let stream = new ByteStream();
    size += stream.writeVarUInt(this._signature.length);
    size += this._signature.length;

    return size;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    this.serializeUnsigned(ostream, version);
    ostream.writeVarBytes(this._signature);
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    if (!this.deserializeUnsigned(istream, version)) {
      return false;
    }

    let signature: bytes_t;
    signature = istream.readVarBytes(signature);

    if (!signature) {
      Log.error("UnregisterCR Deserialize: read _signature");
      return false;
    }
    this._signature = signature;
    return true;
  }

  serializeUnsigned(ostream: ByteStream, version: uint8_t) {
    ostream.writeVarBytes(this._cid.bytes());
  }

  deserializeUnsigned(istream: ByteStream, version: uint8_t) {
    let cid: bytes_t;
    cid = istream.readVarBytes(cid);
    if (!cid) {
      Log.error("UnregisterCR Deserialize: read _did");
      return false;
    }
    this._cid = uint168.newFrom21BytesBuffer(cid);
    return true;
  }

  toJson(version: uint8_t): json {
    let j = {};
    j["CID"] = Address.newFromAddressString(
      this._cid.bytes().toString()
    ).string();
    j["Signature"] = this._signature.toString("hex");
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    let cid = j["CID"] as string;
    this._cid = Address.newFromAddressString(cid).programHash();

    let signature = j["Signature"] as string;
    this._signature = Buffer.from(signature, "hex");
  }

  copyPayload(payload: Payload) {
    try {
      const unregisterCR = payload as UnregisterCR;
      this.copyUnregisterCR(unregisterCR);
    } catch (e) {
      Log.error("payload is not instance of UnregisterCR");
    }

    return this;
  }

  copyUnregisterCR(payload: UnregisterCR) {
    this._cid = payload._cid;
    this._signature = payload._signature;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as UnregisterCR;
      return (
        this._cid.bytes().toString() == p._cid.bytes().toString() &&
        this._signature.toString() == p._signature.toString()
      );
    } catch (e) {
      Log.error("payload is not instance of UnregisterCR");
    }

    return false;
  }
}
