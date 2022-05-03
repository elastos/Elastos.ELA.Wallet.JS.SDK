// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
import { Buffer } from "buffer";
import { bytes_t, uint8_t, json, size_t } from "../../types";
import { Payload } from "./Payload";
import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";

export class CancelProducer extends Payload {
  private _publicKey: bytes_t;
  private _signature: bytes_t;

  newFromParams(pubkey: bytes_t, sign: bytes_t) {
    this._publicKey = pubkey;
    this._signature = sign;
  }

  newFromCancelProducer(payload: CancelProducer) {
    this.copyCancelProducer(payload);
  }

  destory() {}

  getPublicKey(): bytes_t {
    return this._publicKey;
  }

  setPublicKey(key: bytes_t) {
    this._publicKey = key;
  }

  setSignature(signature: bytes_t) {
    this._signature = signature;
  }

  serializeUnsigned(ostream: ByteStream, version: uint8_t) {
    ostream.writeVarBytes(this._publicKey);
  }

  deserializeUnsigned(istream: ByteStream, version: uint8_t): boolean {
    let publicKey: bytes_t;
    publicKey = istream.readVarBytes(this._publicKey);
    if (publicKey) {
      this._publicKey = publicKey;
      return true;
    } else {
      return false;
    }
  }

  estimateSize(version: uint8_t): size_t {
    let size: size_t = 0;
    let stream = new ByteStream();

    size += stream.writeVarUInt(this._publicKey.length);
    size += this._publicKey.length;
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
      Log.error("Deserialize: cancel producer payload read unsigned");
      return false;
    }

    let signature: bytes_t;
    signature = istream.readVarBytes(this._signature);
    if (!signature) {
      Log.error("Deserialize: cancel producer payload read signature");
      return false;
    }
    this._signature = signature;
    return true;
  }

  toJson(version: uint8_t): json {
    let j: json = {};
    j["PublicKey"] = this._publicKey.toString("hex");
    j["Signature"] = this._signature.toString("hex");
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._publicKey = Buffer.from(j["PublicKey"] as string, "hex");
    this._signature = Buffer.from(j["Signature"] as string, "hex");
  }

  copyPayload(payload: Payload) {
    try {
      const payloadCancelProducer = payload as CancelProducer;
      this.copyCancelProducer(payloadCancelProducer);
    } catch (e) {
      Log.error("payload is not instance of CancelProducer");
    }

    return this;
  }

  copyCancelProducer(payload: CancelProducer) {
    this._publicKey = payload._publicKey;
    this._signature = payload._signature;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as CancelProducer;
      return (
        this._publicKey.toString() == p._publicKey.toString() &&
        this._signature.toString() == p._signature.toString()
      );
    } catch (e) {
      Log.error("payload is not instance of CancelProducer");
    }

    return false;
  }
}
