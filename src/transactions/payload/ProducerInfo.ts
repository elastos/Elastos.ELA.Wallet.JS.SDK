// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import {
  bytes_t,
  size_t,
  uint64_t,
  uint8_t,
  json,
  sizeof_uint64_t
} from "../../types";
import { Payload } from "./Payload";
import { Log } from "../../common/Log";
import { ByteStream } from "../../common/bytestream";
import BigNumber from "bignumber.js";

export class ProducerInfo extends Payload {
  private _ownerPublicKey: bytes_t;
  private _nodePublicKey: bytes_t;
  private _nickName: string;
  private _url: string;
  private _location: uint64_t;
  private _address: string;
  private _signature: bytes_t;

  newFromParams(
    ownerPublicKey: bytes_t,
    nodePublicKey: bytes_t,
    nickName: string,
    url: string,
    location: uint64_t,
    address: string,
    signature: bytes_t
  ) {
    this._ownerPublicKey = ownerPublicKey;
    this._nodePublicKey = nodePublicKey;
    this._nickName = nickName;
    this._url = url;
    this._location = location;
    this._address = address;
    this._signature = signature;
  }

  newFromProducerInfo(payload: ProducerInfo) {
    this.copyProducerInfo(payload);
  }

  destory() {}

  getPublicKey(): bytes_t {
    return this._ownerPublicKey;
  }

  setPublicKey(key: bytes_t) {
    this._ownerPublicKey = key;
  }

  getNodePublicKey(): bytes_t {
    return this._nodePublicKey;
  }

  setNodePublicKey(key: bytes_t) {
    this._nodePublicKey = key;
  }

  getNickName(): string {
    return this._nickName;
  }

  setNickName(name: string) {
    this._nickName = name;
  }

  getUrl(): string {
    return this._url;
  }

  setUrl(url: string) {
    this._url = url;
  }

  getLocation(): uint64_t {
    return this._location;
  }

  setLocation(location: uint64_t) {
    this._location = location;
  }

  getAddress(): string {
    return this._address;
  }

  setAddress(address: string) {
    this._address = address;
  }

  getSignature(): bytes_t {
    return this._signature;
  }

  setSignature(signature: bytes_t) {
    this._signature = signature;
  }

  serializeUnsigned(ostream: ByteStream, version: uint8_t) {
    ostream.writeVarBytes(this._ownerPublicKey);
    ostream.writeVarBytes(this._nodePublicKey);
    ostream.writeVarString(this._nickName);
    ostream.writeVarString(this._url);
    ostream.writeBNAsUIntOfSize(this._location, 8);
    ostream.writeVarString(this._address);
  }

  deserializeUnsigned(istream: ByteStream, version: uint8_t): boolean {
    let ownerPublicKey: bytes_t;
    ownerPublicKey = istream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      Log.error("Deserialize: read public key");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let nodePublicKey: bytes_t;
    nodePublicKey = istream.readVarBytes(this._nodePublicKey);
    if (!nodePublicKey) {
      Log.error("Deserialize: read node public key");
      return false;
    }
    this._nodePublicKey = nodePublicKey;

    const nickName = istream.readVarString();
    if (!nickName) {
      Log.error("Deserialize: read nick name");
      return false;
    }

    const url = istream.readVarString();
    if (!url) {
      Log.error("Deserialize: read url");
      return false;
    }

    let location = istream.readUIntOfBytesAsBN(8);
    if (!location) {
      Log.error("Deserialize: read location");
      return false;
    }
    this._location = location;

    const address = istream.readVarString();
    if (!address) {
      Log.error("Deserialize: read address");
      return false;
    }
    this._address = address;
    return true;
  }

  estimateSize(version: uint8_t): size_t {
    let size: size_t = 0;
    let stream = new ByteStream();
    size += stream.writeVarUInt(this._ownerPublicKey.length);
    size += this._ownerPublicKey.length;
    size += stream.writeVarUInt(this._nodePublicKey.length);
    size += this._nodePublicKey.length;
    size += stream.writeVarUInt(this._nickName.length);
    size += this._nickName.length;
    size += stream.writeVarUInt(this._url.length);
    size += this._url.length;
    size += sizeof_uint64_t(); // size of this.loacation
    size += stream.writeVarUInt(this._address.length);
    size += this._address.length;
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
      Log.error("Deserialize: register producer payload unsigned");
      return false;
    }

    let signature: bytes_t;
    signature = istream.readVarBytes(this._signature);
    if (!signature) {
      Log.error("Deserialize: register producer payload read signature");
      return false;
    }
    this._signature = signature;
    return true;
  }

  toJson(version: uint8_t): json {
    let j: json = {};
    j["OwnerPublicKey"] = this._ownerPublicKey.toString("hex");
    j["NodePublicKey"] = this._nodePublicKey.toString("hex");
    j["NickName"] = this._nickName;
    j["Url"] = this._url;
    j["Location"] = this._location.toString(16);
    j["Address"] = this._address;
    j["Signature"] = this._signature.toString("hex");
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._ownerPublicKey = Buffer.from(j["OwnerPublicKey"] as string, "hex");
    this._nodePublicKey = Buffer.from(j["NodePublicKey"] as string, "hex");
    this._nickName = j["NickName"] as string;
    this._url = j["Url"] as string;
    this._location = new BigNumber(j["Location"] as string, 16);
    this._address = j["Address"] as string;
    this._signature = Buffer.from(j["Signature"] as string, "hex");
  }

  copyPayload(payload: Payload) {
    try {
      const payloadRegisterProducer = payload as ProducerInfo;
      this.copyProducerInfo(payloadRegisterProducer);
    } catch (e) {
      Log.error("payload is not instance of ProducerInfo");
    }

    return this;
  }

  copyProducerInfo(payload: ProducerInfo): ProducerInfo {
    this._ownerPublicKey = payload._ownerPublicKey;
    this._nodePublicKey = payload._nodePublicKey;
    this._nickName = payload._nickName;
    this._url = payload._url;
    this._location = payload._location;
    this._address = payload._address;
    this._signature = payload._signature;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as ProducerInfo;
      return (
        this._ownerPublicKey.toString() == p._ownerPublicKey.toString() &&
        this._nodePublicKey.toString() == p._nodePublicKey.toString() &&
        this._nickName == p._nickName &&
        this._url == p._url &&
        this._location.eq(p._location) &&
        this._address == p._address &&
        this._signature.toString() == p._signature.toString()
      );
    } catch (e) {
      Log.error("payload is not instance of ProducerInfo");
    }

    return false;
  }
}
