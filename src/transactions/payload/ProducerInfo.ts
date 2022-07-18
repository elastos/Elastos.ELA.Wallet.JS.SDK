// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import BigNumber from "bignumber.js";
import { Buffer } from "buffer";
import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";
import {
  bytes_t,
  sizeof_uint32_t,
  sizeof_uint64_t,
  size_t,
  uint32_t,
  uint64_t,
  uint8_t
} from "../../types";
import { Payload } from "./Payload";

export const ProducerInfoVersion = 0x00;
export const ProducerInfoDposV2Version = 0x01;

export type ProducerInfoJson = {
  OwnerPublicKey: string;
  NodePublicKey: string;
  NickName: string;
  Url: string;
  Location: string;
  Address: string;
  StakeUntil?: number;
  Signature: string;
};

export class ProducerInfo extends Payload {
  private _ownerPublicKey: bytes_t;
  private _nodePublicKey: bytes_t;
  private _nickName: string;
  private _url: string;
  private _location: uint64_t;
  private _address: string;
  private _StakeUntil: uint32_t;
  private _signature: bytes_t;

  static newFromParams(
    ownerPublicKey: bytes_t,
    nodePublicKey: bytes_t,
    nickName: string,
    url: string,
    location: uint64_t,
    address: string,
    stakeUntil: number,
    signature: bytes_t
  ) {
    let producerInfo = new ProducerInfo();
    producerInfo._ownerPublicKey = ownerPublicKey;
    producerInfo._nodePublicKey = nodePublicKey;
    producerInfo._nickName = nickName;
    producerInfo._url = url;
    producerInfo._location = location;
    producerInfo._address = address;
    if (stakeUntil) {
      producerInfo._StakeUntil = stakeUntil;
    }
    producerInfo._signature = signature;
    return producerInfo;
  }

  newFromProducerInfo(payload: ProducerInfo) {
    let producerInfo = new ProducerInfo();
    return producerInfo.copyProducerInfo(payload);
  }

  destroy() {}

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

  getStakeUntil(): uint32_t {
    return this._StakeUntil;
  }

  setStakeUntil(stakeUntil: uint32_t) {
    this._StakeUntil = stakeUntil;
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
    if (version === ProducerInfoDposV2Version) {
      ostream.writeUInt32(this._StakeUntil);
    }
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
    nodePublicKey = istream.readVarBytes(nodePublicKey);
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
    this._nickName = nickName;

    const url = istream.readVarString();
    if (!url) {
      Log.error("Deserialize: read url");
      return false;
    }
    this._url = url;

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

    if (version === ProducerInfoDposV2Version) {
      const stakeUntil = istream.readUInt32();
      if (!stakeUntil) {
        Log.error("Deserialize: read stakeUntil");
        return false;
      }
      this._StakeUntil = stakeUntil;
    }

    return true;
  }

  estimateSize(version: uint8_t): size_t {
    let size: size_t = 0;
    let stream = new ByteStream();

    size += stream.writeVarUInt(this._ownerPublicKey.length);
    size += this._ownerPublicKey.length;

    size += stream.writeVarUInt(this._nodePublicKey.length);
    size += this._nodePublicKey.length;

    let nickName = Buffer.from(this._nickName, "utf8");
    size += stream.writeVarUInt(nickName.length);
    size += nickName.length;

    let url = Buffer.from(this._url, "utf8");
    size += stream.writeVarUInt(url.length);
    size += url.length;

    size += sizeof_uint64_t(); // size of this.loacation

    let address = Buffer.from(this._address, "utf8");
    size += stream.writeVarUInt(address.length);
    size += address.length;

    if (version === ProducerInfoDposV2Version) {
      size += sizeof_uint32_t(); // size of this.stakeUntil
    }

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

  toJson(version: uint8_t): ProducerInfoJson {
    let j = <ProducerInfoJson>{};
    j["OwnerPublicKey"] = this._ownerPublicKey.toString("hex");
    j["NodePublicKey"] = this._nodePublicKey.toString("hex");
    j["NickName"] = this._nickName;
    j["Url"] = this._url;
    j["Location"] = this._location.toString(16);
    j["Address"] = this._address;
    if (version === ProducerInfoDposV2Version) {
      j["StakeUntil"] = this._StakeUntil;
    }
    j["Signature"] = this._signature.toString("hex");
    return j;
  }

  fromJson(j: ProducerInfoJson, version: uint8_t) {
    this._ownerPublicKey = Buffer.from(j["OwnerPublicKey"], "hex");
    this._nodePublicKey = Buffer.from(j["NodePublicKey"], "hex");
    this._nickName = j["NickName"];
    this._url = j["Url"];
    this._location = new BigNumber(j["Location"], 16);
    this._address = j["Address"];
    if (version === ProducerInfoDposV2Version) {
      this._StakeUntil = j["StakeUntil"];
    }
    this._signature = Buffer.from(j["Signature"], "hex");
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
    if (payload._StakeUntil) {
      this._StakeUntil = payload._StakeUntil;
    }
    this._signature = payload._signature;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as ProducerInfo;
      let equal =
        this._ownerPublicKey.equals(p._ownerPublicKey) &&
        this._nodePublicKey.equals(p._nodePublicKey) &&
        this._nickName == p._nickName &&
        this._url == p._url &&
        this._location.eq(p._location) &&
        this._address == p._address &&
        this._signature.equals(p._signature);
      if (version === ProducerInfoDposV2Version) {
        equal = equal && this._StakeUntil == p._StakeUntil;
      }
      return equal;
    } catch (e) {
      Log.error("payload is not instance of ProducerInfo");
    }

    return false;
  }
}
