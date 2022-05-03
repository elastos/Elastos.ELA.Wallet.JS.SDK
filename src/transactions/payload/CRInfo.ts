// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
import { Buffer } from "buffer";
import { ByteStream } from "../../common/bytestream";
import { uint168 } from "../../common/uint168";
import {
  json,
  bytes_t,
  size_t,
  uint64_t,
  uint8_t,
  sizeof_uint64_t
} from "../../types";
import { Log } from "../../common/Log";
import { Payload } from "./Payload";
import BigNumber from "bignumber.js";
import { Address } from "../../walletcore/Address";
import { EcdsaSigner } from "../../walletcore/ecdsasigner";
import { SHA256 } from "../../walletcore/sha256";

export const CRInfoVersion = 0x00;
export const CRInfoDIDVersion = 0x01;

export class CRInfo extends Payload {
  private _code: bytes_t;
  private _cid: uint168;
  private _did: uint168;
  private _nickName: string;
  private _url: string;
  private _location: uint64_t;
  private _signature: bytes_t;

  static newFromParams(
    code: bytes_t,
    cid: uint168,
    did: uint168,
    nickName: string,
    url: string,
    location: uint64_t,
    signature: bytes_t
  ) {
    const crInfo = new CRInfo();
    crInfo._code = code;
    crInfo._cid = cid;
    crInfo._did = did;
    crInfo._nickName = nickName;
    crInfo._url = url;
    crInfo._location = location;
    crInfo._signature = signature;
  }

  getCode(): bytes_t {
    return this._code;
  }

  setCode(code: bytes_t) {
    this._code = code;
  }

  getCID(): uint168 {
    return this._cid;
  }

  setCID(cid: uint168) {
    this._cid = cid;
  }

  getDID(): uint168 {
    return this._did;
  }

  setDID(did: uint168) {
    this._did = did;
  }

  getNickName(): string {
    return this._nickName;
  }

  setNickName(nickName: string) {
    this._nickName = nickName;
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

  getSignature(): bytes_t {
    return this._signature;
  }

  setSignature(signature: bytes_t) {
    this._signature = signature;
  }

  estimateSize(version: uint8_t): size_t {
    let size: size_t = 0;
    let stream = new ByteStream();

    size += stream.writeVarUInt(this._code.length);
    size += this._code.length;
    size += this._cid.bytes().length;
    if (version > CRInfoVersion) {
      size += this._did.bytes().length;
    }

    size += stream.writeVarUInt(this._nickName.length);
    size += this._nickName.length;
    size += stream.writeVarUInt(this._url.length);
    size += this._url.length;
    size += sizeof_uint64_t();
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
      Log.error("CRInfo Deserialize: payload unsigned");
      return false;
    }

    let signature: bytes_t;
    signature = istream.readVarBytes(signature);
    if (!signature) {
      Log.error("CRInfo Deserialize: read signature");
      return false;
    }
    this._signature = signature;
    return true;
  }

  serializeUnsigned(ostream: ByteStream, version: uint8_t) {
    ostream.writeVarBytes(this._code);
    ostream.writeVarBytes(this._cid.bytes());
    if (version > CRInfoVersion) {
      ostream.writeVarBytes(this._did.bytes());
    }
    ostream.writeVarString(this._nickName);
    ostream.writeVarString(this._url);
    ostream.writeBNAsUIntOfSize(this._location, 8);
  }

  deserializeUnsigned(istream: ByteStream, version: uint8_t) {
    let code: bytes_t;
    code = istream.readVarBytes(code);
    if (!code) {
      Log.error("CRInfo Deserialize: read _code");
      return false;
    }
    this._code = code;
    let cid: bytes_t;
    cid = istream.readVarBytes(cid);
    if (!cid) {
      Log.error("CRInfo Deserialize: read _cid");
      return false;
    }
    if (version > CRInfoVersion) {
      let did: bytes_t;
      did = istream.readVarBytes(cid);
      if (!did) {
        Log.error("CRInfo Deserialize: read _did");
        return false;
      }
    }
    let nickName = istream.readVarString();
    if (!nickName) {
      Log.error("CRInfoDeserialize: read nick name");
      return false;
    }
    this._nickName = nickName;
    let url = istream.readVarString();
    if (!url) {
      Log.error("CRInfo Deserialize: read url");
      return false;
    }
    this._url = url;
    let location = istream.readUIntOfBytesAsBN(8);
    if (!location) {
      Log.error("CRInfo Deserialize: read location");
      return false;
    }
    this._location = location;
    return true;
  }

  toJson(version: uint8_t): json {
    let j = {};
    j["Code"] = this._code.toString("hex");
    j["CID"] = Address.newFromAddressString(
      this._cid.bytes().toString()
    ).string();
    j["DID"] = Address.newFromAddressString(
      this._did.bytes().toString()
    ).string();
    j["NickName"] = this._nickName;
    j["Url"] = this._url;
    j["Location"] = this._location.toString();
    j["Signature"] = this._signature.toString("hex");
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    let code = j["Code"] as string;
    this._code = Buffer.from(code, "hex");

    let cid = j["CID"] as string;
    this._cid = Address.newFromAddressString(cid).programHash();

    let did = j["DID"] as string;
    this._did = Address.newFromAddressString(did).programHash();

    this._nickName = j["NickName"] as string;
    this._url = j["Url"] as string;
    this._location = new BigNumber(j["Location"] as string);

    this._signature = Buffer.from(j["Signature"] as string, "hex");
  }

  isValid(version: uint8_t): boolean {
    let stream = new ByteStream(this._code);
    let pubKey: bytes_t;
    pubKey = stream.readVarBytes(pubKey);
    let ostream = new ByteStream();
    this.serializeUnsigned(ostream, version);
    let digest = SHA256.encodeToBuffer(ostream.getBytes());
    return EcdsaSigner.verify(pubKey, this._signature, digest);
  }

  copyPayload(payload: Payload) {
    try {
      const crInfo = payload as CRInfo;
      this.copyCRInfo(crInfo);
    } catch (e) {
      Log.error("payload is not instance of CRInfo");
    }

    return this;
  }

  copyCRInfo(payload: CRInfo) {
    this._code = payload._code;
    this._cid = payload._cid;
    this._did = payload._did;
    this._nickName = payload._nickName;
    this._url = payload._url;
    this._location = payload._location;
    this._signature = payload._signature;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as CRInfo;
      let equal: boolean =
        this._code.toString() == p._code.toString() &&
        this._cid.bytes().toString() == p._cid.bytes().toString() &&
        this._nickName == p._nickName &&
        this._url == p._url &&
        this._location.eq(p._location) &&
        this._signature.toString() == p._signature.toString();

      if (version > CRInfoDIDVersion) {
        const rs = this._did.bytes().toString() == p._did.bytes().toString();
        equal = equal && rs;
      }

      return equal;
    } catch (e) {
      Log.error("payload is not instance of CRInfo");
    }

    return false;
  }
}
