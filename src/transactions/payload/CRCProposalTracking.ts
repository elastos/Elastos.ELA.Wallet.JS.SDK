/*
 * Copyright (c) 2019 Elastos Foundation
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
import {
  bytes_t,
  uint256,
  uint8_t,
  size_t,
  sizeof_uint256_t,
  sizeof_uint8_t,
  json
} from "../../types";
import { Address } from "../../walletcore/Address";
import { SHA256 } from "../../walletcore/sha256";
import { ByteStream } from "../../common/bytestream";
import { Payload } from "./Payload";
import { Error, ErrorChecker } from "../../common/ErrorChecker";
import { Log } from "../../common/Log";
import { BASE64 as Base64 } from "../../walletcore/base64";
import { EcdsaSigner } from "../../walletcore/ecdsasigner";

export const MESSAGE_DATA_MAX_SIZE = 800 * 1024;
export const OPINION_DATA_MAX_SIZE = 200 * 1024;

export const CRCProposalTrackingDefaultVersion = 0;
export const CRCProposalTrackingVersion01 = 0x01;

export const JsonKeyProposalHash = "ProposalHash";
export const JsonKeyMessageHash = "MessageHash";
export const JsonKeyMessageData = "MessageData";
export const JsonKeyStage = "Stage";
export const JsonKeyOwnerPublicKey = "OwnerPublicKey";
export const JsonKeyNewOwnerPublicKey = "NewOwnerPublicKey";
export const JsonKeyOwnerSignature = "OwnerSignature";
export const JsonKeyNewOwnerSignature = "NewOwnerSignature";
export const JsonKeyType = "Type";
export const JsonKeySecretaryGeneralOpinionHash = "SecretaryGeneralOpinionHash";
export const JsonKeySecretaryGeneralOpinionData = "SecretaryGeneralOpinionData";
export const JsonKeySecretaryGeneralSignature = "SecretaryGeneralSignature";

export enum CRCProposalTrackingType {
  common = 0x0000,
  progress = 0x01,
  rejected = 0x02,
  terminated = 0x03,
  changeOwner = 0x04,
  finalized = 0x05,
  unknowTrackingType
}

export class CRCProposalTracking extends Payload {
  private _proposalHash: uint256;
  private _messageHash: uint256;
  private _messageData: bytes_t;
  private _stage: uint8_t;
  private _ownerPubKey: bytes_t;
  private _newOwnerPubKey: bytes_t;
  private _ownerSign: bytes_t;
  private _newOwnerSign: bytes_t;
  private _type: CRCProposalTrackingType;
  private _secretaryGeneralOpinionHash: uint256;
  private _secretaryGeneralOpinionData: bytes_t;
  private _secretaryGeneralSignature: bytes_t;
  private _digestOwnerUnsigned: uint256;
  private _digestNewOwnerUnsigned: uint256;
  private _digestSecretaryUnsigned: uint256;

  setProposalHash(proposalHash: uint256) {
    this._proposalHash = proposalHash;
  }

  getProposalHash(): uint256 {
    return this._proposalHash;
  }

  setMessageHash(messageHash: uint256) {
    this._messageHash = messageHash;
  }

  getMessageHash(): uint256 {
    return this._messageHash;
  }

  setMessageData(data: bytes_t) {
    this._messageData = data;
  }

  getMessageData(): bytes_t {
    return this._messageData;
  }

  setStage(stage: uint8_t) {
    this._stage = stage;
  }

  getStage(): uint8_t {
    return this._stage;
  }

  setOwnerPubKey(ownerPubKey: bytes_t) {
    this._ownerPubKey = ownerPubKey;
  }

  getOwnerPubKey(): bytes_t {
    return this._ownerPubKey;
  }

  setNewOwnerPubKey(newOwnerPubKey: bytes_t) {
    this._newOwnerPubKey = newOwnerPubKey;
  }

  getNewOwnerPubKey(): bytes_t {
    return this._newOwnerPubKey;
  }

  setOwnerSign(signature: bytes_t) {
    this._ownerSign = signature;
  }

  getOwnerSign(): bytes_t {
    return this._ownerSign;
  }

  setNewOwnerSign(signature: bytes_t) {
    this._newOwnerSign = signature;
  }

  getNewOwnerSign(): bytes_t {
    return this._newOwnerSign;
  }

  setType(type: CRCProposalTrackingType) {
    this._type = type;
  }

  getType(): CRCProposalTrackingType {
    return this._type;
  }

  setSecretaryGeneralOpinionHash(hash: uint256) {
    this._secretaryGeneralOpinionHash = hash;
  }

  getSecretaryGeneralOpinionHash(): uint256 {
    return this._secretaryGeneralOpinionHash;
  }

  setSecretaryGeneralOpinionData(data: bytes_t) {
    this._secretaryGeneralOpinionData = data;
  }

  getSecretaryGeneralOpinionData(): bytes_t {
    return this._secretaryGeneralOpinionData;
  }

  setSecretaryGeneralSignature(signature: bytes_t) {
    this._secretaryGeneralSignature = signature;
  }

  getSecretaryGeneralSignature(): bytes_t {
    return this._secretaryGeneralSignature;
  }

  digestOwnerUnsigned(version: uint8_t): uint256 {
    if (this._digestOwnerUnsigned.isEqualTo(0)) {
      let stream = new ByteStream();
      this.serializeOwnerUnsigned(stream, version);
      let rs = SHA256.encodeToBuffer(stream.getBytes());
      this._digestOwnerUnsigned = new BigNumber(rs.toString("hex"), 16);
    }

    return this._digestOwnerUnsigned;
  }

  digestNewOwnerUnsigned(version: uint8_t): uint256 {
    if (this._digestNewOwnerUnsigned.isEqualTo(0)) {
      let stream = new ByteStream();
      this.serializeNewOwnerUnsigned(stream, version);
      let rs = SHA256.encodeToBuffer(stream.getBytes());
      this._digestNewOwnerUnsigned = new BigNumber(rs.toString("hex"), 16);
    }

    return this._digestNewOwnerUnsigned;
  }

  digestSecretaryUnsigned(version: uint8_t): uint256 {
    if (this._digestSecretaryUnsigned.isEqualTo(0)) {
      let stream = new ByteStream();
      this.serializeSecretaryUnsigned(stream, version);
      let rs = SHA256.encodeToBuffer(stream.getBytes());
      this._digestSecretaryUnsigned = new BigNumber(rs.toString("hex"), 16);
    }

    return this._digestSecretaryUnsigned;
  }

  estimateSize(version: uint8_t): size_t {
    let stream = new ByteStream();
    let size: size_t = 0;

    if (version >= CRCProposalTrackingVersion01) {
      size += stream.writeVarUInt(this._messageData.length);
      size += this._messageData.length;
      size += stream.writeVarUInt(this._secretaryGeneralOpinionData.length);
      size += this._secretaryGeneralOpinionData.length;
    }
    // size += this._proposalHash.size();
    size += sizeof_uint256_t();
    // size += this._messageHash.size();
    size += sizeof_uint256_t();

    // size += sizeof(uint8_t); // stage
    size += sizeof_uint8_t(); // stage

    size += stream.writeVarUInt(this._ownerPubKey.length);
    size += this._ownerPubKey.length;

    size += stream.writeVarUInt(this._newOwnerPubKey.length);
    size += this._newOwnerPubKey.length;

    size += stream.writeVarUInt(this._ownerSign.length);
    size += this._ownerSign.length;

    size += stream.writeVarUInt(this._newOwnerSign.length);
    size += this._newOwnerSign.length;

    size += sizeof_uint8_t(); // type

    // size += _secretaryGeneralOpinionHash.size();
    size += sizeof_uint256_t();

    size += stream.writeVarUInt(this._secretaryGeneralSignature.length);
    size += this._secretaryGeneralSignature.length;

    return size;
  }

  serializeOwnerUnsigned(stream: ByteStream, version: uint8_t) {
    stream.writeBNAsUIntOfSize(this._proposalHash, 32);
    stream.writeBNAsUIntOfSize(this._messageHash, 32);
    if (version >= CRCProposalTrackingVersion01) {
      stream.writeVarBytes(this._messageData);
    }

    stream.writeUInt8(this._stage);
    stream.writeVarBytes(this._ownerPubKey);
    stream.writeVarBytes(this._newOwnerPubKey);
  }

  deserializeOwnerUnsigned(stream: ByteStream, version: uint8_t): boolean {
    let programHash = stream.readUIntOfBytesAsBN(32);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize proposal hash");
      return false;
    }
    this._proposalHash = programHash;

    let messageHash = stream.readUIntOfBytesAsBN(32);
    if (!messageHash) {
      // SPVLOG_ERROR("deserialize document hash");
      return false;
    }
    this._messageHash = messageHash;

    if (version >= CRCProposalTrackingVersion01) {
      let messageData: bytes_t;
      messageData = stream.readVarBytes(messageData);
      if (!messageData) {
        // SPVLOG_ERROR("deserialize msg data");
        return false;
      }
      this._messageData = messageData;
    }

    let stage = stream.readUInt8();
    if (!stage) {
      // SPVLOG_ERROR("deserialize stage");
      return false;
    }
    this._stage = stage;

    let ownerPubKey: bytes_t;
    ownerPubKey = stream.readVarBytes(this._ownerPubKey);
    if (!ownerPubKey) {
      // SPVLOG_ERROR("deserialize owner public key");
      return false;
    }
    this._ownerPubKey = ownerPubKey;

    let newOwnerPubKey: bytes_t;
    newOwnerPubKey = stream.readVarBytes(newOwnerPubKey);
    if (!newOwnerPubKey) {
      // SPVLOG_ERROR("deserialize new owner public key");
      return false;
    }
    this._newOwnerPubKey = newOwnerPubKey;

    return true;
  }

  serializeNewOwnerUnsigned(stream: ByteStream, version: uint8_t) {
    this.serializeOwnerUnsigned(stream, version);

    stream.writeVarBytes(this._ownerSign);
  }

  deserializeNewOwnerUnsigned(stream: ByteStream, version: uint8_t): boolean {
    if (!this.deserializeOwnerUnsigned(stream, version)) return false;

    if (!stream.readVarBytes(this._ownerSign)) {
      // SPVLOG_ERROR("deserialize owner sign");
      return false;
    }

    return true;
  }

  serializeSecretaryUnsigned(stream: ByteStream, version: uint8_t) {
    this.serializeNewOwnerUnsigned(stream, version);
    stream.writeVarBytes(this._newOwnerSign);
    stream.writeUInt8(this._type);
    // stream.writeBytes(this._secretaryGeneralOpinionHash);
    stream.writeBNAsUIntOfSize(this._secretaryGeneralOpinionHash, 32);
    if (version >= CRCProposalTrackingVersion01) {
      stream.writeVarBytes(this._secretaryGeneralOpinionData);
    }
  }

  deserializeSecretaryUnsigned(stream: ByteStream, version: uint8_t): boolean {
    if (!this.deserializeNewOwnerUnsigned(stream, version)) {
      return false;
    }

    let newOwnerSign: bytes_t;
    newOwnerSign = stream.readVarBytes(newOwnerSign);
    if (!newOwnerSign) {
      // SPVLOG_ERROR("deserialize new owner sign");
      return false;
    }
    this._newOwnerPubKey = newOwnerSign;

    let type: uint8_t = stream.readUInt8();
    if (!type) {
      // SPVLOG_ERROR("deserialize type");
      return false;
    }
    this._type = type as CRCProposalTrackingType;

    let secretaryGeneralOpinionHash = stream.readUIntOfBytesAsBN(32);
    if (!secretaryGeneralOpinionHash) {
      // SPVLOG_ERROR("deserialize secretary opinion hash");
      return false;
    }
    this._secretaryGeneralOpinionHash = secretaryGeneralOpinionHash;

    if (version >= CRCProposalTrackingVersion01) {
      let secretaryGeneralOpinionData: bytes_t;
      secretaryGeneralOpinionData = stream.readVarBytes(
        secretaryGeneralOpinionData
      );
      if (!secretaryGeneralOpinionData) {
        // SPVLOG_ERROR("deserialize secretary opinion data");
        return false;
      }
      this._secretaryGeneralOpinionData = secretaryGeneralOpinionData;
    }

    return true;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    this.serializeSecretaryUnsigned(stream, version);
    stream.writeVarBytes(this._secretaryGeneralSignature);
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    if (!this.deserializeSecretaryUnsigned(istream, version)) {
      // SPVLOG_ERROR("deserialize secretary unsigned");
      return false;
    }

    let secretaryGeneralSignature: bytes_t;
    secretaryGeneralSignature = istream.readVarBytes(secretaryGeneralSignature);
    if (!secretaryGeneralSignature) {
      // SPVLOG_ERROR("deserialize secretary signature");
      return false;
    }
    this._secretaryGeneralSignature = secretaryGeneralSignature;

    return true;
  }

  toJsonOwnerUnsigned(version: uint8_t): json {
    let j: json = {};
    j[JsonKeyProposalHash] = this._proposalHash.toString(16);
    j[JsonKeyMessageHash] = this._messageHash.toString(16);
    if (version >= CRCProposalTrackingVersion01) {
      j[JsonKeyMessageData] = Base64.encode(this._messageData.toString("hex"));
    }

    j[JsonKeyStage] = this._stage;
    j[JsonKeyOwnerPublicKey] = this._ownerPubKey.toString("hex");
    j[JsonKeyNewOwnerPublicKey] = this._newOwnerPubKey.toString("hex");
    return j;
  }

  fromJsonOwnerUnsigned(j: json, version: uint8_t) {
    this._proposalHash = new BigNumber(j[JsonKeyProposalHash] as string, 16);
    this._messageHash = new BigNumber(j[JsonKeyMessageHash] as string, 16);
    if (version >= CRCProposalTrackingVersion01) {
      let messageData = j[JsonKeyMessageData] as string;
      this._messageData = Buffer.from(Base64.decode(messageData), "hex");
      ErrorChecker.checkParam(
        this._messageData.length > MESSAGE_DATA_MAX_SIZE,
        Error.Code.ProposalContentTooLarge,
        "message data size too large"
      );
      let hash = SHA256.hashTwice(this._messageData).toString("hex");
      let messageHash = new BigNumber(hash, 16);
      ErrorChecker.checkParam(
        !this._messageHash.isEqualTo(messageHash),
        Error.Code.ProposalHashNotMatch,
        "message hash not match"
      );
    }
    this._stage = j[JsonKeyStage] as number;
    this._ownerPubKey = Buffer.from(j[JsonKeyOwnerPublicKey] as string, "hex");
    this._newOwnerPubKey = Buffer.from(
      j[JsonKeyNewOwnerPublicKey] as string,
      "hex"
    );
  }

  toJsonNewOwnerUnsigned(version: uint8_t): json {
    let j: json = this.toJsonOwnerUnsigned(version);
    j[JsonKeyOwnerSignature] = this._ownerSign.toString("hex");
    return j;
  }

  fromJsonNewOwnerUnsigned(j: json, version: uint8_t) {
    this.fromJsonOwnerUnsigned(j, version);
    this._ownerSign = Buffer.from(j[JsonKeyOwnerSignature] as string, "hex");
  }

  toJsonSecretaryUnsigned(version: uint8_t): json {
    let j: json = this.toJsonNewOwnerUnsigned(version);
    j[JsonKeyNewOwnerSignature] = this._newOwnerSign.toString("hex");
    j[JsonKeyType] = this._type;
    j[JsonKeySecretaryGeneralOpinionHash] =
      this._secretaryGeneralOpinionHash.toString(16);
    if (version >= CRCProposalTrackingVersion01) {
      j[JsonKeySecretaryGeneralOpinionData] = Base64.encode(
        this._secretaryGeneralOpinionData.toString("hex")
      );
    }

    return j;
  }

  fromJsonSecretaryUnsigned(j: json, version: uint8_t) {
    this.fromJsonNewOwnerUnsigned(j, version);
    this._newOwnerSign = Buffer.from(
      j[JsonKeyNewOwnerSignature] as string,
      "hex"
    );
    this._type = j[JsonKeyType] as CRCProposalTrackingType;
    this._secretaryGeneralOpinionHash = new BigNumber(
      j[JsonKeySecretaryGeneralOpinionHash] as string,
      16
    );
    if (version >= CRCProposalTrackingVersion01) {
      let data = j[JsonKeySecretaryGeneralOpinionData] as string;
      this._secretaryGeneralOpinionData = Buffer.from(
        Base64.decode(data),
        "hex"
      );
      ErrorChecker.checkParam(
        this._secretaryGeneralOpinionData.length > OPINION_DATA_MAX_SIZE,
        Error.Code.ProposalContentTooLarge,
        "opinion data size too large"
      );
      let hash = SHA256.hashTwice(this._secretaryGeneralOpinionData);
      let opinionHash = new BigNumber(hash.toString("hex"), 16);
      ErrorChecker.checkParam(
        !opinionHash.isEqualTo(this._secretaryGeneralOpinionHash),
        Error.Code.ProposalHashNotMatch,
        "opinion hash not match"
      );
    }
  }

  toJson(version: uint8_t): json {
    let j = this.toJsonSecretaryUnsigned(version);
    j[JsonKeySecretaryGeneralSignature] =
      this._secretaryGeneralSignature.toString("hex");
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this.fromJsonSecretaryUnsigned(j, version);

    this._secretaryGeneralSignature = Buffer.from(
      j[JsonKeySecretaryGeneralSignature] as string,
      "hex"
    );
  }

  isValidOwnerUnsigned(version: uint8_t): boolean {
    if (this._stage > 127) {
      // SPVLOG_ERROR("invalid stage");
      return false;
    }

    try {
      // Key key(CTElastos, _ownerPubKey);
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPubKey);
    } catch (e) {
      // SPVLOG_ERROR("invalid owner pubkey");
      return false;
    }

    if (this._newOwnerPubKey) {
      try {
        // Key key(CTElastos, _newOwnerPubKey);
        let key = EcdsaSigner.getKeyFromPublic(this._newOwnerPubKey);
      } catch (e) {
        // SPVLOG_ERROR("invalid new owner pubkey");
        return false;
      }
    }

    return true;
  }

  isValidNewOwnerUnsigned(version: uint8_t): boolean {
    if (!this.isValidOwnerUnsigned(version)) return false;

    // verify signature of owner
    try {
      if (
        !EcdsaSigner.verify(
          this._ownerPubKey,
          this._ownerSign,
          Buffer.from(this.digestOwnerUnsigned(version).toString(16), "hex")
        )
      ) {
        // SPVLOG_ERROR("verify owner sign fail");
        return false;
      }
    } catch (e) {
      // SPVLOG_ERROR("versify new owner sign exception: {}", e.what());
      return false;
    }

    return true;
  }

  isValidSecretaryUnsigned(version: uint8_t): boolean {
    if (!this.isValidNewOwnerUnsigned(version)) return false;

    // verify signature of new owner
    if (this._newOwnerPubKey) {
      try {
        if (
          !EcdsaSigner.verify(
            this._newOwnerPubKey,
            this._newOwnerSign,
            Buffer.from(
              this.digestNewOwnerUnsigned(version).toString(16),
              "hex"
            )
          )
        ) {
          // SPVLOG_ERROR("verify new owner sign fail");
          return false;
        }
      } catch (e) {
        // SPVLOG_ERROR("verify new owner sign exception: {}", e.what());
        return false;
      }
    }

    if (this._type >= CRCProposalTrackingType.unknowTrackingType) {
      // SPVLOG_ERROR("unknow type: {}", _type);
      return false;
    }

    return true;
  }

  isValid(version: uint8_t): boolean {
    if (!this.isValidSecretaryUnsigned(version)) return false;

    if (!this._secretaryGeneralSignature) {
      // SPVLOG_ERROR("secretary signature is empty");
      return false;
    }

    return true;
  }

  copyPayload(payload: Payload) {
    try {
      const tracking = payload as CRCProposalTracking;
      this.copyCRCProposalTracking(tracking);
    } catch (e) {
      // SPVLOG_ERROR("payload is not instance of CRCProposalTracking");
    }
    return this;
  }

  copyCRCProposalTracking(payload: CRCProposalTracking) {
    this._proposalHash = payload._proposalHash;
    this._messageHash = payload._messageHash;
    this._messageData = payload._messageData;
    this._stage = payload._stage;
    this._ownerPubKey = payload._ownerPubKey;
    this._newOwnerPubKey = payload._newOwnerPubKey;
    this._ownerSign = payload._ownerSign;
    this._newOwnerSign = payload._newOwnerSign;
    this._type = payload._type;
    this._secretaryGeneralOpinionHash = payload._secretaryGeneralOpinionHash;
    this._secretaryGeneralOpinionData = payload._secretaryGeneralOpinionData;
    this._secretaryGeneralSignature = payload._secretaryGeneralSignature;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as CRCProposalTracking;
      let equal: boolean =
        this._proposalHash.isEqualTo(p._proposalHash) &&
        this._messageHash.isEqualTo(p._messageHash) &&
        this._stage == p._stage &&
        this._ownerPubKey.toString() == p._ownerPubKey.toString() &&
        this._newOwnerPubKey.toString() == p._newOwnerPubKey.toString() &&
        this._ownerSign.toString() == p._ownerSign.toString() &&
        this._newOwnerSign.toString() == p._newOwnerSign.toString() &&
        this._type == p._type &&
        this._secretaryGeneralOpinionHash.isEqualTo(
          p._secretaryGeneralOpinionHash
        ) &&
        this._secretaryGeneralSignature.toString() ==
          p._secretaryGeneralSignature.toString();

      if (version >= CRCProposalTrackingVersion01) {
        equal =
          equal &&
          this._messageData.toString() == p._messageData.toString() &&
          this._secretaryGeneralOpinionData.toString() ==
            p._secretaryGeneralOpinionData.toString();
      }

      return equal;
    } catch (e) {
      Log.error("payload is not instance of CRCProposalTracking");
    }

    return false;
  }
}
