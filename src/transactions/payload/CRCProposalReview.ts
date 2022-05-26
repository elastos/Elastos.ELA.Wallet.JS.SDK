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
import { Buffer } from "buffer";
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

export const CRCProposalReviewDefaultVersion = 0;
export const CRCProposalReviewVersion01 = 0x01;

export const JsonKeyProposalHash = "ProposalHash";
export const JsonKeyVoteResult = "VoteResult";
export const JsonKeyOpinionHash = "OpinionHash";
export const JsonKeyOpinionData = "OpinionData";
export const JsonKeyDID = "DID";
export const JsonKeySignature = "Signature";

export const OPINION_DATA_MAX_SIZE = 1024 * 1024;

export enum VoteResult {
  approve = 0x00,
  reject = 0x01,
  abstain = 0x02,
  unknownVoteResult
}

export class CRCProposalReview extends Payload {
  private _proposalHash: uint256;
  private _voteResult: VoteResult;
  private _opinionHash: uint256;
  private _opinionData: bytes_t;
  private _did: Address;
  private _signature: bytes_t;
  private _digest: uint256;

  setProposalHash(hash: uint256) {
    this._proposalHash = hash;
  }

  getProposalHash(): uint256 {
    return this._proposalHash;
  }

  setVoteResult(voteResult: VoteResult) {
    this._voteResult = voteResult;
  }

  getVoteResult(): VoteResult {
    return this._voteResult;
  }

  setOpinionHash(hash: uint256) {
    this._opinionHash = hash;
  }

  getOpinionHash(): uint256 {
    return this._opinionHash;
  }

  setOpinionData(data: bytes_t) {
    this._opinionData = data;
  }

  getOpinionData(): bytes_t {
    return this._opinionData;
  }

  setDID(DID: Address) {
    this._did = DID;
  }

  getDID(): Address {
    return this._did;
  }

  setSignature(signature: bytes_t) {
    this._signature = signature;
  }

  getSignature(): bytes_t {
    return this._signature;
  }

  digestUnsigned(version: uint8_t): uint256 {
    if (this._digest.isZero()) {
      let stream = new ByteStream();
      this.serializeUnsigned(stream, version);
      const rs = SHA256.encodeToBuffer(stream.getBytes());
      this._digest = new BigNumber(rs.toString("hex"), 16);
    }
    return this._digest;
  }

  estimateSize(version: uint8_t): size_t {
    let stream = new ByteStream();
    let size: size_t = 0;

    // size += this._proposalHash.size();
    size += sizeof_uint256_t();
    // size += sizeof(uint8_t);
    size += sizeof_uint8_t();
    // size += this._opinionHash.size();
    size += sizeof_uint256_t();
    if (version >= CRCProposalReviewVersion01) {
      size += stream.writeVarUInt(this._opinionData.length);
      size += this._opinionData.length;
    }
    size += this._did.programHash().bytes().length;
    size += stream.writeVarUInt(this._signature.length);
    size += this._signature.length;

    return size;
  }

  serializeUnsigned(stream: ByteStream, version: uint8_t) {
    stream.writeBNAsUIntOfSize(this._proposalHash, 32);
    stream.writeUInt8(this._voteResult);
    stream.writeBNAsUIntOfSize(this._opinionHash, 32);
    if (version >= CRCProposalReviewVersion01) {
      stream.writeVarBytes(this._opinionData);
    }

    stream.writeBytes(this._did.programHash().bytes());
  }

  deserializeUnsigned(stream: ByteStream, version: uint8_t): boolean {
    let proposalHash = stream.readUIntOfBytesAsBN(32);
    if (!proposalHash) {
      // SPVLOG_ERROR("deserialize proposal hash");
      return false;
    }
    this._proposalHash = proposalHash;

    let opinion = stream.readUInt8();
    if (!opinion) {
      // SPVLOG_ERROR("deserialize opinion");
      return false;
    }
    this._voteResult = opinion as VoteResult;

    let opinionHash = stream.readUIntOfBytesAsBN(32);
    if (!opinionHash) {
      // SPVLOG_ERROR("desrialize opinion hash");
      return false;
    }
    this._opinionHash = opinionHash;

    if (version >= CRCProposalReviewVersion01) {
      let opinionData = Buffer.alloc(0);
      opinionData = stream.readVarBytes(opinionData);
      if (!opinionData) {
        // SPVLOG_ERROR("deserialize opinion data");
        return false;
      }
      this._opinionData = opinionData;
    }

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize did");
      return false;
    }
    this._did = Address.newFromAddressString(programHash.toString("hex"));

    return true;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    this.serializeUnsigned(ostream, version);
    ostream.writeVarBytes(this._signature);
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    if (!this.deserializeUnsigned(istream, version)) {
      // SPVLOG_ERROR("proposal review deserialize unsigned");
      return false;
    }

    let signature: bytes_t;
    signature = istream.readVarBytes(signature);
    if (!signature) {
      // SPVLOG_ERROR("proposal review deserialize signature");
      return false;
    }
    this._signature = signature;
    return true;
  }

  toJsonUnsigned(version: uint8_t): json {
    let j: json = {};
    j[JsonKeyProposalHash] = this._proposalHash.toString(16);
    j[JsonKeyVoteResult] = this._voteResult;
    j[JsonKeyOpinionHash] = this._opinionHash.toString(16);
    if (version >= CRCProposalReviewVersion01)
      j[JsonKeyOpinionData] = Base64.encode(this._opinionData.toString("hex"));
    j[JsonKeyDID] = this._did.string();
    return j;
  }

  fromJsonUnsigned(j: json, version: uint8_t) {
    this._proposalHash = new BigNumber(j[JsonKeyProposalHash] as string, 16);
    this._voteResult = j[JsonKeyVoteResult] as VoteResult;
    this._opinionHash = new BigNumber(j[JsonKeyOpinionHash] as string, 16);
    if (version >= CRCProposalReviewVersion01) {
      let opinionData = j[JsonKeyOpinionData] as string;
      this._opinionData = Buffer.from(Base64.decode(opinionData), "hex");
      ErrorChecker.checkParam(
        this._opinionData.length > OPINION_DATA_MAX_SIZE,
        Error.Code.ProposalContentTooLarge,
        "opinion hash too large"
      );
      let opinionHash = SHA256.hashTwice(this._opinionData).toString("hex");
      ErrorChecker.checkParam(
        this._opinionHash.isEqualTo(new BigNumber(opinionHash, 16)),
        Error.Code.ProposalHashNotMatch,
        "opinion hash not match"
      );
    }
    this._did = Address.newFromAddressString(j[JsonKeyDID] as string);
  }

  toJson(version: uint8_t): json {
    let j: json = this.toJsonUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this.fromJsonUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature] as string);
  }

  isValidUnsigned(version: uint8_t): boolean {
    if (this._voteResult >= VoteResult.unknownVoteResult) {
      // SPVLOG_ERROR("invalid opinion: {}", _voteResult);
      return false;
    }

    if (!this._did.valid()) {
      // SPVLOG_ERROR("invalid committee did");
      return false;
    }

    return true;
  }

  isValid(version: uint8_t): boolean {
    if (!this.isValidUnsigned(version)) return false;

    if (this._signature.length === 0) {
      // SPVLOG_ERROR("signature is empty");
      return false;
    }

    return true;
  }

  copyPayload(payload: Payload) {
    try {
      const review = payload as CRCProposalReview;
      this.copyCRCProposalReview(review);
    } catch (e) {
      // SPVLOG_ERROR("payload is not instance of CRCProposalReview");
    }
    return this;
  }

  copyCRCProposalReview(payload: CRCProposalReview) {
    this._proposalHash = payload._proposalHash;
    this._voteResult = payload._voteResult;
    this._opinionHash = payload._opinionHash;
    this._opinionData = payload._opinionData;
    this._did = payload._did;
    this._signature = payload._signature;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as CRCProposalReview;
      let equal: boolean =
        this._proposalHash.isEqualTo(p._proposalHash) &&
        this._voteResult == p._voteResult &&
        this._opinionHash.isEqualTo(p._opinionHash) &&
        this._did.equals(p._did) &&
        this._signature.toString() == p._signature.toString();

      if (version >= CRCProposalReviewVersion01) {
        let isEqual = this._opinionData.toString() == p._opinionData.toString();
        equal = equal && isEqual;
      }

      return equal;
    } catch (e) {
      Log.error("payload is not instance of CRCProposalReview");
    }

    return false;
  }
}
