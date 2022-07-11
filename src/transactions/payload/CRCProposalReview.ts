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
import { Buffer } from "buffer";
import BigNumber from "bignumber.js";
import {
  bytes_t,
  uint256,
  uint8_t,
  size_t,
  sizeof_uint256_t,
  sizeof_uint8_t
} from "../../types";
import { Address } from "../../walletcore/Address";
import { SHA256 } from "../../walletcore/sha256";
import { ByteStream } from "../../common/bytestream";
import { Payload } from "./Payload";
import { Error, ErrorChecker } from "../../common/ErrorChecker";
import { Log } from "../../common/Log";
import { uint168 } from "../../common/uint168";
import { reverseHashString } from "../../common/utils";
import { getBNHexString } from "../../common/bnutils";

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

export type CRCProposalReviewInfo = {
  ProposalHash: string;
  VoteResult: number;
  OpinionHash: string;
  OpinionData?: string;
  DID: string;
  Signature?: string;
};

export class CRCProposalReview extends Payload {
  private _proposalHash: uint256;
  private _voteResult: VoteResult;
  private _opinionHash: uint256;
  private _opinionData: bytes_t;
  private _did: Address;
  private _signature: bytes_t;
  private _digest: string;

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

  digestUnsigned(version: uint8_t): string {
    if (!this._digest) {
      let stream = new ByteStream();
      this.serializeUnsigned(stream, version);
      const rs = SHA256.encodeToBuffer(stream.getBytes());

      this._digest = rs.toString("hex");
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
      Log.error("deserialize proposal hash");
      return false;
    }
    this._proposalHash = proposalHash;

    let opinion = stream.readUInt8();
    if (!opinion && opinion !== VoteResult.approve) {
      Log.error("deserialize opinion");
      return false;
    }
    this._voteResult = opinion as VoteResult;

    let opinionHash = stream.readUIntOfBytesAsBN(32);
    if (!opinionHash) {
      Log.error("desrialize opinion hash");
      return false;
    }
    this._opinionHash = opinionHash;

    if (version >= CRCProposalReviewVersion01) {
      let opinionData: bytes_t;
      opinionData = stream.readVarBytes(opinionData);
      if (!opinionData) {
        Log.error("deserialize opinion data");
        return false;
      }
      this._opinionData = opinionData;
    }

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize did");
      return false;
    }

    this._did = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    return true;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    this.serializeUnsigned(ostream, version);
    ostream.writeVarBytes(this._signature);
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    if (!this.deserializeUnsigned(istream, version)) {
      Log.error("proposal review deserialize unsigned");
      return false;
    }

    let signature: bytes_t;
    signature = istream.readVarBytes(signature);
    if (!signature) {
      Log.error("proposal review deserialize signature");
      return false;
    }
    this._signature = signature;
    return true;
  }

  toJsonUnsigned(version: uint8_t) {
    let j = <CRCProposalReviewInfo>{};
    j[JsonKeyProposalHash] = reverseHashString(
      getBNHexString(this._proposalHash)
    );
    j[JsonKeyVoteResult] = this._voteResult;
    j[JsonKeyOpinionHash] = reverseHashString(
      getBNHexString(this._opinionHash)
    );
    if (version >= CRCProposalReviewVersion01) {
      // sync with dev branch of wallet c++ sdk
      j[JsonKeyOpinionData] = this._opinionData.toString("hex");
    }

    j[JsonKeyDID] = this._did.string();
    return j;
  }

  fromJsonUnsigned(j: CRCProposalReviewInfo, version: uint8_t) {
    this._proposalHash = new BigNumber(j[JsonKeyProposalHash], 16);
    this._voteResult = j[JsonKeyVoteResult] as VoteResult;
    this._opinionHash = new BigNumber(j[JsonKeyOpinionHash], 16);
    if (version >= CRCProposalReviewVersion01) {
      let opinionData = j[JsonKeyOpinionData];
      this._opinionData = Buffer.from(opinionData, "hex");
      ErrorChecker.checkParam(
        this._opinionData.length > OPINION_DATA_MAX_SIZE,
        Error.Code.ProposalContentTooLarge,
        "opinion hash too large"
      );
      let opinionHash = SHA256.hashTwice(this._opinionData).toString("hex");
      opinionHash = reverseHashString(opinionHash);
      ErrorChecker.checkParam(
        !this._opinionHash.eq(new BigNumber(opinionHash, 16)),
        Error.Code.ProposalHashNotMatch,
        "opinion hash not match"
      );
    }
    this._did = Address.newFromAddressString(j[JsonKeyDID]);
  }

  toJson(version: uint8_t): CRCProposalReviewInfo {
    let j = this.toJsonUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    return j;
  }

  fromJson(j: CRCProposalReviewInfo, version: uint8_t) {
    this.fromJsonUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature], "hex");
  }

  isValidUnsigned(version: uint8_t): boolean {
    if (this._voteResult >= VoteResult.unknownVoteResult) {
      Log.error("invalid opinion: {}", this._voteResult);
      return false;
    }

    if (!this._did.valid()) {
      Log.error("invalid committee did");
      return false;
    }

    return true;
  }

  isValid(version: uint8_t): boolean {
    if (!this.isValidUnsigned(version)) return false;

    if (this._signature.length === 0) {
      Log.error("signature is empty");
      return false;
    }

    return true;
  }

  copyPayload(payload: Payload) {
    try {
      const review = payload as CRCProposalReview;
      this.copyCRCProposalReview(review);
    } catch (e) {
      Log.error("payload is not instance of CRCProposalReview");
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
        this._proposalHash.eq(p._proposalHash) &&
        this._voteResult == p._voteResult &&
        this._opinionHash.eq(p._opinionHash) &&
        this._did.equals(p._did) &&
        this._signature.equals(p._signature);

      if (version >= CRCProposalReviewVersion01) {
        equal = equal && this._opinionData.equals(p._opinionData);
      }

      return equal;
    } catch (e) {
      Log.error("payload is not instance of CRCProposalReview");
    }

    return false;
  }
}
