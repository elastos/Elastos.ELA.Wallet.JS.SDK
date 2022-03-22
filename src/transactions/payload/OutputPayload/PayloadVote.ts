// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import BigNumber from "bignumber.js";
import { ErrorChecker } from "../../../common/ErrorChecker";
import { Log } from "../../../common/Log";
import { bytes_t, uint8_t, json, JSONArray, size_t } from "../../../types";
import { ByteStream } from "../../../common/bytestream";
import { OutputPayload } from "./OutputPayload";

export const VOTE_PRODUCER_CR_VERSION = 0x01;

export enum Type {
  Delegate,
  CRC,
  CRCProposal,
  CRCImpeachment,
  Max
}

export class CandidateVotes {
  private _candidate: bytes_t;
  private _votes: BigNumber;

  candidateVotes() {
    this._votes = new BigNumber(0);
  }

  newFromParams(candidate: bytes_t, votes: BigNumber) {
    this._votes = votes;
    this._candidate = candidate;
  }

  getCandidate(): bytes_t {
    return this._candidate;
  }

  getVotes(): BigNumber {
    return this._votes;
  }

  setVotes(votes: BigNumber) {
    this._votes = votes;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    ostream.writeVarBytes(this._candidate);

    if (version >= VOTE_PRODUCER_CR_VERSION) {
      ostream.writeBigNumber(this._votes);
    }
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    if (!istream.readVarBytes(this._candidate)) {
      Log.error("CandidateVotes deserialize candidate fail");
      return false;
    }

    if (version >= VOTE_PRODUCER_CR_VERSION) {
      let votes = istream.readUInt64();
      if (!votes) {
        Log.error("CandidateVotes deserialize votes fail");
        return false;
      }
      this._votes = new BigNumber(votes);
    }

    return true;
  }

  toJson(version: uint8_t): json {
    let j: json;
    j["Candidate"] = this._candidate.toString("hex");
    if (version >= VOTE_PRODUCER_CR_VERSION) {
      j["Votes"] = this._votes.toNumber();
    }
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._candidate = Buffer.from(j["Candidate"] as string, "hex");
    if (version >= VOTE_PRODUCER_CR_VERSION) {
      this._votes = new BigNumber(j["Votes"] as number);
    }
  }

  equals(cv: CandidateVotes): boolean {
    return (
      this._candidate.toString() == cv._candidate.toString() &&
      this._votes.isEqualTo(cv._votes)
    );
  }
}

export class VoteContent {
  private _type: Type;
  private _candidates: CandidateVotes[];

  constructor() {
    this._type = Type.Delegate;
  }

  newFromType(t: Type, c?: CandidateVotes[]) {
    this._type = t;
    if (c) {
      this._candidates = c;
    }
  }

  addCandidate(candidateVotes: CandidateVotes) {
    this._candidates.push(candidateVotes);
  }

  getType(): Type {
    return this._type;
  }

  getTypeString(): string {
    if (this._type == Type.CRC) {
      return "CRC";
    } else if (this._type == Type.Delegate) {
      return "Delegate";
    } else if (this._type == Type.CRCProposal) {
      return "CRCProposal";
    } else if (this._type == Type.CRCImpeachment) {
      return "CRCImpeachment";
    }

    return "Unknow";
  }

  setCandidateVotes(candidateVotes: CandidateVotes[]) {
    this._candidates = candidateVotes;
  }

  getCandidateVotes(): CandidateVotes[] {
    return this._candidates;
  }

  setAllCandidateVotes(votes: BigNumber) {
    for (let i = 0; i < this._candidates.length; ++i) {
      this._candidates[i].setVotes(votes);
    }
  }

  getMaxVoteAmount(): BigNumber {
    let max = new BigNumber(0);

    for (let i = 0; i < this._candidates.length; i++) {
      let item = this._candidates[i];
      if (max.isLessThan(item.getVotes())) {
        max = item.getVotes();
      }
    }

    return max;
  }

  getTotalVoteAmount(): BigNumber {
    let total = new BigNumber(0);

    for (let i = 0; i < this._candidates.length; i++) {
      total.plus(this._candidates[i].getVotes());
    }

    return total;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    ostream.writeUInt8(this._type);

    ostream.writeVarUInt(this._candidates.length);
    for (let i = 0; i < this._candidates.length; ++i) {
      this._candidates[i].serialize(ostream, version);
    }
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    let type: Type = 0;
    if (!istream.readUInt8(type)) {
      Log.error("VoteContent deserialize type error");
    }
    this._type = type;

    let size = istream.readVarUInt();
    if (size === null) {
      Log.error("VoteContent deserialize candidates count error");
      return false;
    }

    this._candidates = new Array(size.toNumber());
    for (let i = 0; i < size.toNumber(); ++i) {
      if (!this._candidates[i].deserialize(istream, version)) {
        Log.error("VoteContent deserialize candidates error");
        return false;
      }
    }

    return true;
  }

  toJson(version: uint8_t): json {
    let j: json;
    j["Type"] = this._type;

    let candidates: json[];
    for (let i = 0; i < this._candidates.length; ++i) {
      candidates.push(this._candidates[i].toJson(version));
    }
    j["Candidates"] = candidates;

    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._type = j["Type"] as Type;

    let candidates = j["Candidates"] as json[];
    this._candidates = new Array(candidates.length);
    for (let i = 0; i < candidates.length; ++i) {
      this._candidates[i].fromJson(candidates[i], version);
    }
  }

  equals(vc: VoteContent): boolean {
    return this._type == vc._type && this.isEqual(vc._candidates);
  }

  private isEqual(candidates: CandidateVotes[]) {
    if (this._candidates.length == candidates.length) {
      for (let i = 0; i < candidates.length; ++i) {
        if (!this._candidates[i].equals(candidates[i])) {
          return false;
        }
      }
      return true;
    } else {
      return false;
    }
  }
}

export class PayloadVote {
  private _version: uint8_t;
  private _content: VoteContent[];

  constructor(version: uint8_t, voteContents?: VoteContent[]) {
    this._version = version;
    if (voteContents) {
      this._content = voteContents;
    }
  }

  newFromPayloadVote(payload: PayloadVote) {
    this.copyPayloadVote(payload);
    return this;
  }

  setVoteContent(voteContent: VoteContent[]) {
    this._content = voteContent;
  }

  getVoteContent(): VoteContent[] {
    return this._content;
  }

  version(): uint8_t {
    return this._version;
  }

  estimateSize(): size_t {
    let stream = new ByteStream();
    let size: size_t = 0;

    size += 1;
    size += stream.writeVarUInt(this._content.length);
    for (let i = 0; i < this._content.length; i++) {
      let item = this._content[i];
      size += 1;
      size += stream.writeVarUInt(item.getCandidateVotes().length);

      const candidateVotes: CandidateVotes[] = item.getCandidateVotes();
      for (let j = 0; j < candidateVotes.length; j++) {
        let cv = candidateVotes[j];
        size += stream.writeVarUInt(cv.getCandidate().length);
        size += cv.getCandidate().length;

        if (this._version >= VOTE_PRODUCER_CR_VERSION) {
          size += stream.writeVarUInt(cv.getVotes().toNumber());
        }
      }
    }

    return size;
  }

  srialize(stream: ByteStream): void {
    stream.writeUInt8(this._version);

    stream.writeVarUInt(this._content.length);
    for (let i = 0; i < this._content.length; ++i) {
      this._content[i].serialize(stream, this._version);
    }
  }

  deserialize(stream: ByteStream): boolean {
    this._version = stream.readUInt8();
    if (this._version === null) {
      Log.error("payload vote deserialize version error");
      return false;
    }

    let contentCount = stream.readVarUInt();
    if (!contentCount) {
      Log.error("payload vote deserialize content count error");
      return false;
    }

    this._content = new Array(contentCount.toNumber());
    for (let i = 0; i < contentCount.toNumber(); ++i) {
      if (!this._content[i].deserialize(stream, this._version)) {
        Log.error("payload vote deserialize content error");
        return false;
      }
    }

    return true;
  }

  toJson(): json {
    let j: json;
    j["Version"] = this._version;

    let voteContent: json[];
    for (let i = 0; i < this._content.length; ++i) {
      voteContent.push(this._content[i].toJson(this._version));
    }
    j["VoteContent"] = voteContent;

    return j;
  }

  fromJson(j: json) {
    this._version = j["Version"] as uint8_t;
    let voteContent = j["VoteContent"] as json[];
    this._content = new Array(voteContent.length);

    for (let i = 0; i < voteContent.length; ++i) {
      this._content[i].fromJson(voteContent[i], this._version);
    }
  }

  copyPayloadVote(payload: PayloadVote) {
    try {
      this._version = payload._version;
      this._content = payload._content;
    } catch (e) {
      Log.error("payload is not instance of PayloadVote");
    }

    return this;
  }

  equals(payloadVote: PayloadVote): boolean {
    try {
      return (
        this._version == payloadVote._version &&
        this.isEqual(payloadVote._content)
      );
    } catch (e) {
      Log.error("payload is not instance of PayloadVote");
    }

    return false;
  }

  private isEqual(content: VoteContent[]) {
    if (this._content.length == content.length) {
      for (let i = 0; i < content.length; ++i) {
        if (!this._content[i].equals(content[i])) {
          return false;
        }
      }
      return true;
    } else {
      return false;
    }
  }
}
