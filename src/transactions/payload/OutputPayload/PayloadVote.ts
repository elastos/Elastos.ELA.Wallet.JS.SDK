// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
import BigNumber from "bignumber.js";
import { Buffer } from "buffer";
import { ByteStream } from "../../../common/bytestream";
import { Log } from "../../../common/Log";
import {
  bytes_t, json,
  JSONArray, size_t,
  uint64_t,
  uint8_t
} from "../../../types";
import { OutputPayload } from "../OutputPayload/OutputPayload";

export const VOTE_PRODUCER_CR_VERSION = 0x01;
export type VoteContentArray = VoteContent[];

export class CandidateVotes {
  private _candidate: bytes_t;
  private _votes: BigNumber;
  constructor() {
    this._votes = new BigNumber(0);
  }

  static newFromParams(candidate: bytes_t, votes: BigNumber) {
    const cv = new CandidateVotes();
    cv._candidate = candidate;
    cv._votes = new BigNumber(votes);
    return cv;
  }

  getCandidate(): bytes_t {
    return this._candidate;
  }

  getVotes(): BigNumber {
    return this._votes;
  }

  setVotes(votes: uint64_t) {
    this._votes = votes;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    ostream.writeVarBytes(this._candidate);

    if (version >= VOTE_PRODUCER_CR_VERSION) {
      ostream.writeBNAsUIntOfSize(this._votes, 8);
    }
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    let candidate: bytes_t;
    candidate = istream.readVarBytes(candidate);
    if (!candidate) {
      Log.error("CandidateVotes deserialize candidate fail");
      return false;
    }
    this._candidate = candidate;

    if (version >= VOTE_PRODUCER_CR_VERSION) {
      let votes = istream.readUIntOfBytesAsBN(8);
      if (!votes) {
        Log.error("CandidateVotes deserialize votes fail");
        return false;
      }
      this._votes = votes;
    }

    return true;
  }

  toJson(version: uint8_t): json {
    let j: json = {};
    j["Candidate"] = this._candidate.toString("hex");
    if (version >= VOTE_PRODUCER_CR_VERSION) {
      j["Votes"] = this._votes.toString();
    }
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._candidate = Buffer.from(j["Candidate"] as string, "hex");
    if (version >= VOTE_PRODUCER_CR_VERSION) {
      this._votes = new BigNumber(j["Votes"] as string);
    }
  }

  equals(cv: CandidateVotes): boolean {
    return this._candidate == cv._candidate && this._votes == cv._votes;
  }
}
export enum VoteContentType {
  Delegate,
  CRC,
  CRCProposal,
  CRCImpeachment,
  Max
}

export class VoteContent {
  private _type: VoteContentType;
  private _candidates: CandidateVotes[];
  constructor() {
    this._type = VoteContentType.Delegate;
  }

  static newFromType(t: VoteContentType) {
    const vc = new VoteContent();
    vc._type = t;
    return vc;
  }

  static newFromVoteContent(t: VoteContentType, c: CandidateVotes[]) {
    const vc = new VoteContent();
    vc._type = t;
    vc._candidates = c;
    return vc;
  }

  addCandidate(candidateVotes: CandidateVotes) {
    this._candidates.push(candidateVotes);
  }

  getType(): VoteContentType {
    return this._type;
  }

  getTypeString(): string {
    if (this._type == VoteContentType.CRC) {
      return "CRC";
    } else if (this._type == VoteContentType.Delegate) {
      return "Delegate";
    } else if (this._type == VoteContentType.CRCProposal) {
      return "CRCProposal";
    } else if (this._type == VoteContentType.CRCImpeachment) {
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

  setAllCandidateVotes(votes: uint64_t) {
    for (let i = 0; i < this._candidates.length; ++i) {
      this._candidates[i].setVotes(votes);
    }
  }

  getMaxVoteAmount(): BigNumber {
    let max = new BigNumber(0);

    for (let i = 0; i < this._candidates.length; i++) {
      if (max < this._candidates[i].getVotes()) {
        max = this._candidates[i].getVotes();
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
    for (let i = 0; i < this._candidates.length; i++) {
      this._candidates[i].serialize(ostream, version);
    }
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    let type = istream.readUInt8();
    if (!type) {
      Log.error("VoteContent deserialize type error");
    }
    this._type = type;

    let size = new BigNumber(0);
    size = istream.readVarUInt();
    if (!size) {
      Log.error("VoteContent deserialize candidates count error");
      return false;
    }

    let candidates: CandidateVotes[] = [];
    for (let i = 0; i < size.toNumber(); ++i) {
      if (!candidates[i].deserialize(istream, version)) {
        Log.error("VoteContent deserialize candidates error");
        return false;
      }
    }

    return true;
  }

  toJson(version: uint8_t): json {
    let j: json = {};
    j["Type"] = this._type;

    let candidates: JSONArray;
    for (let i = 0; i < this._candidates.length; ++i) {
      candidates.push(this._candidates[i].toJson(version));
    }
    j["Candidates"] = candidates;

    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._type = j["Type"] as VoteContentType;

    let candidates = j["Candidates"] as [];
    for (let i = 0; i < candidates.length; ++i) {
      this._candidates[i].fromJson(candidates[i], version);
    }
  }

  isEqual(candidates: CandidateVotes[]): boolean {
    for (let i = 0; i < candidates.length; ++i) {
      if (!this._candidates[i].equals(candidates[i])) {
        return false;
      }
    }
    return true;
  }

  equals(vc: VoteContent): boolean {
    return this._type == vc._type && this.isEqual(vc._candidates);
  }
}

export class PayloadVote extends OutputPayload {
  private _version: uint8_t;
  private _content: VoteContent[];

  static newFromVersion(version: uint8_t) {
    const payloadVote = new PayloadVote();
    payloadVote._version = version;
    return payloadVote;
  }

  static newFromParams(voteContents: VoteContent[], version: uint8_t) {
    const payloadVote = new PayloadVote();
    payloadVote._content = voteContents;
    payloadVote._version = version;
    return payloadVote;
  }

  static newFromPayloadVote(payload: PayloadVote) {
    const payloadVote = new PayloadVote();
    return payloadVote.copyPayloadVote(payload);
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
    for (let i = 0; i < this._content.length; ++i) {
      size += 1;
      size += stream.writeVarUInt(this._content[i].getCandidateVotes().length);

      let candidateVotes = this._content[i].getCandidateVotes();

      for (let i = 0; i < candidateVotes.length; ++i) {
        size += stream.writeVarUInt(candidateVotes[i].getCandidate().length);
        size += candidateVotes[i].getCandidate().length;

        if (this._version >= VOTE_PRODUCER_CR_VERSION) {
          size += stream.writeVarUInt(candidateVotes[i].getVotes().toNumber());
        }
      }
    }

    return size;
  }

  serialize(stream: ByteStream) {
    stream.writeUInt8(this._version);

    stream.writeVarUInt(this._content.length);
    for (let i = 0; i < this._content.length; ++i) {
      this._content[i].serialize(stream, this._version);
    }
  }

  deserialize(stream: ByteStream) {
    if (!stream.readUInt8(this._version)) {
      Log.error("payload vote deserialize version error");
      return false;
    }

    let contentCount = stream.readVarUInt();
    if (!contentCount) {
      Log.error("payload vote deserialize content count error");
      return false;
    }

    for (let i = 0; i < contentCount.toNumber(); ++i) {
      if (!this._content[i].deserialize(stream, this._version)) {
        Log.error("payload vote deserialize content error");
        return false;
      }
    }

    return true;
  }

  toJson(): json {
    let j = {};
    j["Version"] = this._version;

    let voteContent;
    for (let i = 0; i < this._content.length; ++i) {
      voteContent.push(this._content[i].toJson(this._version));
    }
    j["VoteContent"] = voteContent;

    return j;
  }

  fromJson(j: json) {
    this._version = j["Version"] as number;
    let voteContent = j["VoteContent"] as [];

    for (let i = 0; i < voteContent.length; ++i) {
      this._content[i].fromJson(voteContent[i], this._version);
    }
  }

  copyOutputPayload(payload: OutputPayload) {
    try {
      const payloadVote = payload as PayloadVote;
      this.copyPayloadVote(payloadVote);
    } catch (e) {
      Log.error("payload is not instance of PayloadVote");
    }

    return this;
  }

  copyPayloadVote(payload: PayloadVote) {
    this._version = payload._version;
    this._content = payload._content;

    return this;
  }

  equals(payload: OutputPayload): boolean {
    try {
      const payloadVote = payload as PayloadVote;
      return (
        this._version == payloadVote._version &&
        this._content == payloadVote._content
      );
    } catch (e) {
      Log.error("payload is not instance of PayloadVote");
    }

    return false;
  }
}
