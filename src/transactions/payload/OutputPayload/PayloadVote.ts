// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import BigNumber from "bignumber.js";
import { Buffer } from "buffer";
import { ByteStream } from "../../../common/bytestream";
import { Log } from "../../../common/Log";
import { bytes_t, size_t, uint64_t, uint8_t } from "../../../types";
import { OutputPayload } from "../OutputPayload/OutputPayload";

export const VOTE_PRODUCER_CR_VERSION = 0x01;
export type VoteContentArray = VoteContent[];

export type CandidateVotesInfo = { Candidate: string; Votes?: string };

export class CandidateVotes {
  private _candidate: bytes_t;
  private _votes: uint64_t;
  constructor() {
    this._votes = new BigNumber(0);
  }

  static newFromParams(candidate: bytes_t, votes: BigNumber) {
    const cv = new CandidateVotes();
    cv._candidate = candidate;
    cv._votes = votes;
    return cv;
  }

  getCandidate(): bytes_t {
    return this._candidate;
  }

  getVotes(): uint64_t {
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

  toJson(version: uint8_t): CandidateVotesInfo {
    let j = <CandidateVotesInfo>{};
    j["Candidate"] = this._candidate.toString("hex");
    if (version >= VOTE_PRODUCER_CR_VERSION) {
      j["Votes"] = this._votes.toString();
    }
    return j;
  }

  fromJson(j: CandidateVotesInfo, version: uint8_t) {
    this._candidate = Buffer.from(j["Candidate"], "hex");
    if (version >= VOTE_PRODUCER_CR_VERSION) {
      this._votes = new BigNumber(j["Votes"]);
    }
  }

  equals(cv: CandidateVotes): boolean {
    return this._candidate.equals(cv._candidate) && this._votes.eq(cv._votes);
  }
}

export enum VoteContentType {
  Delegate,
  CRC,
  CRCProposal,
  CRCImpeachment,
  Max
}

interface CandidateVotesObj {
  [key: string]: string;
}

export type VoteContentInfo = {
  Type: "Delegate" | "CRC" | "CRCProposal" | "CRCImpeachment";
  Candidates: CandidateVotesObj;
};

export type VoteContentJson = {
  Type: number;
  Candidates: CandidateVotesInfo[];
};

export class VoteContent {
  private _type: VoteContentType;
  private _candidates: CandidateVotes[] = [];
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

    for (let i = 0; i < this._candidates.length; ++i) {
      if (max < this._candidates[i].getVotes()) {
        max = this._candidates[i].getVotes();
      }
    }

    return max;
  }

  getTotalVoteAmount(): BigNumber {
    let total = new BigNumber(0);

    for (let i = 0; i < this._candidates.length; i++) {
      total = total.plus(this._candidates[i].getVotes());
    }

    return total;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    ostream.writeUInt8(this._type);

    ostream.writeVarUInt(this._candidates.length);

    this._candidates.forEach((c) => c.serialize(ostream, version));
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    let type = istream.readUInt8();
    // ignore the Delegate vote type
    if (!type && type !== 0) {
      Log.error("VoteContent deserialize type error");
      return false;
    }
    this._type = type;

    let size = istream.readVarUInt();
    if (!size) {
      Log.error("VoteContent deserialize candidates count error");
      return false;
    }

    this._candidates = [];
    for (let i = 0; i < size.toNumber(); ++i) {
      let candidateVotes = new CandidateVotes();
      if (!candidateVotes.deserialize(istream, version)) {
        Log.error("VoteContent deserialize candidates error");
      }
      this._candidates.push(candidateVotes);
    }

    return true;
  }

  toJson(version: uint8_t): VoteContentJson {
    let j = <VoteContentJson>{};
    j["Type"] = this._type;

    let candidates = [];
    for (let i = 0; i < this._candidates.length; ++i) {
      candidates.push(this._candidates[i].toJson(version));
    }
    j["Candidates"] = candidates;

    return j;
  }

  fromJson(j: VoteContentJson, version: uint8_t) {
    this._type = j["Type"];

    let candidates = j["Candidates"];
    this._candidates = [];
    for (let i = 0; i < candidates.length; ++i) {
      let candidate = new CandidateVotes();
      candidate.fromJson(candidates[i], version);
      this._candidates.push(candidate);
    }
  }

  private isEqualCandidates(candidates: CandidateVotes[]): boolean {
    if (this._candidates.length !== candidates.length) {
      return false;
    }
    let equal = false;
    for (let i = 0; i < candidates.length; ++i) {
      for (let j = 0; j < this._candidates.length; ++j) {
        if (this._candidates[j].equals(candidates[i])) {
          equal = true;
          break;
        } else {
          equal = false;
        }
      }
      if (equal === false) {
        return false;
      }
    }
    return equal;
  }

  equals(vc: VoteContent): boolean {
    return this._type == vc._type && this.isEqualCandidates(vc._candidates);
  }
}

export type PayloadVoteInfo = {
  Version: number;
  VoteContent: VoteContentJson[];
};

export class PayloadVote extends OutputPayload {
  private _version: uint8_t;
  private _content: VoteContent[];

  constructor() {
    super();
    this._version = 0;
  }

  static newFromParams(voteContents: VoteContent[], version = 0) {
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
    let version = stream.readUInt8();
    if (!version) {
      Log.error("payload vote deserialize version error");
      return false;
    }
    this._version = version;

    let contentCount = stream.readVarUInt();
    if (!contentCount) {
      Log.error("payload vote deserialize content count error");
      return false;
    }

    this._content = [];
    for (let i = 0; i < contentCount.toNumber(); ++i) {
      let voteContent = new VoteContent();
      if (!voteContent.deserialize(stream, this._version)) {
        Log.error("payload vote deserialize content error");
        return false;
      }
      this._content.push(voteContent);
    }
    return true;
  }

  toJson(): PayloadVoteInfo {
    let j = <PayloadVoteInfo>{};
    j["Version"] = this._version;

    let voteContent = [];
    for (let i = 0; i < this._content.length; ++i) {
      voteContent.push(this._content[i].toJson(this._version));
    }
    j["VoteContent"] = voteContent;

    return j;
  }

  fromJson(j: PayloadVoteInfo) {
    this._version = j["Version"];
    let voteContent = j["VoteContent"];
    this._content = [];
    for (let i = 0; i < voteContent.length; ++i) {
      let content = new VoteContent();
      content.fromJson(voteContent[i], this._version);
      this._content.push(content);
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

  private isEqualContent(content: VoteContent[]): boolean {
    if (this._content.length !== content.length) {
      return false;
    }
    let equal = false;
    for (let i = 0; i < content.length; ++i) {
      for (let j = 0; j < this._content.length; ++j) {
        if (this._content[j].equals(content[i])) {
          equal = true;
          break;
        } else {
          equal = false;
        }
      }
      if (equal === false) {
        return false;
      }
    }
    return equal;
  }

  equals(payload: OutputPayload): boolean {
    try {
      const payloadVote = payload as PayloadVote;
      return (
        this._version == payloadVote._version &&
        this.isEqualContent(payloadVote._content)
      );
    } catch (e) {
      Log.error("payload is not instance of PayloadVote");
    }

    return false;
  }
}
