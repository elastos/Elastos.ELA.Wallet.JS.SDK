/*
 * Copyright (c) 2022 Elastos Foundation LTD.
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

import { BigNumber } from "bignumber.js";
import { get32BytesOfBNAsHexString } from "../../common/bnutils";
import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";
import {
  bytes_t,
  uint64_t,
  uint32_t,
  uint8_t,
  size_t,
  sizeof_uint64_t,
  sizeof_uint32_t,
  sizeof_uint8_t,
  uint256,
  sizeof_uint256_t
} from "../../types";
import { VoteContentType } from "./OutputPayload/PayloadVote";
import { Payload } from "./Payload";

export const VoteVersion = 0;
export const RenewalVoteVersion = 1;

export type VotesWithLockTimeInfo = {
  Candidate?: string;
  Votes: string;
  Locktime: number;
};

export class VotesWithLockTime {
  private _candidate: bytes_t;
  private _votes: uint64_t;
  private _lockTime: uint32_t;

  static newFromParams(
    candidate: bytes_t,
    votes: uint64_t,
    lockTime: uint32_t
  ) {
    let votesWithLockTime = new VotesWithLockTime();
    votesWithLockTime._candidate = candidate;
    votesWithLockTime._votes = votes;
    votesWithLockTime._lockTime = lockTime;
    return votesWithLockTime;
  }

  estimateSize(version: uint8_t): size_t {
    let size = 0;
    let stream = new ByteStream();

    size += stream.writeVarUInt(this._candidate.length);
    size += this._candidate.length;
    size += sizeof_uint64_t();
    size += sizeof_uint32_t();

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    stream.writeVarBytes(this._candidate);
    stream.writeBNAsUIntOfSize(this._votes, 8);
    stream.writeUInt32(this._lockTime);
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    let candidate: bytes_t;
    candidate = stream.readVarBytes(candidate);
    if (!candidate) {
      Log.error("VotesWithLockTime deserialize candidate");
      return false;
    }
    this._candidate = candidate;

    this._votes = stream.readUIntOfBytesAsBN(8);
    if (!this._votes) {
      Log.error("VotesWithLockTime deserialize votes");
      return false;
    }

    this._lockTime = stream.readUInt32();
    if (!this._lockTime && this._lockTime !== 0) {
      Log.error("VotesWithLockTime deserialize locktime");
      return false;
    }

    return true;
  }

  equals(vwl: VotesWithLockTime, version: uint8_t) {
    return (
      this._candidate.equals(vwl._candidate) &&
      this._votes == vwl._votes &&
      this._lockTime == vwl._lockTime
    );
  }

  fromJson(j: VotesWithLockTimeInfo, v: VotesWithLockTime) {
    v._candidate = Buffer.from(j["Candidate"]);
    v._votes = new BigNumber(j["Votes"]);
    v._lockTime = j["Locktime"];
  }

  toJson(j: VotesWithLockTimeInfo, v: VotesWithLockTime) {
    j["Candidate"] = v._candidate.toString();
    j["Votes"] = v._votes.toString();
    j["Locktime"] = v._lockTime;
  }
}

export type VotesContentInfo = {
  VoteType: number;
  VotesInfo: VotesWithLockTimeInfo[];
};

export class VotesContent {
  private _voteType: uint8_t;
  private _votesInfo: VotesWithLockTime[];

  static newFromParams(voteType: uint8_t, votesInfo: VotesWithLockTime[]) {
    let votesContent = new VotesContent();

    votesContent._voteType = voteType;
    votesContent._votesInfo = votesInfo;
    return votesContent;
  }

  estimateSize(version: uint8_t): size_t {
    let size = 0;
    let stream = new ByteStream();

    size += sizeof_uint8_t();
    size += stream.writeVarUInt(this._votesInfo.length);
    for (let i = 0; i < this._votesInfo.length; ++i) {
      size += this._votesInfo[i].estimateSize(version);
    }

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    stream.writeByte(this._voteType);
    stream.writeVarUInt(this._votesInfo.length);
    for (let info of this._votesInfo) {
      info.serialize(stream, version);
    }
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    this._voteType = stream.readByte();
    if (!this._voteType && this._voteType !== VoteContentType.Delegate) {
      Log.error("deserialize VotesContent vote type");
      return false;
    }

    let size = stream.readVarUInt();
    if (!size) {
      Log.error("deserialize vote info size");
      return false;
    }

    this._votesInfo = [];
    for (let i = 0; i < size.toNumber(); ++i) {
      let vinfo = new VotesWithLockTime();
      if (!vinfo.deserialize(stream, version)) {
        Log.error("deserialize voteinfo[{}]", i);
        return false;
      }
      this._votesInfo.push(vinfo);
    }

    return true;
  }

  equals(vc: VotesContent, version: uint8_t) {
    if (this._voteType != vc._voteType) return false;

    if (this._votesInfo.length != vc._votesInfo.length) return false;

    for (let i = 0; i < this._votesInfo.length; ++i) {
      if (!this._votesInfo[i].equals(vc._votesInfo[i], version)) return false;
    }

    return true;
  }

  fromJson(j: VotesContentInfo, vc: VotesContent) {
    vc._voteType = j["VoteType"];
    let votesInfo = [];
    let voteInfo = new VotesWithLockTime();
    for (let i = 0; i < j["VotesInfo"].length; i++) {
      voteInfo.fromJson(j["VotesInfo"][i], voteInfo);
      votesInfo.push(voteInfo);
    }
    vc._votesInfo = votesInfo;
  }

  toJson(j: VotesContentInfo, vc: VotesContent) {
    j["VoteType"] = vc._voteType;
    let votesInfo = [];
    let voteInfo = new VotesWithLockTime();
    for (let i = 0; i < vc._votesInfo.length; i++) {
      let j = <VotesWithLockTimeInfo>{};
      voteInfo.toJson(j, vc._votesInfo[i]);
      votesInfo.push(j);
    }
    j["VotesInfo"] = votesInfo;
  }
}

export type RenewalVotesContentInfo = {
  ReferKey: string;
  VoteInfo: VotesWithLockTimeInfo;
};

export class RenewalVotesContent {
  private _referKey: uint256;
  private _voteInfo: VotesWithLockTime;

  static newFromParams(referKey: uint256, voteInfo: VotesWithLockTime) {
    let renewalVotesContent = new RenewalVotesContent();
    renewalVotesContent._referKey = referKey;
    renewalVotesContent._voteInfo = voteInfo;
    return renewalVotesContent;
  }

  estimateSize(version: uint8_t): size_t {
    let size = 0;

    size += sizeof_uint256_t();
    size += this._voteInfo.estimateSize(version);

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    // stream.writeBytes(this._referKey);
    stream.writeBNAsUIntOfSize(this._referKey, 32);
    this._voteInfo.serialize(stream, version);
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    this._referKey = stream.readUIntOfBytesAsBN(32);
    if (!this._referKey) {
      Log.error("RenewalVotesContent deserialize refer key");
      return false;
    }

    this._voteInfo = new VotesWithLockTime();
    if (!this._voteInfo.deserialize(stream, version)) {
      Log.error("RenewalVotesContent deserialize vote info");
      return false;
    }

    return true;
  }

  equals(rvc: RenewalVotesContent, version: uint8_t) {
    return (
      this._referKey == rvc._referKey &&
      this._voteInfo.equals(rvc._voteInfo, version)
    );
  }

  fromJson(j: RenewalVotesContentInfo, rvc: RenewalVotesContent) {
    rvc._referKey = new BigNumber(j["ReferKey"], 16);
    let votesWithLockTime = new VotesWithLockTime();
    votesWithLockTime.fromJson(j["VoteInfo"], votesWithLockTime);
    rvc._voteInfo = votesWithLockTime;
  }

  toJson(j: RenewalVotesContentInfo, rvc: RenewalVotesContent) {
    j["ReferKey"] = get32BytesOfBNAsHexString(rvc._referKey);
    let votesWithLockTime = rvc._voteInfo;
    let voteInfo = <VotesWithLockTimeInfo>{};
    votesWithLockTime.toJson(voteInfo, votesWithLockTime);
    j["VoteInfo"] = voteInfo;
  }
}

export type VotingInfo = {
  Version?: number;
  Contents?: VotesContentInfo[];
  RenewalVotesContent?: RenewalVotesContentInfo[];
};

export class Voting extends Payload {
  private _contents: VotesContent[]; // 投票
  private _renewalVotesContent: RenewalVotesContent[]; // 续期

  static newFromParams(
    contents: VotesContent[],
    renewalVotesContent: RenewalVotesContent[]
  ) {
    let voting = new Voting();
    voting._contents = contents;
    voting._renewalVotesContent = renewalVotesContent;
    return voting;
  }

  estimateSize(version: uint8_t) {
    let size = 0;
    let stream = new ByteStream();

    if (version == VoteVersion) {
      size += stream.writeVarUInt(this._contents.length);
      for (let i = 0; i < this._contents.length; ++i) {
        size += this._contents[i].estimateSize(version);
      }
    } else if (version == RenewalVoteVersion) {
      size += stream.writeVarUInt(this._renewalVotesContent.length);
      for (let i = 0; i < this._renewalVotesContent.length; ++i) {
        size += this._renewalVotesContent[i].estimateSize(version);
      }
    }

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    if (version == VoteVersion) {
      stream.writeVarUInt(this._contents.length);
      for (let vc of this._contents) {
        vc.serialize(stream, version);
      }
    } else if (version == RenewalVoteVersion) {
      stream.writeVarUInt(this._renewalVotesContent.length);
      for (let rvc of this._renewalVotesContent) {
        rvc.serialize(stream, version);
      }
    }
  }

  deserialize(stream: ByteStream, version: uint8_t) {
    if (version == VoteVersion) {
      let size = stream.readVarUInt();
      if (!size) {
        Log.error("voting deserialize contents size");
        return false;
      }
      this._contents = [];
      for (let i = 0; i < size.toNumber(); ++i) {
        let vc = new VotesContent();
        if (!vc.deserialize(stream, version)) {
          Log.error("voting deserialize VotesContent[{}]", i);
          return false;
        }
        this._contents.push(vc);
      }
    } else if (version == RenewalVoteVersion) {
      let size = stream.readVarUInt();
      if (!size) {
        Log.error("voting deserialize RenewalVotesContent size");
        return false;
      }
      this._renewalVotesContent = [];
      for (let i = 0; i < size.toNumber(); ++i) {
        let rvc = new RenewalVotesContent();
        if (!rvc.deserialize(stream, version)) {
          Log.error("voting deserialize RenewalVotesContent[{}]", i);
          return false;
        }
        this._renewalVotesContent.push(rvc);
      }
    }

    return true;
  }

  toJson(version: uint8_t) {
    let j = <VotingInfo>{};
    if (version == VoteVersion) {
      let contents = [];
      for (let i = 0; i < this._contents.length; ++i) {
        let votesContent = new VotesContent();
        let info = <VotesContentInfo>{};
        votesContent.toJson(info, this._contents[i]);
        contents.push(info);
      }

      j["Contents"] = contents;
    } else if (version == RenewalVoteVersion) {
      let contents = [];
      for (let i = 0; i < this._renewalVotesContent.length; ++i) {
        let renewalVotesContent = new RenewalVotesContent();
        let info = <RenewalVotesContentInfo>{};
        renewalVotesContent.toJson(info, this._renewalVotesContent[i]);
        contents.push(info);
      }

      j["RenewalVotesContent"] = contents;
    }
    return j;
  }

  fromJson(j: VotingInfo, version: uint8_t) {
    if (version == VoteVersion) {
      let contents = [];
      for (let i = 0; i < j["Contents"].length; ++i) {
        let votesContent = new VotesContent();
        votesContent.fromJson(j["Contents"][i], votesContent);
        contents.push(votesContent);
      }
      this._contents = contents;
    } else if (version == RenewalVoteVersion) {
      let contents = [];
      for (let i = 0; i < j["RenewalVotesContent"].length; ++i) {
        let renewalVotesContent = new RenewalVotesContent();

        renewalVotesContent.fromJson(
          j["RenewalVotesContent"][i],
          renewalVotesContent
        );
        contents.push(renewalVotesContent);
      }
      this._renewalVotesContent = contents;
    }
  }

  isValid(version: uint8_t): boolean {
    return true;
  }

  copyPayload(payload: Payload) {
    try {
      const p = payload as Voting;
      this.copyVoting(p);
    } catch (e) {
      Log.error("payload is not instance of Voting");
    }

    return this;
  }

  copyVoting(payload: Voting) {
    this._contents = payload._contents;
    this._renewalVotesContent = payload._renewalVotesContent;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      let p = payload as Voting;
      if (version == VoteVersion) {
        if (this._contents.length != p._contents.length) return false;

        for (let i = 0; i < this._contents.length; ++i) {
          if (!this._contents[i].equals(p._contents[i], version)) return false;
        }
      } else if (version == RenewalVoteVersion) {
        if (this._renewalVotesContent.length != p._renewalVotesContent.length)
          return false;

        for (let i = 0; i < this._renewalVotesContent.length; ++i) {
          if (
            !this._renewalVotesContent[i].equals(
              p._renewalVotesContent[i],
              version
            )
          )
            return false;
        }
      }
    } catch (e) {
      Log.error("payload is not instance of Voting");
      return false;
    }

    return true;
  }
}
