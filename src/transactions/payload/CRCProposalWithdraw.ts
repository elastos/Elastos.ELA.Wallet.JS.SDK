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
  size_t,
  uint256,
  uint8_t,
  sizeof_uint256_t,
  sizeof_uint64_t,
  bytes_t
} from "../../types";
import { Address } from "../../walletcore/Address";
import { SHA256 } from "../../walletcore/sha256";
import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";
import { Payload } from "./Payload";
import { EcdsaSigner } from "../../walletcore/ecdsasigner";
import { uint168 } from "../../common/uint168";
import { getBNHexStr } from "../../common/bnutils";

const JsonKeyProposalHash = "ProposalHash";
const JsonKeyOwnerPubkey = "OwnerPublicKey";
const JsonKeyRecipient = "Recipient";
const JsonKeyAmount = "Amount";
const JsonKeySignature = "Signature";

export const CRCProposalWithdrawVersion = 0;
export const CRCProposalWithdrawVersion_01 = 0x01;

export type CRCProposalWithdrawInfo = {
  ProposalHash: string;
  OwnerPublicKey: string;
  Recipient?: string;
  Amount?: string;
  Signature?: string;
};

export class CRCProposalWithdraw extends Payload {
  private _proposalHash: uint256;
  private _ownerPubkey: Buffer;
  private _recipient: Address;
  private _amount: BigNumber;
  private _signature: Buffer;
  private _digest: string;

  setProposalHash(hash: uint256) {
    this._proposalHash = hash;
  }

  getProposalHash(): uint256 {
    return this._proposalHash;
  }

  setOwnerPublicKey(pubkey: Buffer) {
    this._ownerPubkey = pubkey;
  }

  getOwnerPublicKey(): Buffer {
    return this._ownerPubkey;
  }

  setSignature(signature: Buffer) {
    this._signature = signature;
  }

  gGetSignature(): Buffer {
    return this._signature;
  }

  digestUnsigned(version: number): string {
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
    let size = 0;

    // size += this._proposalHash.size();
    size += sizeof_uint256_t();
    size += stream.writeVarUInt(this._ownerPubkey.length);
    size += this._ownerPubkey.length;
    size += stream.writeVarUInt(this._signature.length);
    if (version == CRCProposalWithdrawVersion_01) {
      size += this._recipient.programHash().bytes().length;
      size += sizeof_uint64_t();
    }
    size += this._signature.length;

    return size;
  }

  serializeUnsigned(stream: ByteStream, version: uint8_t) {
    stream.writeBNAsUIntOfSize(this._proposalHash, 32);
    stream.writeVarBytes(this._ownerPubkey);

    if (version == CRCProposalWithdrawVersion_01) {
      stream.writeBytes(this._recipient.programHash().bytes());
      // WAS stream.WriteUint64(_amount.getUint64());
      stream.writeBNAsUIntOfSize(this._amount, 8);
    }
  }

  serialize(stream: ByteStream, version: uint8_t) {
    this.serializeUnsigned(stream, version);
    stream.writeVarBytes(this._signature);
  }

  deserializeUnsigned(stream: ByteStream, version: uint8_t) {
    let proposalHash = stream.readUIntOfBytesAsBN(32);
    if (!proposalHash) {
      Log.error("deserialize proposal hash");
      return false;
    }
    this._proposalHash = proposalHash;

    let ownerPubkey: bytes_t;
    ownerPubkey = stream.readVarBytes(ownerPubkey);
    if (!ownerPubkey) {
      Log.error("deserialize owner pubkey");
      return false;
    }
    this._ownerPubkey = ownerPubkey;

    if (version == CRCProposalWithdrawVersion_01) {
      let programHash: bytes_t;
      programHash = stream.readBytes(programHash, 21);
      if (!programHash) {
        Log.error("deserialize recipient");
        return false;
      }

      this._recipient = Address.newFromProgramHash(
        uint168.newFrom21BytesBuffer(programHash)
      );

      let amount = stream.readUIntOfBytesAsBN(8);
      if (!amount) {
        Log.error("deserialize amount");
        return false;
      }
      this._amount = amount;
    }

    return true;
  }

  deserialize(stream: ByteStream, version: uint8_t) {
    if (!this.deserializeUnsigned(stream, version)) return false;

    let signature: bytes_t;
    signature = stream.readVarBytes(signature);
    if (!signature) {
      Log.error("deserialize sign");
      return false;
    }
    this._signature = signature;

    return true;
  }

  toJsonUnsigned(version: uint8_t): CRCProposalWithdrawInfo {
    let j = <CRCProposalWithdrawInfo>{};
    j[JsonKeyProposalHash] = getBNHexStr(this._proposalHash);
    j[JsonKeyOwnerPubkey] = this._ownerPubkey.toString("hex");
    if (version == CRCProposalWithdrawVersion_01) {
      j[JsonKeyRecipient] = this._recipient.string();
      j[JsonKeyAmount] = this._amount.toString();
    }
    return j;
  }

  toJson(version: uint8_t): CRCProposalWithdrawInfo {
    let j = this.toJsonUnsigned(version);

    j[JsonKeySignature] = this._signature.toString("hex");
    return j;
  }

  fromJsonUnsigned(j: CRCProposalWithdrawInfo, version: uint8_t) {
    this._proposalHash = new BigNumber(j[JsonKeyProposalHash], 16);
    this._ownerPubkey = Buffer.from(j[JsonKeyOwnerPubkey], "hex");
    if (version == CRCProposalWithdrawVersion_01) {
      this._recipient = Address.newFromAddressString(j[JsonKeyRecipient]);
      this._amount = new BigNumber(j[JsonKeyAmount]);
    }
  }

  fromJson(j: CRCProposalWithdrawInfo, version: uint8_t) {
    this.fromJsonUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature], "hex");
  }

  isValidUnsigned(version: uint8_t): boolean {
    try {
      EcdsaSigner.getKeyFromPublic(this._ownerPubkey);
    } catch (e) {
      Log.error("invalid owner pubkey");
      return false;
    }

    if (version == CRCProposalWithdrawVersion_01) {
      if (!this._recipient.valid()) {
        Log.error("invalid recipient");
        return false;
      }

      if (this._amount.isLessThan(0)) {
        Log.error("invalid amount");
        return false;
      }
    }

    return true;
  }

  isValid(version: uint8_t): boolean {
    if (!this.isValidUnsigned(version)) return false;

    try {
      if (
        !EcdsaSigner.verify(
          this._ownerPubkey,
          this._signature,
          Buffer.from(this.digestUnsigned(version), "hex")
        )
      ) {
        Log.error("verify signature fail");
        return false;
      }
    } catch (e) {
      Log.error("verify signature excpetion: {}", e.what());
      return false;
    }

    return true;
  }

  copyPayload(payload: Payload) {
    try {
      const tracking = payload as CRCProposalWithdraw;
      this.copyCRCProposalWithdraw(tracking);
    } catch (e) {
      Log.error("payload is not instance of CRCProposalWithdraw");
    }
    return this;
  }

  copyCRCProposalWithdraw(payload: CRCProposalWithdraw) {
    this._proposalHash = payload._proposalHash;
    this._ownerPubkey = Buffer.alloc(payload._ownerPubkey.length);
    payload._ownerPubkey.copy(this._ownerPubkey);
    this._ownerPubkey = payload._ownerPubkey;
    this._recipient = Address.newFromAddress(payload._recipient);
    this._amount = payload._amount;
    this._signature = Buffer.alloc(payload._signature.length);
    payload._signature.copy(this._signature);
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as CRCProposalWithdraw;
      let equal =
        this._proposalHash.eq(p._proposalHash) &&
        this._ownerPubkey.equals(p._ownerPubkey) &&
        this._signature.equals(p._signature);

      if (version >= CRCProposalWithdrawVersion_01) {
        equal =
          equal &&
          this._recipient.equals(p._recipient) &&
          this._amount.eq(p._amount);
      }
      return equal;
    } catch (e) {
      Log.error("payload is not instance of CRCProposalWithdraw");
    }

    return false;
  }
}
