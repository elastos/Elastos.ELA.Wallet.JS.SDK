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
import BigNumber from "bignumber.js";
import { Buffer } from "buffer";
import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";
import { uint168 } from "../../common/uint168";
import { bytes_t, size_t, uint256, uint8_t } from "../../types";
import { Address } from "../../walletcore/Address";
import { EcdsaSigner } from "../../walletcore/ecdsasigner";
import { SHA256 } from "../../walletcore/sha256";
import { Payload } from "./Payload";

export const JsonKeyNodePublicKey = "NodePublicKey";
export const JsonKeyCRCouncilMemberDID = "CRCouncilMemberDID";
export const JsonKeyCRCouncilMemberSignature = "CRCouncilMemberSignature";
export const CRCouncilMemberClaimNodeVersion = 0;

export type CRCouncilMemberClaimNodeInfo = {
  NodePublicKey: string;
  CRCouncilMemberDID: string;
  CRCouncilMemberSignature?: string;
};

export class CRCouncilMemberClaimNode extends Payload {
  private _nodePublicKey: bytes_t;
  private _crCouncilMemberDID: Address;
  private _crCouncilMemberSignature: bytes_t;
  private _digestUnsigned: uint256;

  estimateSize(version: uint8_t): size_t {
    let stream = new ByteStream();
    let size: size_t = 0;

    size += stream.writeVarUInt(this._nodePublicKey.length);
    size += this._nodePublicKey.length;
    size += this._crCouncilMemberDID.programHash().bytes().length;
    size += stream.writeVarUInt(this._crCouncilMemberSignature.length);
    size += this._crCouncilMemberSignature.length;

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    this.serializeUnsigned(stream, version);
    stream.writeVarBytes(this._crCouncilMemberSignature);
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    if (!this.deserializeUnsigned(stream, version)) {
      Log.error("deserialize unsigned fail");
      return false;
    }
    let crCouncilMemberSignature: bytes_t;
    crCouncilMemberSignature = stream.readVarBytes(crCouncilMemberSignature);
    if (!crCouncilMemberSignature) {
      Log.error("deserialize signature fail");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;
    return true;
  }

  toJson(version: uint8_t): CRCouncilMemberClaimNodeInfo {
    let j = this.toJsonUnsigned(version);
    j[JsonKeyCRCouncilMemberSignature] =
      this._crCouncilMemberSignature.toString("hex");
    return j;
  }

  fromJson(j: CRCouncilMemberClaimNodeInfo, version: uint8_t) {
    this.fromJsonUnsigned(j, version);
    this._crCouncilMemberSignature = Buffer.from(
      j[JsonKeyCRCouncilMemberSignature],
      "hex"
    );
  }

  isValid(version: uint8_t) {
    if (!this.isValidUnsigned(version)) {
      Log.error("unsigned is not valid");
      return false;
    }

    if (!this._crCouncilMemberSignature.length) {
      Log.error("invalid signature");
      return false;
    }

    return true;
  }

  copyPayload(payload: Payload) {
    try {
      const realPayload = payload as CRCouncilMemberClaimNode;
      this.copyCRCouncilMemberClaimNode(realPayload);
    } catch (e) {
      Log.error("payload is not instance of CRCouncilMemberClaimNode");
    }
    return this;
  }

  copyCRCouncilMemberClaimNode(payload: CRCouncilMemberClaimNode) {
    this._digestUnsigned = payload._digestUnsigned;
    this._nodePublicKey = payload._nodePublicKey;
    this._crCouncilMemberDID = payload._crCouncilMemberDID;
    this._crCouncilMemberSignature = payload._crCouncilMemberSignature;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    let equal = false;

    try {
      const realPayload = payload as CRCouncilMemberClaimNode;
      equal =
        this._nodePublicKey.equals(realPayload._nodePublicKey) &&
        this._crCouncilMemberDID.equals(realPayload._crCouncilMemberDID) &&
        this._crCouncilMemberSignature.equals(
          realPayload._crCouncilMemberSignature
        );
    } catch (e) {
      Log.error("payload is not instance of CRCouncilMemberClaimNode");
      equal = false;
    }

    return equal;
  }

  serializeUnsigned(stream: ByteStream, version: uint8_t) {
    stream.writeVarBytes(this._nodePublicKey);
    stream.writeBytes(this._crCouncilMemberDID.programHash().bytes());
  }

  deserializeUnsigned(stream: ByteStream, version: uint8_t): boolean {
    let nodePublicKey: bytes_t;
    nodePublicKey = stream.readVarBytes(nodePublicKey);
    if (!nodePublicKey) {
      Log.error("deserialize node pubkey");
      return false;
    }
    this._nodePublicKey = nodePublicKey;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize cr council member did");
      return false;
    }

    this._crCouncilMemberDID = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    return true;
  }

  toJsonUnsigned(version: uint8_t): CRCouncilMemberClaimNodeInfo {
    let j = <CRCouncilMemberClaimNodeInfo>{};

    j[JsonKeyNodePublicKey] = this._nodePublicKey.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();

    return j;
  }

  fromJsonUnsigned(j: CRCouncilMemberClaimNodeInfo, version: uint8_t) {
    this._nodePublicKey = Buffer.from(j[JsonKeyNodePublicKey], "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID]
    );
  }

  isValidUnsigned(version: uint8_t): boolean {
    try {
      // Key key(CTElastos, _nodePublicKey);
      let key = EcdsaSigner.getKeyFromPublic(this._nodePublicKey);
    } catch (e) {
      Log.error("invalid node pubkey");
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      Log.error("invalid cr council member did");
      return false;
    }

    return true;
  }

  digestUnsigned(version: uint8_t): uint256 {
    if (!this._digestUnsigned) {
      let stream = new ByteStream();
      this.serializeUnsigned(stream, version);
      let digest = SHA256.encodeToBuffer(stream.getBytes()).toString("hex");
      this._digestUnsigned = new BigNumber(digest, 16);
    }

    return this._digestUnsigned;
  }

  setNodePublicKey(pubkey: bytes_t) {
    this._nodePublicKey = pubkey;
  }

  setCRCouncilMemberDID(did: Address) {
    this._crCouncilMemberDID = did;
  }

  setCRCouncilMemberSignature(signature: bytes_t) {
    this._crCouncilMemberSignature = signature;
  }
}
