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
import { ByteStream } from "../common/bytestream";
import { JsonSerializer } from "../common/JsonSerializer";
import { Log } from "../common/Log";
import { ELAMessage } from "../ELAMessage";
import { bytes_t, size_t, uint8_t } from "../types";
import { OP_1, SignType } from "../walletcore/Address";
import { EcdsaSigner } from "../walletcore/ecdsasigner";

export type ProgramPtr = Program;
export type ProgramArray = ProgramPtr[];
export type SignedInfo = {
  SignType: string;
  M?: number;
  N?: number;
  Signers: string[];
};
export type ProgramInfo = { Parameter: string; Code: string };

export class Program extends ELAMessage implements JsonSerializer {
  private _code: bytes_t;
  private _parameter: bytes_t;

  public static newFromParams(code: bytes_t, parameter: bytes_t): Program {
    let program = new Program();
    program._parameter = Buffer.alloc(parameter.length);
    parameter.copy(program._parameter);
    program._code = Buffer.alloc(code.length);
    code.copy(program._code);
    return program;
  }

  public static newFromProgram(p: Program): Program {
    let program = new Program();
    program._parameter = Buffer.alloc(p._parameter.length);
    p._parameter.copy(program._parameter);
    program._code = Buffer.alloc(p._code.length);
    p._code.copy(program._code);
    return program;
  }

  public verifySignature(md: string): boolean {
    let signatureCount: uint8_t = 0;
    let publicKeys: bytes_t[] = [];

    let type: SignType = this.decodePublicKey(publicKeys);
    if (type == SignType.SignTypeInvalid) {
      Log.error("Invalid Redeem script");
      return false;
    }
    let stream = new ByteStream(this._parameter);
    let signature: bytes_t;
    signature = stream.readVarBytes(signature);
    while (signature) {
      let verified = false;
      for (let i = 0; i < publicKeys.length; ++i) {
        let publicKey = publicKeys[i];
        if (
          signature &&
          EcdsaSigner.verify(publicKey, signature, Buffer.from(md, "hex"))
        ) {
          verified = true;
          break;
        }
      }

      signatureCount++;
      signature = stream.readVarBytes(signature);
      if (!verified) {
        Log.error("Transaction signature verify failed");
        return false;
      }
    }

    if (this._code[this._code.length - 1] == SignType.SignTypeMultiSign) {
      let m: uint8_t = this._code[0] - OP_1 + 1;
      let n: uint8_t = this._code[this._code.length - 2] - OP_1 + 1;

      if (signatureCount < m) {
        Log.info("Signature not enough for multi sign tx");
        return false;
      }

      if (publicKeys.length > n) {
        Log.error("Too many signers");
        return false;
      }
    } else if (this._code[this._code.length - 1] == SignType.SignTypeStandard) {
      if (publicKeys.length != signatureCount) {
        return false;
      }
    }

    return true;
  }

  public getSignedInfo(md: string): SignedInfo {
    let info = <SignedInfo>{};
    let publicKeys: bytes_t[] = [];

    let type: SignType = this.decodePublicKey(publicKeys);
    if (type == SignType.SignTypeInvalid) {
      Log.warn("Can not decode pubkey from program");
      return info;
    }

    let stream = new ByteStream(this._parameter);
    let signature: bytes_t = Buffer.alloc(0);
    let signers: string[] = [];
    signature = stream.readVarBytes(signature);
    while (signature) {
      for (let i = 0; i < publicKeys.length; ++i) {
        let publicKey = publicKeys[i];
        if (EcdsaSigner.verify(publicKey, signature, Buffer.from(md, "hex"))) {
          signers.push(publicKeys[i].toString("hex"));
          break;
        }
      }
      signature = stream.readVarBytes(signature);
    }

    if (
      (this._code[this._code.length - 1] as SignType) ===
      SignType.SignTypeMultiSign
    ) {
      let m: uint8_t = this._code[0] - OP_1 + 1;
      let n: uint8_t = this._code[this._code.length - 2] - OP_1 + 1;
      info["SignType"] = "MultiSign";
      info["M"] = m;
      info["N"] = n;
      info["Signers"] = signers;
    } else if (
      (this._code[this._code.length - 1] as SignType) ==
      SignType.SignTypeStandard
    ) {
      info["SignType"] = "Standard";
      info["Signers"] = signers;
    }

    return info;
  }

  decodePublicKey(pubkeys: bytes_t[]): SignType {
    if (this._code.length < 33 + 2) return SignType.SignTypeInvalid;

    let signType = this._code[this._code.length - 1];
    let stream = new ByteStream(this._code);
    if (
      signType == SignType.SignTypeMultiSign ||
      signType == SignType.SignTypeCrossChain
    ) {
      stream.skip(1);
    } else if (
      signType != SignType.SignTypeStandard &&
      signType != SignType.SignTypeDID
    ) {
      Log.error("unsupport sign type");
      return SignType.SignTypeInvalid;
    }

    let pubKey: bytes_t;
    pubKey = stream.readVarBytes(pubKey);
    while (pubKey) {
      pubkeys.push(pubKey);
      pubKey = stream.readVarBytes(pubKey);
    }

    return signType;
  }

  public getCode(): bytes_t {
    return this._code;
  }

  public getParameter(): bytes_t {
    return this._parameter;
  }

  public setCode(code: bytes_t) {
    this._code = code;
  }

  public setParameter(parameter: bytes_t) {
    this._parameter = parameter;
  }

  estimateSize(): size_t {
    let size: size_t = 0;
    let stream = new ByteStream();

    if (!this._parameter) {
      if (this._code[this._code.length - 1] == SignType.SignTypeMultiSign) {
        let m = this._code[0] - OP_1 + 1;
        let signLen = m * 64; // WAS uint64_t signLen = m * 64ul;
        size += stream.writeVarUInt(signLen);
        size += signLen;
      } else if (
        this._code[this._code.length - 1] == SignType.SignTypeStandard
      ) {
        size += 65;
      }
    } else {
      size += stream.writeVarUInt(this._parameter.length);
      size += this._parameter.length;
    }

    size += stream.writeVarUInt(this._code.length);
    size += this._code.length;

    return size;
  }

  public serialize(stream: ByteStream) {
    stream.writeVarBytes(this._parameter);
    stream.writeVarBytes(this._code);
  }

  public deserialize(stream: ByteStream): boolean {
    let parameter: bytes_t;
    parameter = stream.readVarBytes(parameter);
    if (!parameter) {
      Log.error("Program deserialize parameter fail");
      return false;
    }
    this._parameter = parameter;

    let code: bytes_t;
    code = stream.readVarBytes(code);
    if (!code) {
      Log.error("Program deserialize code fail");
      return false;
    }
    this._code = code;

    return true;
  }

  public toJson(): ProgramInfo {
    return {
      Parameter: this._parameter.toString("hex"),
      Code: this._code.toString("hex")
    };
  }

  public fromJson(j: ProgramInfo): Program {
    this._parameter = Buffer.from(j["Parameter"] as string, "hex");
    this._code = Buffer.from(j["Code"] as string, "hex");
    return this;
  }

  public equals(p: Program): boolean {
    return (
      this._code.toString() == p._code.toString() &&
      this._parameter.toString() == p._parameter.toString()
    );
  }
}
