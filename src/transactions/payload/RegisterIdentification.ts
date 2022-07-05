// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import BigNumber from "bignumber.js";
import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";
import {
  json,
  size_t,
  uint8_t,
  bytes_t,
  sizeof_uint32_t,
  uint256
} from "../../types";
import { Error, ErrorChecker } from "../../common/ErrorChecker";
import { Payload } from "./Payload";

export class ValueItem {
  DataHash: uint256;
  Proof: string;
  Info: string;

  newFromParams(hash: uint256, p: string, i: string) {
    this.DataHash = hash;
    this.Proof = p;
    this.Info = i;
  }

  equals(vi: ValueItem): boolean {
    return (
      this.DataHash.eq(vi.DataHash) &&
      this.Proof == vi.Proof &&
      this.Info == vi.Info
    );
  }
}

export class SignContent {
  Path: string;
  Values: ValueItem[];

  newFromParams(p: string, v: ValueItem[]) {}

  private isEqualValues(values: ValueItem[]): boolean {
    if (this.Values.length !== values.length) {
      return false;
    }
    let equal = false;
    for (let i = 0; i < values.length; ++i) {
      for (let j = 0; j < this.Values.length; ++j) {
        if (this.Values[j].equals(values[i])) {
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

  equals(sc: SignContent): boolean {
    return this.Path == sc.Path && this.isEqualValues(sc.Values);
  }
}

export class RegisterIdentification extends Payload {
  private _id: string;
  private _sign: bytes_t;
  private _contents: SignContent[];

  constructor() {
    super();
    this._id = "";
  }

  newFromRegisterIdentification(payload: RegisterIdentification) {
    this.copyRegisterIdentification(payload);
  }

  getID(): string {
    return this._id;
  }

  setID(id: string) {
    this._id = id;
  }

  getSign(): bytes_t {
    return this._sign;
  }

  setSign(sign: bytes_t) {
    this._sign = sign;
  }

  isValid(version: uint8_t): boolean {
    if (!this._id || this._contents.length == 0 || this._sign.length == 0) {
      return false;
    }
    return true;
  }

  estimateSize(version: uint8_t): size_t {
    let size = 0;
    let stream = new ByteStream();

    size += stream.writeVarUInt(this._id.length);
    size += this._id.length;
    size += stream.writeVarUInt(this._sign.length);
    size += this._sign.length;

    size += stream.writeVarUInt(this._contents.length);
    for (let i = 0; i < this._contents.length; ++i) {
      size += stream.writeVarUInt(this._contents[i].Path.length);
      size += this._contents[i].Path.length;

      size += stream.writeVarUInt(this._contents[i].Values.length);
      for (let j = 0; j < this._contents[i].Values.length; ++j) {
        size += sizeof_uint32_t();
        size += stream.writeVarUInt(this._contents[i].Values[j].Proof.length);
        size += this._contents[i].Values[j].Proof.length;
        size += stream.writeVarUInt(this._contents[i].Values[j].Info.length);
        size += this._contents[i].Values[j].Info.length;
      }
    }

    return size;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    if (!this._id) {
      Log.error("Payload register identification serialize id fail");
      return false;
    }
    if (!this._contents || this._contents.length == 0) {
      Log.error("Payload register identification serialize contents fail");
      return false;
    }

    ostream.writeVarString(this._id);
    ostream.writeVarBytes(this._sign);

    ostream.writeVarUInt(this._contents.length);
    for (let i = 0; i < this._contents.length; ++i) {
      ostream.writeVarString(this._contents[i].Path);

      ostream.writeVarUInt(this._contents[i].Values.length);
      for (let j = 0; j < this._contents[i].Values.length; ++j) {
        ostream.writeBNAsUIntOfSize(this._contents[i].Values[j].DataHash, 32);
        ostream.writeVarString(this._contents[i].Values[j].Proof);
        ostream.writeVarString(this._contents[i].Values[j].Info);
      }
    }
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    let id = istream.readVarString();
    if (!id) {
      Log.error("Payload register identification deserialize id fail");
      return false;
    }
    this._id = id;

    let sign: bytes_t;
    sign = istream.readVarBytes(sign);
    if (!sign) {
      Log.error("Payload register identification deserialize sign fail");
      return false;
    }
    this._sign = sign;

    let size = istream.readVarUInt();
    if (!size || size.isZero()) {
      Log.error(
        "Payload register identification deserialize content size fail"
      );
      return false;
    }

    for (let i = 0; i < size.toNumber(); ++i) {
      let content = new SignContent();
      content.Path = istream.readVarString();
      if (!content.Path) {
        Log.error("Payload register identification deserialize path fail");
        return false;
      }

      let valueSize = istream.readVarUInt();
      if (!valueSize) {
        Log.error(
          "Payload register identification deserialize value size fail"
        );
        return false;
      }

      for (let j = 0; j < valueSize.toNumber(); ++j) {
        let value = new ValueItem();
        let dataHash = istream.readUIntOfBytesAsBN(32);
        if (!dataHash) {
          Log.error(
            "Payload register identification deserialize data hash fail"
          );
          return false;
        }
        value.DataHash = dataHash;

        let proof = istream.readVarString();
        if (!proof) {
          Log.error("Payload register identification deserialize proof fail");
          return false;
        }
        value.Proof = proof;
        let info = istream.readVarString();
        if (!info) {
          Log.error("Payload register identification deserialize info fail");
          return false;
        }
        content.Values.push(value);
      }

      this._contents.push(content);
    }

    return true;
  }

  toJson(version: uint8_t) {
    let j = {};
    j["Id"] = this._id;
    j["Sign"] = this._sign.toString("hex");

    let contents = [];
    for (let i = 0; i < this._contents.length; ++i) {
      let content = {};
      content["Path"] = this._contents[i].Path;

      let values = [];
      for (let k = 0; k < this._contents[i].Values.length; ++k) {
        let value = {};
        value["DataHash"] = this._contents[i].Values[k].DataHash.toString(16);
        value["Proof"] = this._contents[i].Values[k].Proof;
        value["Info"] = this._contents[i].Values[k].Info;
        values.push(value);
      }
      content["Values"] = values;

      contents.push(content);
    }
    j["Contents"] = contents;
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._id = j["Id"] as string;
    if (j["Sign"]) this._sign = Buffer.from(j["Sign"] as string, "hex");

    let contents = j["Contents"] as [];

    for (let i = 0; i < contents.length; ++i) {
      let content = new SignContent();
      content.Path = contents[i]["Path"] as string;

      let values = contents[i]["Values"] as [];
      for (let k = 0; k < values.length; ++k) {
        let value = new ValueItem();
        value.DataHash = new BigNumber(values[k]["DataHash"] as string, 16);
        value.Proof = values[k]["Proof"] as string;
        if (values[k]["Info"]) value.Info = values[k]["Info"] as string;
        content.Values.push(value);
      }

      this._contents.push(content);
    }
  }

  getPath(index: size_t): string {
    ErrorChecker.checkCondition(
      index >= this._contents.length,
      Error.Code.PayloadRegisterID,
      "Index too large"
    );

    return this._contents[index].Path;
  }

  setPath(path: string, index: size_t) {
    ErrorChecker.checkCondition(
      index >= this._contents.length,
      Error.Code.PayloadRegisterID,
      "Index too large"
    );

    this._contents[index].Path = path;
  }

  getDataHash(index: size_t, valueIndex: size_t): uint256 {
    ErrorChecker.checkCondition(
      index >= this._contents.length,
      Error.Code.PayloadRegisterID,
      "Index too large"
    );

    return this._contents[index].Values[valueIndex].DataHash;
  }

  setDataHash(dataHash: uint256, index: size_t, valueIndex: size_t) {
    ErrorChecker.checkCondition(
      index >= this._contents.length,
      Error.Code.PayloadRegisterID,
      "Index too large"
    );

    this._contents[index].Values[valueIndex].DataHash = dataHash;
  }

  getProof(index: size_t, valueIndex: size_t): string {
    ErrorChecker.checkCondition(
      index >= this._contents.length,
      Error.Code.PayloadRegisterID,
      "Index too large"
    );

    return this._contents[index].Values[valueIndex].Proof;
  }

  setProof(proof: string, index: size_t, valueIndex: size_t) {
    ErrorChecker.checkCondition(
      index >= this._contents.length,
      Error.Code.PayloadRegisterID,
      "Index too large"
    );

    this._contents[index].Values[valueIndex].Proof = proof;
  }

  getContentCount(): size_t {
    return this._contents.length;
  }

  addContent(content: SignContent) {
    this._contents.push(content);
  }

  setContent(contents: SignContent[]) {
    this._contents = contents;
  }

  removeContent(index: size_t) {
    ErrorChecker.checkCondition(
      index >= this._contents.length,
      Error.Code.PayloadRegisterID,
      "Index too large"
    );

    this._contents = [
      ...this._contents.slice(0, index),
      ...this._contents.slice(index + 1)
    ];
  }

  copyPayload(payload: Payload) {
    try {
      const payloadRegisterIdentification = payload as RegisterIdentification;
      this.copyRegisterIdentification(payloadRegisterIdentification);
    } catch (e) {
      Log.error("payload is not instance of RegisterIdentification");
    }
    return this;
  }

  copyRegisterIdentification(payload: RegisterIdentification) {
    this._id = payload._id;
    this._sign = payload._sign;
    this._contents = payload._contents;

    return this;
  }

  private isEqualContents(contents: SignContent[]): boolean {
    if (this._contents.length !== contents.length) {
      return false;
    }
    let equal = false;
    for (let i = 0; i < contents.length; ++i) {
      for (let j = 0; j < this._contents.length; ++j) {
        if (this._contents[j].equals(contents[i])) {
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

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as RegisterIdentification;
      return (
        this._id == p._id &&
        this._sign.equals(p._sign) &&
        this.isEqualContents(p._contents)
      );
    } catch (e) {
      Log.error("payload is not instance of RegisterIdentification");
    }

    return false;
  }
}
