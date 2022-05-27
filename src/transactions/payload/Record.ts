// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
import { Buffer } from "buffer";
import { size_t, uint8_t, bytes_t, json } from "../../types";
import { Payload } from "./Payload";
import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";

export class Record extends Payload {
  private _recordType: string;
  private _recordData: bytes_t;

  constructor() {
    super();
    this._recordType = "";
  }

  static newFromParmas(recordType: string, recordData: bytes_t) {
    const record = new Record();
    record._recordType = recordType;
    record._recordData = recordData;
    return record;
  }

  static newFromRecord(payload: Record) {
    const record = new Record();
    record.copyFromRecord(payload);
    return record;
  }

  setRecordType(recordType: string) {
    this._recordType = recordType;
  }

  setRecordData(recordData: bytes_t) {
    this._recordData = recordData;
  }

  getRecordType(): string {
    return this._recordType;
  }

  getRecordData(): bytes_t {
    return this._recordData;
  }

  estimateSize(version: uint8_t): size_t {
    let size = 0;
    let stream = new ByteStream();

    size += stream.writeVarUInt(this._recordType.length);
    size += this._recordType.length;
    size += stream.writeVarUInt(this._recordData.length);
    size += this._recordData.length;

    return size;
  }

  serialize(ostream: ByteStream, version: uint8_t) {
    ostream.writeVarString(this._recordType);
    ostream.writeVarBytes(this._recordData);
  }

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    const recordType = istream.readVarString();
    if (!recordType) {
      Log.error("Payload record deserialize type fail");
      return false;
    }
    this._recordType = recordType;

    if (!istream.readVarBytes(this._recordData)) {
      Log.error("Payload record deserialize data fail");
      return false;
    }

    return true;
  }

  toJson(version: uint8_t) {
    let j = {};

    j["RecordType"] = this._recordType;
    j["RecordData"] = this._recordData.toString("hex");

    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._recordType = j["RecordType"] as string;
    this._recordData = Buffer.from(j["RecordData"] as string, "hex");
  }

  copyFromPayload(payload: Payload) {
    try {
      const payloadRecord = payload as Record;
      this.copyFromRecord(payloadRecord);
    } catch (e) {
      Log.error("payload is not instance of Record");
    }

    return this;
  }

  copyFromRecord(payload: Record) {
    this._recordData = payload._recordData;
    this._recordType = payload._recordType;

    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as Record;
      return (
        this._recordData.equals(p._recordData) &&
        this._recordType == p._recordType
      );
    } catch (e) {
      Log.error("payload is not instance of Record");
    }

    return false;
  }
}
