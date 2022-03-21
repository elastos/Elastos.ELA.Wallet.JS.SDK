// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import BigNumber from "bignumber.js";
import { ByteStream } from "../common/bytestream";
import { JsonSerializer } from "../common/JsonSerializer";
import { Log } from "../common/Log";
import { ELAMessage } from "../ELAMessage";
import { json, size_t, uint256, uint8_t } from "../types";
import { SHA256 } from "../walletcore/sha256";

export const TOKEN_ASSET_PRECISION = "1000000000000000000";

export enum AssetType {
  Token = 0x00,
  Share = 0x01
}

export enum AssetRecordType {
  Unspent = 0x00,
  Balance = 0x01
}

export const MaxPrecision: uint8_t = 18;

export class Asset extends ELAMessage implements JsonSerializer {
  private _name: string;
  private _description: string;
  private _precision: uint8_t;
  private _assetType: AssetType;
  private _recordType: AssetRecordType;
  private _hash: uint256;

  private static _elaAsset: BigNumber = null;

  constructor() {
    super();
    this._name = "ELA";
    this._description = "";
    this._precision = 8;
    this._assetType = AssetType.Token;
    this._recordType = AssetRecordType.Unspent;
    this._hash = Asset.getELAAssetID();
  }

  public static newFromParams(
    name: string,
    desc: string,
    precision: uint8_t,
    assetType: AssetType,
    recordType: AssetRecordType
  ): Asset {
    let newAsset = new Asset();
    newAsset._name = name;
    newAsset._description = desc;
    newAsset._precision = precision;
    newAsset._assetType = assetType;
    newAsset._recordType = recordType;
    return newAsset;
  }

  /* Asset::Asset(const Asset &asset) {
		this->operator=(asset);
	} */

  public static newFromAsset(asset: Asset): Asset {
    let newAsset = new Asset();
    newAsset._name = asset._name;
    newAsset._description = asset._description;
    newAsset._precision = asset._precision;
    newAsset._assetType = asset._assetType;
    newAsset._recordType = asset._recordType;
    newAsset._hash = asset._hash;
    return newAsset;
  }

  public estimateSize(): size_t {
    let size: size_t = 0;
    let stream = new ByteStream();

    size += stream.writeVarUInt(this._name.length);
    size += this._name.length;
    size += stream.writeVarUInt(this._description.length);
    size += this._description.length;
    size += 3;

    return size;
  }

  public serialize(stream: ByteStream) {
    stream.writeVarString(this._name);
    stream.writeVarString(this._description);
    stream.writeByte(this._precision);
    stream.writeByte(this._assetType);
    stream.writeByte(this._recordType);
  }

  public deserialize(stream: ByteStream): boolean {
    this._name = stream.readVarString();
    if (!this._name) {
      Log.error("Asset payload deserialize name fail");
      return false;
    }

    this._description = stream.readVarString();
    if (!this._description) {
      Log.error("Asset payload deserialize description fail");
      return false;
    }

    this._precision = stream.readUInt8();
    if (this._precision === null) {
      Log.error("Asset payload deserialize precision fail");
      return false;
    }

    this._assetType = stream.readUInt8();
    if (this._assetType === null) {
      Log.error("Asset payload deserialize asset type fail");
      return false;
    }

    this._recordType = stream.readUInt8();
    if (this._recordType === null) {
      Log.error("Asset payload deserialize record type fail");
      return false;
    }

    if (this._name == "ELA") {
      this._hash = Asset.getELAAssetID();
    } else {
      this._hash = new BigNumber(0);
      this.getHash();
    }

    return true;
  }

  public toJson(): json {
    return {
      Name: this._name,
      Description: this._description,
      Precision: this._precision,
      AssetType: this._assetType,
      RecordType: this._recordType
    };
  }

  public fromJson(j: json) {
    this._name = j["Name"] as string;
    this._description = j["Description"] as string;
    this._precision = j["Precision"] as number;
    this._assetType = j["AssetType"] as number;
    this._recordType = j["RecordType"] as number;

    if (this._name == "ELA") {
      this._hash = Asset.getELAAssetID();
    } else {
      this._hash = new BigNumber(0);
      this.getHash();
    }
  }

  public static getELAAssetID(): uint256 {
    if (Asset._elaAsset === null) {
      Asset._elaAsset = new BigNumber(
        "a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0",
        16
      );
    }
    return Asset._elaAsset;
  }

  public getHash(): uint256 {
    if (this._hash.eq(0)) {
      let stream = new ByteStream();
      this.serialize(stream);
      this._hash = new BigNumber(
        SHA256.hashTwice(stream.getBytes()).toString("hex")
      );
    }
    return this._hash;
  }

  public setHash(hash: uint256) {
    this._hash = hash;
  }

  public equals(asset: Asset): boolean {
    return (
      this._name == asset._name &&
      this._description == asset._description &&
      this._precision == asset._precision &&
      this._assetType == asset._assetType &&
      this._recordType == asset._recordType
    );
  }

  setName(name: string) {
    this._name = name;
  }

  getName(): string {
    return this._name;
  }

  setDescription(desc: string) {
    this._description = desc;
  }

  getDescription(): string {
    return this._description;
  }

  setAssetType(type: AssetType) {
    this._assetType = type;
  }

  getAssetType(): AssetType {
    return this._assetType;
  }

  setAssetRecordType(type: AssetRecordType) {
    this._recordType = type;
  }

  getAssetRecordType(): AssetRecordType {
    return this._recordType;
  }

  setPrecision(precision: uint8_t) {
    this._precision = precision;
  }

  getPrecision(): uint8_t {
    return this._precision;
  }
}
