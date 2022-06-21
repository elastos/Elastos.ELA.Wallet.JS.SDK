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
import { Error, ErrorChecker } from "../../common/ErrorChecker";
import { Log } from "../../common/Log";
import { uint168 } from "../../common/uint168";
import {
  bytes_t,
  sizeof_uint16_t,
  sizeof_uint256_t,
  size_t,
  uint16_t,
  uint256,
  uint32_t,
  uint64_t,
  uint8_t
} from "../../types";
import { Address } from "../../walletcore/Address";
import { BASE64 as Base64 } from "../../walletcore/base64";
import { EcdsaSigner } from "../../walletcore/ecdsasigner";
import { SHA256 } from "../../walletcore/sha256";
import { Payload } from "./Payload";

export const CRCProposalDefaultVersion = 0;
export const CRCProposalVersion01 = 0x01;

export const JsonKeyType = "Type";
export const JsonKeyStage = "Stage";
export const JsonKeyAmount = "Amount";

export const JsonKeyCategoryData = "CategoryData";
export const JsonKeyOwnerPublicKey = "OwnerPublicKey";
export const JsonKeyDraftHash = "DraftHash";
export const JsonKeyDraftData = "DraftData";
export const JsonKeyBudgets = "Budgets";
export const JsonKeyRecipient = "Recipient";
export const JsonKeyTargetProposalHash = "TargetProposalHash";
export const JsonKeyNewRecipient = "NewRecipient";
export const JsonKeyNewOwnerPublicKey = "NewOwnerPublicKey";
export const JsonKeySecretaryPublicKey = "SecretaryGeneralPublicKey";
export const JsonKeyReservedCustomIDList = "ReservedCustomIDList";
export const JsonKeyReceiverDID = "ReceiverDID";
export const JsonKeyReceivedCustomIDList = "ReceivedCustomIDList";
export const JsonKeyCustomIDFeeRateInfo = "CustomIDFeeRateInfo";
export const JsonKeySecretaryDID = "SecretaryGeneralDID";
export const JsonKeySignature = "Signature";
export const JsonKeyNewOwnerSignature = "NewOwnerSignature";
export const JsonKeySecretarySignature = "SecretaryGeneralSignature";
export const JsonKeyCRCouncilMemberDID = "CRCouncilMemberDID";
export const JsonKeyCRCouncilMemberSignature = "CRCouncilMemberSignature";
export const JsonKeySidechainInfo = "SidechainInfo";
export const JsonKeyUpgradeCodeInfo = "UpgradeCodeInfo";

export enum BudgetType {
  imprest = 0x00,
  normalPayment = 0x01,
  finalPayment = 0x02,
  maxType
}

const DRAFT_DATA_MAX_SIZE = 1024 * 1024;

export type BudgetInfo = {
  Type: number;
  Stage: number;
  Amount: string;
};

export class Budget {
  private _type: BudgetType;
  private _stage: uint8_t;
  private _amount: BigNumber;

  static newFromParams(type: BudgetType, stage: uint8_t, amount: BigNumber) {
    const budget = new Budget();
    budget._type = type;
    budget._stage = stage;
    budget._amount = amount;
    return budget;
  }

  getType(): BudgetType {
    return this._type;
  }

  getStage(): uint8_t {
    return this._stage;
  }

  getAmount(): BigNumber {
    return this._amount;
  }

  serialize(ostream: ByteStream) {
    ostream.writeUInt8(this._type);
    ostream.writeUInt8(this._stage);
    ostream.writeBNAsUIntOfSize(this._amount, 8);
  }

  deserialize(istream: ByteStream): boolean {
    let type: uint8_t = istream.readUInt8();
    // ignore the imprest budget type
    if (!type && type !== 0) {
      Log.error("Budget::Deserialize: read type key");
      return false;
    }
    this._type = type;

    let stage: uint8_t = istream.readUInt8();
    // ignore the stage 0
    if (!stage && stage !== 0) {
      Log.error("Budget::Deserialize: read stage key");
      return false;
    }
    this._stage = stage;

    let amount = istream.readUIntOfBytesAsBN(8);
    if (!amount) {
      Log.error("Budget::Deserialize: read amount key");
      return false;
    }
    this._amount = amount;

    return true;
  }

  isValid(): boolean {
    if (this._type >= BudgetType.maxType) {
      Log.error("invalid budget type: {}", this._type);
      return false;
    }

    if (this._stage > 127) {
      Log.error("invalid budget stage", this._stage);
      return false;
    }

    return true;
  }

  toJson(): BudgetInfo {
    let j = <BudgetInfo>{};
    j[JsonKeyType] = this._type;
    j[JsonKeyStage] = this._stage;
    j[JsonKeyAmount] = this._amount.toString();
    return j;
  }

  fromJson(j: BudgetInfo) {
    this._type = j[JsonKeyType];
    this._stage = j[JsonKeyStage];
    this._amount = new BigNumber(j[JsonKeyAmount]);
  }

  equals(budget: Budget): boolean {
    return (
      this._type == budget._type &&
      this._stage == budget._stage &&
      this._amount.eq(budget._amount)
    );
  }
}

export type UpgradeCodeInfoJson = {
  WorkingHeight: number;
  NodeVersion: string;
  NodeDownloadUrl: string;
  NodeBinHash: string;
  Force: boolean;
};

export class UpgradeCodeInfo {
  private _workingHeight: uint32_t;
  private _nodeVersion: string;
  private _nodeDownloadUrl: string;
  private _nodeBinHash: uint256;
  private _force: boolean;

  serialize(stream: ByteStream, version: uint8_t) {
    stream.writeUInt32(this._workingHeight);
    stream.writeVarString(this._nodeVersion);
    stream.writeVarString(this._nodeDownloadUrl);
    stream.writeBNAsUIntOfSize(this._nodeBinHash, 32);
    stream.writeUInt8(this._force ? 0x01 : 0x00);
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    let workingHeight = stream.readUInt32();
    if (!workingHeight) {
      Log.error("deserialize workingHeight failed");
      return false;
    }
    this._workingHeight = workingHeight;

    const nodeVersion = stream.readVarString();
    if (!nodeVersion) {
      Log.error("deserialize nodeVersion failed");
      return false;
    }
    this._nodeVersion = nodeVersion;

    const nodeDownloadUrl = stream.readVarString();
    if (!nodeDownloadUrl) {
      Log.error("deserialize nodeDownloadUrl failed");
      return false;
    }
    this._nodeDownloadUrl = nodeDownloadUrl;

    let nodeBinHash: bytes_t;
    nodeBinHash = stream.readBytes(nodeBinHash, 32);
    if (!nodeBinHash) {
      Log.error("deserialize nodeBinHash failed");
      return false;
    }
    this._nodeBinHash = new BigNumber(nodeBinHash.toString("hex"), 16);

    let force: uint8_t = 0;
    force = stream.readUInt8();
    if (!force) {
      Log.error("deserialize force failed");
      return false;
    }
    this._force = force == 0 ? false : true;

    return true;
  }

  toJson(version: uint8_t): UpgradeCodeInfoJson {
    let j = <UpgradeCodeInfoJson>{};
    j["WorkingHeight"] = this._workingHeight;
    j["NodeVersion"] = this._nodeVersion;
    j["NodeDownloadUrl"] = this._nodeDownloadUrl;
    j["NodeBinHash"] = this._nodeBinHash.toString(16);
    j["Force"] = this._force;
    return j;
  }

  fromJson(j: UpgradeCodeInfoJson, version: uint8_t) {
    this._workingHeight = j["WorkingHeight"];
    this._nodeVersion = j["NodeVersion"];
    this._nodeDownloadUrl = j["NodeDownloadUrl"];
    this._nodeBinHash = new BigNumber(j["NodeBinHash"], 16);
    this._force = j["Force"];
  }

  isValid(version: uint8_t): boolean {
    return true;
  }
}

export type SideChainInfoJson = {
  SideChainName: string;
  MagicNumber: number;
  GenesisHash: string;
  ExchangeRate: string;
  EffectiveHeight: number;
  ResourcePath: string;
};

export class SideChainInfo {
  private _sideChainName: string;
  private _magicNumber: uint32_t;
  private _genesisHash: uint256;
  private _exchangeRate: uint64_t;
  private _effectiveHeight: uint32_t;
  private _resourcePath: string;

  serialize(stream: ByteStream, version: uint8_t) {
    stream.writeVarString(this._sideChainName);
    stream.writeUInt32(this._magicNumber);
    // stream.writeBytes(this._genesisHash);
    stream.writeBNAsUIntOfSize(this._genesisHash, 32);
    // stream.writeUint64(this._exchangeRate);
    stream.writeBNAsUIntOfSize(this._exchangeRate, 8);
    stream.writeUInt32(this._effectiveHeight);
    stream.writeVarString(this._resourcePath);
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    let sideChainName = stream.readVarString();
    if (!sideChainName) {
      Log.error("deserialize side-chain name failed");
      return false;
    }
    this._sideChainName = sideChainName;

    let magicNumber = stream.readUInt32();
    if (!magicNumber) {
      Log.error("deserialize magic number failed");
      return false;
    }
    this._magicNumber = magicNumber;

    let genesisHash = stream.readUIntOfBytesAsBN(32);
    if (!genesisHash) {
      Log.error("deserialize genesis hash failed");
      return false;
    }
    this._genesisHash = genesisHash;

    let exchangeRate = stream.readUIntOfBytesAsBN(8);
    if (!exchangeRate) {
      Log.error("deserialize exchange rate failed");
      return false;
    }
    this._exchangeRate = exchangeRate;

    let effectiveHeight = stream.readUInt32();
    if (!effectiveHeight) {
      Log.error("deserialize effective height failed");
      return false;
    }
    this._effectiveHeight = effectiveHeight;

    let resourcePath = stream.readVarString();
    if (!resourcePath) {
      Log.error("deserialize resource path failed");
      return false;
    }
    this._resourcePath = resourcePath;
    return true;
  }

  toJson(version: uint8_t): SideChainInfoJson {
    let j = <SideChainInfoJson>{};
    j["SideChainName"] = this._sideChainName;
    j["MagicNumber"] = this._magicNumber;
    j["GenesisHash"] = this._genesisHash.toString(16);
    j["ExchangeRate"] = this._exchangeRate.toString(16);
    j["EffectiveHeight"] = this._effectiveHeight;
    j["ResourcePath"] = this._resourcePath;
    return j;
  }

  fromJson(j: SideChainInfoJson, version: uint8_t) {
    this._sideChainName = j["SideChainName"];
    this._magicNumber = j["MagicNumber"];
    this._genesisHash = new BigNumber(j["GenesisHash"], 16);
    this._exchangeRate = new BigNumber(j["ExchangeRate"], 16);
    this._effectiveHeight = j["EffectiveHeight"];
    this._resourcePath = j["ResourcePath"];
  }

  isValid(version: uint8_t): boolean {
    return true;
  }

  equals(info: SideChainInfo): boolean {
    return (
      this._sideChainName == info._sideChainName &&
      this._magicNumber == info._magicNumber &&
      this._genesisHash.eq(info._genesisHash) &&
      this._exchangeRate.eq(info._exchangeRate) &&
      this._effectiveHeight == info._effectiveHeight &&
      this._resourcePath == info._resourcePath
    );
  }

  copySideChainInfo(info: SideChainInfo) {
    this._sideChainName = info._sideChainName;
    this._magicNumber = info._magicNumber;
    this._genesisHash = info._genesisHash;
    this._exchangeRate = info._exchangeRate;
    this._effectiveHeight = info._effectiveHeight;
    this._resourcePath = info._resourcePath;
    return this;
  }
}

export type CustomIDFeeRateInfoJson = {
  RateOfCustomIDFee: string;
  EIDEffectiveHeight: number;
};

export class CustomIDFeeRateInfo {
  // The rate of custom DID fee.
  private _rateOfCustomIDFee: uint64_t;
  // Effective at the side chain height of EID.
  private _eIDEffectiveHeight: uint32_t;

  serialize(stream: ByteStream, version: uint8_t) {
    stream.writeBNAsUIntOfSize(this._rateOfCustomIDFee, 8);
    stream.writeUInt32(this._eIDEffectiveHeight);
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    let rateOfCustomIDFee = stream.readUIntOfBytesAsBN(8);
    if (!rateOfCustomIDFee) {
      Log.error("deserialize rateOfCustomIDFee failed");
      return false;
    }
    this._rateOfCustomIDFee = rateOfCustomIDFee;

    let eIDEffectiveHeight = stream.readUInt32();
    if (!eIDEffectiveHeight) {
      Log.error("deserialize eIDEffectiveHeight failed");
      return false;
    }
    this._eIDEffectiveHeight = eIDEffectiveHeight;

    return true;
  }

  toJson(version: uint8_t): CustomIDFeeRateInfoJson {
    let j = <CustomIDFeeRateInfoJson>{};
    j["RateOfCustomIDFee"] = this._rateOfCustomIDFee.toString(16);
    j["EIDEffectiveHeight"] = this._eIDEffectiveHeight;
    return j;
  }

  fromJson(j: CustomIDFeeRateInfoJson, version: uint8_t) {
    this._rateOfCustomIDFee = new BigNumber(j["RateOfCustomIDFee"], 16);
    this._eIDEffectiveHeight = j["EIDEffectiveHeight"];
  }

  equals(info: CustomIDFeeRateInfo): boolean {
    return (
      this._rateOfCustomIDFee.eq(info._rateOfCustomIDFee) &&
      this._eIDEffectiveHeight == info._eIDEffectiveHeight
    );
  }

  copyCustomIDFeeRateInfo(info: CustomIDFeeRateInfo) {
    this._rateOfCustomIDFee = info._rateOfCustomIDFee;
    this._eIDEffectiveHeight = info._eIDEffectiveHeight;
    return this;
  }
}

export enum CRCProposalType {
  normal = 0x0000,

  elip = 0x0100,
  flowElip = 0x0101,
  infoElip = 0x0102,

  mainChainUpgradeCode = 0x0200,
  didUpdateCode = 0x0201,
  ethUpdateCode = 0x0202,

  secretaryGeneralElection = 0x0400,
  changeProposalOwner = 0x0401,
  terminateProposal = 0x0402,
  registerSideChain = 0x0410,

  reserveCustomID = 0x0500,
  receiveCustomID = 0x0501,
  changeCustomIDFee = 0x0502,
  maxType
}

export type ChangeProposalOwnerInfo = {
  Type?: number;
  CategoryData: string;
  OwnerPublicKey: string;
  DraftHash: string;
  DraftData?: string;
  TargetProposalHash: string;
  NewRecipient: string;
  NewOwnerPublicKey: string;
  Signature?: string;
  NewOwnerSignature?: string;
  CRCouncilMemberDID?: string;
  CRCouncilMemberSignature?: string;
};

export type TerminateProposalOwnerInfo = {
  Type?: number;
  CategoryData: string;
  OwnerPublicKey: string;
  DraftHash: string;
  DraftData?: string;
  TargetProposalHash: string;
  Signature?: string;
  CRCouncilMemberDID?: string;
  CRCouncilMemberSignature?: string;
};

export type SecretaryElectionInfo = {
  Type: number;
  CategoryData: string;
  OwnerPublicKey: string;
  DraftHash: string;
  DraftData?: string;
  SecretaryGeneralPublicKey: string;
  SecretaryGeneralDID: string;
  Signature?: string;
  SecretaryGeneralSignature?: string;
  CRCouncilMemberDID?: string;
  CRCouncilMemberSignature?: string;
};

export type ReserveCustomIDOwnerInfo = {
  Type: number;
  CategoryData: string;
  OwnerPublicKey: string;
  DraftHash: string;
  DraftData?: string;
  ReservedCustomIDList: string[];
  Signature?: string;
  CRCouncilMemberDID?: string;
  CRCouncilMemberSignature?: string;
};

export type ReceiveCustomIDOwnerInfo = {
  Type: number;
  CategoryData: string;
  OwnerPublicKey: string;
  DraftHash: string;
  DraftData?: string;
  ReceivedCustomIDList: string[];
  ReceiverDID: string;
  Signature?: string;
  CRCouncilMemberDID?: string;
  CRCouncilMemberSignature?: string;
};

export type ChangeCustomIDFeeOwnerInfo = {
  Type: number;
  CategoryData: string;
  OwnerPublicKey: string;
  DraftHash: string;
  DraftData?: string;
  CustomIDFeeRateInfo: CustomIDFeeRateInfoJson;
  Signature?: string;
  CRCouncilMemberDID?: string;
  CRCouncilMemberSignature?: string;
};

export type RegisterSidechainProposalInfo = {
  Type: number;
  CategoryData: string;
  OwnerPublicKey: string;
  DraftHash: string;
  DraftData?: string;
  SidechainInfo: SideChainInfoJson;
  Signature?: string;
  CRCouncilMemberDID?: string;
  CRCouncilMemberSignature?: string;
};

export type UpgradeCodeProposalInfo = {
  Type: number;
  CategoryData: string;
  OwnerPublicKey: string;
  DraftHash: string;
  UpgradeCodeInfo: UpgradeCodeInfoJson;
  Signature?: string;
  CRCouncilMemberDID?: string;
  CRCouncilMemberSignature?: string;
};

export type NormalProposalOwnerInfo = {
  Type: number;
  CategoryData: string;
  OwnerPublicKey: string;
  DraftHash: string;
  DraftData?: string;
  Budgets: BudgetInfo[];
  Recipient: string;
  Signature?: string;
  CRCouncilMemberDID?: string;
  CRCouncilMemberSignature?: string;
};

export type CRCProposalInfo =
  | ChangeProposalOwnerInfo
  | TerminateProposalOwnerInfo
  | SecretaryElectionInfo
  | ReserveCustomIDOwnerInfo
  | ReceiveCustomIDOwnerInfo
  | ChangeCustomIDFeeOwnerInfo
  | RegisterSidechainProposalInfo
  | UpgradeCodeProposalInfo
  | NormalProposalOwnerInfo;

export class CRCProposal extends Payload {
  private _type: CRCProposalType;
  private _categoryData: string;
  private _ownerPublicKey: bytes_t;
  private _draftHash: uint256;
  private _draftData: bytes_t;
  private _budgets: Budget[];
  private _recipient: Address;
  private _targetProposalHash: uint256;
  private _reservedCustomIDList: string[];
  private _receivedCustomIDList: string[];
  private _receiverDID: Address;
  private _customIDFeeRateInfo: CustomIDFeeRateInfo;
  private _newRecipient: Address;
  private _newOwnerPublicKey: bytes_t;
  private _secretaryPublicKey: bytes_t;
  private _secretaryDID: Address;
  private _signature: bytes_t;
  private _newOwnerSignature: bytes_t;
  private _secretarySignature: bytes_t;

  // cr council member did
  private _crCouncilMemberDID: Address;
  private _crCouncilMemberSignature: bytes_t;

  // upgrade code info
  private _upgradeCodeInfo: UpgradeCodeInfo;

  private _sidechainInfo: SideChainInfo;

  setTpye(type: CRCProposalType) {
    this._type = type;
  }

  getType(): CRCProposalType {
    return this._type;
  }

  setCategoryData(categoryData: string) {
    this._categoryData = categoryData;
  }

  getCategoryData(): string {
    return this._categoryData;
  }

  setOwnerPublicKey(publicKey: bytes_t) {
    this._ownerPublicKey = publicKey;
  }

  getOwnerPublicKey(): bytes_t {
    return this._ownerPublicKey;
  }

  setCRCouncilMemberDID(crSponsorDID: Address) {
    this._crCouncilMemberDID = crSponsorDID;
  }

  getCRCouncilMemberDID(): Address {
    return this._crCouncilMemberDID;
  }

  setDraftHash(draftHash: uint256) {
    this._draftHash = draftHash;
  }

  getDraftHash(): uint256 {
    return this._draftHash;
  }

  setDraftData(draftData: bytes_t) {
    this._draftData = draftData;
  }

  getDraftData(): bytes_t {
    return this._draftData;
  }

  setBudgets(budgets: Budget[]) {
    this._budgets = budgets;
  }

  getBudgets(): Budget[] {
    return this._budgets;
  }

  setRecipient(recipient: Address) {
    this._recipient = recipient;
  }

  getRecipient(): Address {
    return this._recipient;
  }

  setTargetProposalHash(hash: uint256) {
    this._targetProposalHash = hash;
  }

  getTargetProposalHash(): uint256 {
    return this._targetProposalHash;
  }

  setNewRecipient(recipient: Address) {
    this._newRecipient = recipient;
  }

  getNewRecipient(): Address {
    return this._newRecipient;
  }

  setNewOwnerPublicKey(pubkey: bytes_t) {
    this._newOwnerPublicKey = pubkey;
  }

  getNewOwnerPublicKey(): bytes_t {
    return this._newOwnerPublicKey;
  }

  setSecretaryPublicKey(pubkey: bytes_t) {
    this._secretaryPublicKey = pubkey;
  }

  getSecretaryPublicKey(): bytes_t {
    return this._secretaryPublicKey;
  }

  setSecretaryDID(did: Address) {
    this._secretaryDID = did;
  }

  getSecretaryDID(): Address {
    return this._secretaryDID;
  }

  setSignature(signature: bytes_t) {
    this._signature = signature;
  }

  getSignature(): bytes_t {
    return this._signature;
  }

  setNewOwnerSignature(sign: bytes_t) {
    this._newOwnerSignature = sign;
  }

  getNewOwnerSignature(): bytes_t {
    return this._newOwnerSignature;
  }

  setSecretarySignature(sign: bytes_t) {
    this._secretarySignature = sign;
  }

  getSecretarySignature(): bytes_t {
    return this._secretarySignature;
  }

  setCRCouncilMemberSignature(signature: bytes_t) {
    this._crCouncilMemberSignature = signature;
  }

  getCRCouncilMemberSignature(): bytes_t {
    return this._crCouncilMemberSignature;
  }

  digestNormalOwnerUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeOwnerUnsigned(stream, version);
    const rs = SHA256.encodeToBuffer(stream.getBytes()).toString("hex");
    return new BigNumber(rs, 16);
  }

  digestNormalCRCouncilMemberUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeCRCouncilMemberUnsigned(stream, version);
    const rs = SHA256.encodeToBuffer(stream.getBytes()).toString("hex");
    return new BigNumber(rs, 16);
  }

  estimateSize(version: uint8_t): size_t {
    let stream = new ByteStream();
    let byteStream = new ByteStream();
    let size: size_t = 0;

    size += sizeof_uint16_t(); // this._type
    let categoryData = Buffer.from(this._categoryData, "utf8");
    size += stream.writeVarUInt(categoryData.length);
    size += categoryData.length;
    size += stream.writeVarUInt(this._ownerPublicKey.length);
    size += this._ownerPublicKey.length;
    if (version >= CRCProposalVersion01) {
      size += stream.writeVarUInt(this._draftData.length);
      size += this._draftData.length;
    }
    size += sizeof_uint256_t(); // this._draftHash

    switch (this._type) {
      case CRCProposalType.elip:
      case CRCProposalType.normal:
        size += stream.writeVarUInt(this._budgets.length);
        for (let i = 0; i < this._budgets.length; ++i) {
          this._budgets[i].serialize(byteStream);
        }
        size += byteStream.getBytes().length;
        size += this._recipient.programHash().bytes().length;
        size += stream.writeVarUInt(this._signature.length);
        size += this._signature.length;
        break;

      case CRCProposalType.secretaryGeneralElection:
        size += stream.writeVarUInt(this._secretaryPublicKey.length);
        size += this._secretaryPublicKey.length;
        size += this._secretaryDID.programHash().bytes().length;
        size += stream.writeVarUInt(this._secretarySignature.length);
        size += this._secretarySignature.length;
        size += stream.writeVarUInt(this._signature.length);
        size += this._signature.length;
        break;

      case CRCProposalType.changeProposalOwner:
        size += sizeof_uint256_t(); // this._targetProposalHash
        size += this._newRecipient.programHash().bytes().length;
        size += stream.writeVarUInt(this._newOwnerPublicKey.length);
        size += this._newOwnerPublicKey.length;
        size += stream.writeVarUInt(this._signature.length);
        size += this._signature.length;
        size += stream.writeVarUInt(this._newOwnerSignature.length);
        size += this._newOwnerSignature.length;
        break;

      case CRCProposalType.terminateProposal:
        size += stream.writeVarUInt(this._signature.length);
        size += this._signature.length;
        size += sizeof_uint256_t(); // this._targetProposalHash
        break;

      default:
        break;
    }

    size += this._crCouncilMemberDID.programHash().bytes().length;
    size += stream.writeVarUInt(this._crCouncilMemberSignature.length);
    size += this._crCouncilMemberSignature.length;

    return size;
  }

  // normal or elip
  serializeOwnerUnsigned(stream: ByteStream, version: uint8_t) {
    stream.writeUInt16(this._type);
    stream.writeVarString(this._categoryData);
    stream.writeVarBytes(this._ownerPublicKey);
    // stream.writeBytes(this._draftHash);
    stream.writeBNAsUIntOfSize(this._draftHash, 32);
    if (version >= CRCProposalVersion01) {
      stream.writeVarBytes(this._draftData);
    }
    stream.writeVarUInt(this._budgets.length);
    for (let i = 0; i < this._budgets.length; ++i) {
      this._budgets[i].serialize(stream);
    }
    stream.writeBytes(this._recipient.programHash().bytes());
  }

  deserializeOwnerUnsigned(stream: ByteStream, version: uint8_t): boolean {
    let categoryData = stream.readVarString();
    if (!categoryData) {
      Log.warn("deserialize categoryData");
      // return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      Log.error("deserialize owner PublicKey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash = stream.readUIntOfBytesAsBN(32);
    if (!draftHash) {
      Log.error("deserialize draftHash");
      return false;
    }
    this._draftHash = draftHash;

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        Log.error("deserialize draftdata");
        return false;
      }
      this._draftData = draftData;
    }

    let count: uint64_t = stream.readVarUInt();
    if (!count) {
      Log.error("deserialize budgets size");
      return false;
    }

    this._budgets = [];
    for (let i = 0; i < count.toNumber(); ++i) {
      const budget = new Budget();
      if (!budget.deserialize(stream)) {
        Log.error("deserialize bugets");
        return false;
      }
      this._budgets.push(budget);
    }

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize recipient");
      return false;
    }

    this._recipient = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    return true;
  }

  serializeCRCouncilMemberUnsigned(ostream: ByteStream, version: uint8_t) {
    this.serializeOwnerUnsigned(ostream, version);

    ostream.writeVarBytes(this._signature);

    ostream.writeBytes(this._crCouncilMemberDID.programHash().bytes());
  }

  deserializeCRCouncilMemberUnsigned(
    istream: ByteStream,
    version: uint8_t
  ): boolean {
    if (!this.deserializeOwnerUnsigned(istream, version)) {
      Log.error("deserialize unsigned");
      return false;
    }

    let signature: bytes_t;
    signature = istream.readVarBytes(signature);
    if (!signature) {
      Log.error("deserialize signature");
      return false;
    }
    this._signature = signature;

    let programHash: bytes_t;
    programHash = istream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize sponsor did");
      return false;
    }

    this._crCouncilMemberDID = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    return true;
  }

  serializeNormalOrELIP(stream: ByteStream, version: uint8_t) {
    this.serializeCRCouncilMemberUnsigned(stream, version);

    stream.writeVarBytes(this._crCouncilMemberSignature);
  }

  deserializeNormalOrELIP(stream: ByteStream, version: uint8_t): boolean {
    if (!this.deserializeCRCouncilMemberUnsigned(stream, version)) {
      Log.error("CRCProposal deserialize crc unsigned");
      return false;
    }

    let crCouncilMemberSignature: bytes_t;
    crCouncilMemberSignature = stream.readVarBytes(crCouncilMemberSignature);
    if (!crCouncilMemberSignature) {
      Log.error("CRCProposal deserialize crc signature");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;

    return true;
  }

  // change owner
  serializeChangeOwnerUnsigned(stream: ByteStream, version: uint8_t) {
    stream.writeUInt16(this._type);

    stream.writeVarString(this._categoryData);
    stream.writeVarBytes(this._ownerPublicKey);
    stream.writeBNAsUIntOfSize(this._draftHash, 32);
    if (version >= CRCProposalVersion01) {
      stream.writeVarBytes(this._draftData);
    }

    stream.writeBNAsUIntOfSize(this._targetProposalHash, 32);
    stream.writeBytes(this._newRecipient.programHash().bytes());
    stream.writeVarBytes(this._newOwnerPublicKey);
  }

  deserializeChangeOwnerUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    let categoryData = stream.readVarString();
    if (!categoryData) {
      Log.warn("deserialize categoryData");
      // return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      Log.error("deserialize owner PublicKey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash = stream.readUIntOfBytesAsBN(32);
    if (!draftHash) {
      Log.error("deserialize draftHash");
      return false;
    }
    this._draftHash = draftHash;

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        Log.error("deserialize draftData");
        return false;
      }
      this._draftData = draftData;
    }

    let targetProposalHash = stream.readUIntOfBytesAsBN(32);
    if (!targetProposalHash) {
      Log.error("deserialize target proposal hash");
      return false;
    }
    this._targetProposalHash = targetProposalHash;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize new recipient");
      return false;
    }

    this._newRecipient = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    let newOwnerPublicKey: bytes_t;
    newOwnerPublicKey = stream.readVarBytes(newOwnerPublicKey);
    if (!newOwnerPublicKey) {
      Log.error("deserialize new owner PublicKey");
      return false;
    }
    this._newOwnerPublicKey = newOwnerPublicKey;

    return true;
  }

  serializeChangeOwnerCRCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ) {
    this.serializeChangeOwnerUnsigned(stream, version);

    stream.writeVarBytes(this._signature);
    stream.writeVarBytes(this._newOwnerSignature);
    stream.writeBytes(this._crCouncilMemberDID.programHash().bytes());
  }

  deserializeChangeOwnerCRCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    if (!this.deserializeChangeOwnerUnsigned(stream, version)) {
      Log.error("deserialize change owner unsigned");
      return false;
    }

    let signature: bytes_t;
    signature = stream.readVarBytes(signature);
    if (!signature) {
      Log.error("deserialize change owner signature");
      return false;
    }
    this._signature = signature;

    let newOwnerSignature: bytes_t;
    newOwnerSignature = stream.readVarBytes(newOwnerSignature);
    if (!newOwnerSignature) {
      Log.error("deserialize change owner new owner signature");
      return false;
    }
    this._newOwnerSignature = newOwnerSignature;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize sponsor did");
      return false;
    }

    this._crCouncilMemberDID = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    return true;
  }

  serializeChangeOwner(stream: ByteStream, version: uint8_t) {
    this.serializeChangeOwnerCRCouncilMemberUnsigned(stream, version);

    stream.writeVarBytes(this._crCouncilMemberSignature);
  }

  deserializeChangeOwner(stream: ByteStream, version: uint8_t): boolean {
    if (!this.deserializeChangeOwnerCRCouncilMemberUnsigned(stream, version)) {
      Log.error("deserialize change owner cr council member unsigned");
      return false;
    }

    let crCouncilMemberSignature: bytes_t;
    crCouncilMemberSignature = stream.readVarBytes(crCouncilMemberSignature);
    if (!crCouncilMemberSignature) {
      Log.error("deserialize change owner cr council member signature");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;

    return true;
  }

  toJsonChangeOwnerUnsigned(version: uint8_t): ChangeProposalOwnerInfo {
    let j = <ChangeProposalOwnerInfo>{};

    j[JsonKeyType] = this._type;
    j[JsonKeyCategoryData] = this._categoryData;
    j[JsonKeyOwnerPublicKey] = this._ownerPublicKey.toString("hex");
    j[JsonKeyDraftHash] = this._draftHash.toString(16);
    if (version >= CRCProposalVersion01) {
      j[JsonKeyDraftData] = this.encodeDraftData(this._draftData);
    }

    j[JsonKeyTargetProposalHash] = this._targetProposalHash.toString(16);
    j[JsonKeyNewRecipient] = this._newRecipient.string();
    j[JsonKeyNewOwnerPublicKey] = this._newOwnerPublicKey.toString("hex");

    return j;
  }

  fromJsonChangeOwnerUnsigned(j: ChangeProposalOwnerInfo, version: uint8_t) {
    this._type = j[JsonKeyType];
    this._categoryData = j[JsonKeyCategoryData];
    this._ownerPublicKey = Buffer.from(j[JsonKeyOwnerPublicKey], "hex");
    this._draftHash = new BigNumber(j[JsonKeyDraftHash], 16);
    if (version >= CRCProposalVersion01) {
      let draftData = j[JsonKeyDraftData];
      this._draftData = this.checkAndDecodeDraftData(
        draftData,
        this._draftHash
      );
    }
    this._targetProposalHash = new BigNumber(j[JsonKeyTargetProposalHash], 16);
    this._newRecipient = Address.newFromAddressString(j[JsonKeyNewRecipient]);
    this._newOwnerPublicKey = Buffer.from(j[JsonKeyNewOwnerPublicKey], "hex");
  }

  toJsonChangeOwnerCRCouncilMemberUnsigned(
    version: uint8_t
  ): ChangeProposalOwnerInfo {
    let j = this.toJsonChangeOwnerUnsigned(version);

    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyNewOwnerSignature] = this._newOwnerSignature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();

    return j;
  }

  fromJsonChangeOwnerCRCouncilMemberUnsigned(
    j: ChangeProposalOwnerInfo,
    version: uint8_t
  ) {
    this.fromJsonChangeOwnerUnsigned(j, version);

    this._signature = Buffer.from(j[JsonKeySignature], "hex");
    this._newOwnerSignature = Buffer.from(j[JsonKeyNewOwnerSignature], "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID]
    );
  }

  isValidChangeOwnerUnsigned(version: uint8_t): boolean {
    if (this._type != CRCProposalType.changeProposalOwner) {
      Log.error("invalid type: {}", this._type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      Log.error("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
      let key1 = EcdsaSigner.getKeyFromPublic(this._newOwnerPublicKey);
    } catch (e) {
      Log.error("invalid publick keys");
      return false;
    }

    if (this._draftHash.isZero() || this._targetProposalHash.isZero()) {
      Log.error("invalid hash");
      return false;
    }

    if (!this._newRecipient.valid()) {
      Log.error("invalid new recipient");
      return false;
    }

    return true;
  }

  isValidChangeOwnerCRCouncilMemberUnsigned(version: uint8_t): boolean {
    if (!this.isValidChangeOwnerUnsigned(version)) {
      return false;
    }

    try {
      const data = this.digestChangeOwnerUnsigned(version).toString(16);
      if (
        !EcdsaSigner.verify(
          this._ownerPublicKey,
          this._signature,
          Buffer.from(data, "hex")
        )
      ) {
        Log.error("verify signature fail");
        return false;
      }

      if (
        !EcdsaSigner.verify(
          this._newOwnerPublicKey,
          this._newOwnerSignature,
          Buffer.from(data, "hex")
        )
      ) {
        Log.error("verify new owner signature fail");
        return false;
      }
    } catch (e) {
      Log.error("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      Log.error("invalid cr council member did");
      return false;
    }

    return true;
  }

  digestChangeOwnerUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeChangeOwnerUnsigned(stream, version);
    const rs = SHA256.encodeToBuffer(stream.getBytes()).toString("hex");
    return new BigNumber(rs, 16);
  }

  digestChangeOwnerCRCouncilMemberUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeChangeOwnerCRCouncilMemberUnsigned(stream, version);
    const rs = SHA256.encodeToBuffer(stream.getBytes()).toString("hex");
    return new BigNumber(rs, 16);
  }

  // terminate proposal
  serializeTerminateProposalUnsigned(stream: ByteStream, version: uint8_t) {
    let type: uint16_t = this._type;
    stream.writeUInt16(type);
    stream.writeVarString(this._categoryData);
    stream.writeVarBytes(this._ownerPublicKey);
    stream.writeBNAsUIntOfSize(this._draftHash, 32);
    if (version >= CRCProposalVersion01) {
      stream.writeVarBytes(this._draftData);
    }

    stream.writeBNAsUIntOfSize(this._targetProposalHash, 32);
  }

  deserializeTerminateProposalUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    let categoryData = stream.readVarString();
    if (!categoryData) {
      Log.warn("deserialize terminate proposal category data");
      // return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      Log.error("deserialize terminate proposal owner pubkey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash = stream.readUIntOfBytesAsBN(32);
    if (!draftHash) {
      Log.error("deserialize terminate proposal draft hash");
      return false;
    }
    this._draftHash = draftHash;

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        Log.error("deserialize terminate proposal draftData");
        return false;
      }
      this._draftData = draftData;
    }

    let targetProposalHash = stream.readUIntOfBytesAsBN(32);
    if (!targetProposalHash) {
      Log.error("deserialize terminate proposal target proposal hash");
      return false;
    }
    this._targetProposalHash = targetProposalHash;

    return true;
  }

  serializeTerminateProposalCRCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ) {
    this.serializeTerminateProposalUnsigned(stream, version);

    stream.writeVarBytes(this._signature);
    stream.writeBytes(this._crCouncilMemberDID.programHash().bytes());
  }

  deserializeTerminateProposalCRCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ) {
    if (!this.deserializeTerminateProposalUnsigned(stream, version)) {
      Log.error("deserialize terminate proposal unsigned");
      return false;
    }

    let signature: bytes_t;
    signature = stream.readVarBytes(signature);
    if (!signature) {
      Log.error("deserialize terminate proposal signature");
      return false;
    }

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize sponsor did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    return true;
  }

  serializeTerminateProposal(stream: ByteStream, version: uint8_t) {
    this.serializeTerminateProposalCRCouncilMemberUnsigned(stream, version);

    stream.writeVarBytes(this._crCouncilMemberSignature);
  }

  deserializeTerminateProposal(stream: ByteStream, version: uint8_t): boolean {
    if (
      !this.deserializeTerminateProposalCRCouncilMemberUnsigned(stream, version)
    ) {
      Log.error("deserialize terminate proposal cr council member unsigned");
      return false;
    }

    let crCouncilMemberSignature: bytes_t;
    crCouncilMemberSignature = stream.readVarBytes(crCouncilMemberSignature);
    if (!crCouncilMemberSignature) {
      Log.error("deserialize change owner cr council member signature");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;

    return true;
  }

  toJsonTerminateProposalOwnerUnsigned(
    version: uint8_t
  ): TerminateProposalOwnerInfo {
    let j = <TerminateProposalOwnerInfo>{};

    j[JsonKeyType] = this._type;
    j[JsonKeyCategoryData] = this._categoryData;
    j[JsonKeyOwnerPublicKey] = this._ownerPublicKey.toString("hex");
    j[JsonKeyDraftHash] = this._draftHash.toString(16);
    if (version >= CRCProposalVersion01) {
      j[JsonKeyDraftData] = this.encodeDraftData(this._draftData);
    }

    j[JsonKeyTargetProposalHash] = this._targetProposalHash.toString(16);
    return j;
  }

  fromJsonTerminateProposalOwnerUnsigned(
    j: TerminateProposalOwnerInfo,
    version: uint8_t
  ) {
    this._type = j[JsonKeyType] as CRCProposalType;
    this._categoryData = j[JsonKeyCategoryData] as string;
    this._ownerPublicKey = Buffer.from(
      j[JsonKeyOwnerPublicKey] as string,
      "hex"
    );
    this._draftHash = new BigNumber(j[JsonKeyDraftHash] as string, 16);
    if (version >= CRCProposalVersion01) {
      let draftData: string = j[JsonKeyDraftData] as string;
      this._draftData = this.checkAndDecodeDraftData(
        draftData,
        this._draftHash
      );
    }
    this._targetProposalHash = new BigNumber(
      j[JsonKeyTargetProposalHash] as string,
      16
    );
  }

  toJsonTerminateProposalCRCouncilMemberUnsigned(version: uint8_t) {
    let j = this.toJsonTerminateProposalOwnerUnsigned(version);

    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();

    return j;
  }

  fromJsonTerminateProposalCRCouncilMemberUnsigned(
    j: TerminateProposalOwnerInfo,
    version: uint8_t
  ) {
    this.fromJsonTerminateProposalOwnerUnsigned(j, version);

    this._signature = Buffer.from(j[JsonKeySignature] as string, "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  isValidTerminateProposalOwnerUnsigned(version: uint8_t) {
    if (this._type != CRCProposalType.terminateProposal) {
      Log.error("invalid type: {}", this._type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      Log.error("category data exceed 4096 bytes");
      return false;
    }

    try {
      // Key key(CTElastos, _ownerPublicKey);
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      Log.error("invalid public keys");
      return false;
    }

    if (this._draftHash.eq(0) || this._targetProposalHash.eq(0)) {
      Log.error("invalid hash");
      return false;
    }

    return true;
  }

  isValidTerminateProposalCRCouncilMemberUnsigned(version: uint8_t) {
    if (!this.isValidTerminateProposalOwnerUnsigned(version)) {
      Log.error("terminate proposal unsigned is not valid");
      return false;
    }

    try {
      const data = this.digestTerminateProposalOwnerUnsigned(version);
      if (
        !EcdsaSigner.verify(
          this._ownerPublicKey,
          this._signature,
          Buffer.from(data.toString(16), "hex")
        )
      ) {
        Log.error("verify signature fail");
        return false;
      }
    } catch (e) {
      Log.error("verify signature exception: {}", e);
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      Log.error("invalid cr council member did");
      return false;
    }

    return true;
  }

  digestTerminateProposalOwnerUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeTerminateProposalUnsigned(stream, version);

    const rs = SHA256.encodeToBuffer(stream.getBytes()).toString("hex");
    return new BigNumber(rs, 16);
  }

  digestTerminateProposalCRCouncilMemberUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeTerminateProposalCRCouncilMemberUnsigned(stream, version);
    const rs = SHA256.encodeToBuffer(stream.getBytes()).toString("hex");
    return new BigNumber(rs, 16);
  }

  // change secretary general
  serializeSecretaryElectionUnsigned(stream: ByteStream, version: uint8_t) {
    stream.writeUInt16(this._type);
    stream.writeVarString(this._categoryData);
    stream.writeVarBytes(this._ownerPublicKey);
    stream.writeBNAsUIntOfSize(this._draftHash, 32);
    if (version >= CRCProposalVersion01) {
      stream.writeVarBytes(this._draftData);
    }

    stream.writeVarBytes(this._secretaryPublicKey);
    stream.writeBytes(this._secretaryDID.programHash().bytes());
  }

  deserializeSecretaryElectionUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    let categoryData = stream.readVarString();
    if (!categoryData) {
      Log.error("deserialize category data");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      Log.error("deserialize owner pubkey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash = stream.readUIntOfBytesAsBN(32);
    if (!draftHash) {
      Log.error("deserialize draft hash");
      return false;
    }
    this._draftHash = draftHash;

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        Log.error("deserialize draft data");
        return false;
      }
      this._draftData = draftData;
    }

    let secretaryPublicKey: bytes_t;
    secretaryPublicKey = stream.readVarBytes(secretaryPublicKey);
    if (!secretaryPublicKey) {
      Log.error("deserialize secretary pubkey");
      return false;
    }
    this._secretaryPublicKey = secretaryPublicKey;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize sponsor did");
      return false;
    }

    this._secretaryDID = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    return true;
  }

  serializeSecretaryElectionCRCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ) {
    this.serializeSecretaryElectionUnsigned(stream, version);

    stream.writeVarBytes(this._signature);
    stream.writeVarBytes(this._secretarySignature);
    stream.writeBytes(this._crCouncilMemberDID.programHash().bytes());
  }

  deserializeSecretaryElectionCRCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    if (!this.deserializeSecretaryElectionUnsigned(stream, version)) {
      Log.error("deserialize change secretary secretary unsigned");
      return false;
    }

    if (!stream.readVarBytes(this._signature)) {
      Log.error("deserialize signature");
      return false;
    }

    if (!stream.readVarBytes(this._secretarySignature)) {
      Log.error("deserialize secretary signature");
      return false;
    }

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize cr council mem did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    return true;
  }

  serializeSecretaryElection(stream: ByteStream, version: uint8_t) {
    this.serializeSecretaryElectionCRCouncilMemberUnsigned(stream, version);

    stream.writeVarBytes(this._crCouncilMemberSignature);
  }

  deserializeSecretaryElection(stream: ByteStream, version: uint8_t): boolean {
    if (
      !this.deserializeSecretaryElectionCRCouncilMemberUnsigned(stream, version)
    ) {
      return false;
    }

    if (!stream.readVarBytes(this._crCouncilMemberSignature)) {
      Log.error("deserialize change secretary cr council member signature");
      return false;
    }

    return true;
  }

  toJsonSecretaryElectionUnsigned(version: uint8_t): SecretaryElectionInfo {
    let j = <SecretaryElectionInfo>{};

    j[JsonKeyType] = this._type;
    j[JsonKeyCategoryData] = this._categoryData;
    j[JsonKeyOwnerPublicKey] = this._ownerPublicKey.toString("hex");
    j[JsonKeyDraftHash] = this._draftHash.toString(16);
    if (version >= CRCProposalVersion01) {
      j[JsonKeyDraftData] = this.encodeDraftData(this._draftData);
    }
    j[JsonKeySecretaryPublicKey] = this._secretaryPublicKey.toString("hex");
    j[JsonKeySecretaryDID] = this._secretaryDID.string();

    return j;
  }

  fromJsonSecretaryElectionUnsigned(
    j: SecretaryElectionInfo,
    version: uint8_t
  ) {
    this._type = j[JsonKeyType];
    this._categoryData = j[JsonKeyCategoryData];
    this._ownerPublicKey = Buffer.from(j[JsonKeyOwnerPublicKey], "hex");
    this._draftHash = new BigNumber(j[JsonKeyDraftHash], 16);
    if (version >= CRCProposalVersion01) {
      this._draftData = this.checkAndDecodeDraftData(
        j[JsonKeyDraftData],
        this._draftHash
      );
    }
    this._secretaryPublicKey = Buffer.from(j[JsonKeySecretaryPublicKey], "hex");
    this._secretaryDID = Address.newFromAddressString(j[JsonKeySecretaryDID]);
  }

  toJsonSecretaryElectionCRCouncilMemberUnsigned(
    version: uint8_t
  ): SecretaryElectionInfo {
    let j = <SecretaryElectionInfo>{};

    j = this.toJsonSecretaryElectionUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeySecretarySignature] = this._secretarySignature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();

    return j;
  }

  fromJsonSecretaryElectionCRCouncilMemberUnsigned(
    j: SecretaryElectionInfo,
    version: uint8_t
  ) {
    this.fromJsonSecretaryElectionUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature] as string);
    this._secretarySignature = Buffer.from(
      j[JsonKeySecretarySignature] as string
    );
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  isValidSecretaryElectionUnsigned(version: uint8_t): boolean {
    if (this._type != CRCProposalType.secretaryGeneralElection) {
      Log.error("invalid type: {}", this._type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      Log.error("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
      let key1 = EcdsaSigner.getKeyFromPublic(this._secretaryPublicKey);
    } catch (e) {
      Log.error("invalid public keys");
      return false;
    }

    if (!this._secretaryDID.valid()) {
      Log.error("invalid secretary did");
      return false;
    }

    return true;
  }

  isValidSecretaryElectionCRCouncilMemberUnsigned(version: uint8_t): boolean {
    if (!this.isValidSecretaryElectionUnsigned(version)) {
      Log.error("secretary election secretary unsigned not valid");
      return false;
    }

    try {
      let rs = this.digestSecretaryElectionUnsigned(version);
      if (
        !EcdsaSigner.verify(
          this._ownerPublicKey,
          this._signature,
          Buffer.from(rs.toString(16), "hex")
        )
      ) {
        Log.error("verify owner signature fail");
        return false;
      }
      if (
        !EcdsaSigner.verify(
          this._secretaryPublicKey,
          this._secretarySignature,
          Buffer.from(rs.toString(16), "hex")
        )
      ) {
        Log.error("verify secretary signature fail");
        return false;
      }
    } catch (e) {
      Log.error("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      Log.error("invalid cr committee did");
      return false;
    }

    return true;
  }

  digestSecretaryElectionUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeSecretaryElectionUnsigned(stream, version);
    const rs = SHA256.encodeToBuffer(stream.getBytes()).toString("hex");
    return new BigNumber(rs, 16);
  }

  digestSecretaryElectionCRCouncilMemberUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeSecretaryElectionCRCouncilMemberUnsigned(stream, version);
    const rs = SHA256.encodeToBuffer(stream.getBytes()).toString("hex");
    return new BigNumber(rs, 16);
  }

  serializeReserveCustomIDUnsigned(stream: ByteStream, version: uint8_t) {
    let type: uint16_t = this._type;
    stream.writeUInt16(type);
    stream.writeVarString(this._categoryData);
    stream.writeVarBytes(this._ownerPublicKey);
    // stream.writeBytes(this._draftHash);
    stream.writeBNAsUIntOfSize(this._draftHash, 21);
    if (version >= CRCProposalVersion01) {
      stream.writeVarBytes(this._draftData);
    }

    stream.writeVarUInt(this._reservedCustomIDList.length);
    for (let reservedCustomID of this._reservedCustomIDList) {
      stream.writeVarString(reservedCustomID);
    }
  }

  deserializeReserveCustomIDUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    let categoryData = stream.readVarString();
    if (!categoryData) {
      Log.error("deserialize reserved custom id category data");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      Log.error("deserialize reserved custom id owner pubkey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash: bytes_t;
    draftHash = stream.readBytes(draftHash, 32);
    if (!draftHash) {
      Log.error("deserialize reserved custom id draft hash");
      return false;
    }
    this._draftHash = new BigNumber(draftHash.toString("hex"), 16);

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        Log.error("deserialize reserved custom id draft data");
        return false;
      }
      this._draftData = draftData;
    }

    let size: uint64_t = new BigNumber(0);
    size = stream.readVarUInt();
    if (!size) {
      Log.error("deserialize reserved custom id list size");
      return false;
    }
    for (let i = 0; i < size.toNumber(); ++i) {
      let reservedCustomID: string = stream.readVarString();
      if (!reservedCustomID) {
        Log.error("deserialize reserved custom id list[{}]", i);
        return false;
      }
      this._reservedCustomIDList.push(reservedCustomID);
    }

    return true;
  }

  serializeReserveCustomIDCRCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ) {
    this.serializeReserveCustomIDUnsigned(stream, version);
    stream.writeVarBytes(this._signature);
    stream.writeBytes(this._crCouncilMemberDID.programHash().bytes());
  }

  deserializeReserveCustomIDCRCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ) {
    if (!this.deserializeReserveCustomIDUnsigned(stream, version)) {
      return false;
    }

    let signature: bytes_t;
    signature = stream.readVarBytes(signature);
    if (!signature) {
      Log.error("deserialize reserved custom id signature");
      return false;
    }
    this._signature = signature;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize cr council mem did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    return true;
  }

  serializeReserveCustomID(stream: ByteStream, version: uint8_t) {
    this.serializeReserveCustomIDCRCouncilMemberUnsigned(stream, version);
    stream.writeVarBytes(this._crCouncilMemberSignature);
  }

  deserializeReserveCustomID(stream: ByteStream, version: uint8_t): boolean {
    if (
      !this.deserializeReserveCustomIDCRCouncilMemberUnsigned(stream, version)
    ) {
      return false;
    }

    let crCouncilMemberSignature: bytes_t;
    crCouncilMemberSignature = stream.readVarBytes(crCouncilMemberSignature);
    if (!crCouncilMemberSignature) {
      Log.error("deserialize reserved custom id council member sign");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;
    return true;
  }

  toJsonReserveCustomIDOwnerUnsigned(
    version: uint8_t
  ): ReserveCustomIDOwnerInfo {
    let j = <ReserveCustomIDOwnerInfo>{};

    j[JsonKeyType] = this._type;
    j[JsonKeyCategoryData] = this._categoryData;
    j[JsonKeyOwnerPublicKey] = this._ownerPublicKey.toString("hex");
    j[JsonKeyDraftHash] = this._draftHash.toString(16);
    if (version >= CRCProposalVersion01) {
      j[JsonKeyDraftData] = this.encodeDraftData(this._draftData);
    }
    j[JsonKeyReservedCustomIDList] = this._reservedCustomIDList;

    return j;
  }

  fromJsonReserveCustomIDOwnerUnsigned(
    j: ReserveCustomIDOwnerInfo,
    version: uint8_t
  ) {
    this._type = j[JsonKeyType];
    this._categoryData = j[JsonKeyCategoryData];
    this._ownerPublicKey = Buffer.from(j[JsonKeyOwnerPublicKey], "hex");
    this._draftHash = new BigNumber(j[JsonKeyDraftHash], 16);
    if (version >= CRCProposalVersion01) {
      this._draftData = this.checkAndDecodeDraftData(
        j[JsonKeyDraftData],
        this._draftHash
      );
    }
    this._reservedCustomIDList = j[JsonKeyReservedCustomIDList];
  }

  toJsonReserveCustomIDCRCouncilMemberUnsigned(version: uint8_t) {
    let j = this.toJsonReserveCustomIDOwnerUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();
    return j;
  }

  fromJsonReserveCustomIDCRCouncilMemberUnsigned(
    j: ReserveCustomIDOwnerInfo,
    version: uint8_t
  ) {
    this.fromJsonReserveCustomIDOwnerUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature] as string, "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  isValidReserveCustomIDOwnerUnsigned(version: uint8_t): boolean {
    if (this._type != CRCProposalType.reserveCustomID) {
      Log.error("invalid type: {}", this._type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      Log.error("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      Log.error("invalid reserve custom id pubkey");
      return false;
    }

    return true;
  }

  isValidReserveCustomIDCRCouncilMemberUnsigned(version: uint8_t): boolean {
    if (!this.isValidReserveCustomIDOwnerUnsigned(version)) return false;

    try {
      let rs = this.digestReserveCustomIDOwnerUnsigned(version);

      if (
        !EcdsaSigner.verify(
          this._ownerPublicKey,
          this._signature,
          Buffer.from(rs.toString(16), "hex")
        )
      ) {
        Log.error("reserve custom id verify owner signature fail");
        return false;
      }
    } catch (e) {
      Log.error("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      Log.error("invalid cr committee did");
      return false;
    }

    return true;
  }

  digestReserveCustomIDOwnerUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeReserveCustomIDUnsigned(stream, version);
    let rs = SHA256.encodeToBuffer(stream.getBytes());
    return new BigNumber(rs.toString("hex"), 16);
  }

  digestReserveCustomIDCRCouncilMemberUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeReserveCustomIDCRCouncilMemberUnsigned(stream, version);
    let rs = SHA256.encodeToBuffer(stream.getBytes());
    return new BigNumber(rs.toString("hex"), 16);
  }

  // ReceiveCustomID
  serializeReceiveCustomIDUnsigned(stream: ByteStream, version: uint8_t) {
    let type: uint16_t = this._type;
    stream.writeUInt16(type);
    stream.writeVarString(this._categoryData);
    stream.writeVarBytes(this._ownerPublicKey);
    // stream.writeBytes(_draftHash);
    stream.writeBNAsUIntOfSize(this._draftHash, 32);
    if (version >= CRCProposalVersion01) {
      stream.writeVarBytes(this._draftData);
    }

    stream.writeVarUInt(this._receivedCustomIDList.length);
    for (let receivedCustomID of this._receivedCustomIDList) {
      stream.writeVarString(receivedCustomID);
    }

    stream.writeBytes(this._receiverDID.programHash().bytes());
  }

  deserializeReceiveCustomIDUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    let categoryData = stream.readVarString();
    if (!categoryData) {
      Log.error("deserialize receive custom category data");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      Log.error("deserialize receive custom owner pubkey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash: BigNumber;
    draftHash = stream.readUIntOfBytesAsBN(32);
    if (!draftHash) {
      Log.error("deserialize receive custom draft hash");
      return false;
    }
    this._draftHash = draftHash;

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        Log.error("deserialize receive custom draft data");
        return false;
      }
      this._draftData = draftData;
    }

    let size = stream.readVarUInt();
    if (!size) {
      Log.error("deserialize receive custom id list size");
      return false;
    }
    for (let i = 0; i < size.toNumber(); ++i) {
      let receivedCustomID = stream.readVarString();
      if (!receivedCustomID) {
        Log.error("deserialize receive custom id list[{}]", i);
        return false;
      }
      this._receivedCustomIDList.push(receivedCustomID);
    }

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize receiver did");
      return false;
    }
    this._receiverDID = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    return true;
  }

  serializeReceiveCustomIDCRCCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ) {
    this.serializeReceiveCustomIDUnsigned(stream, version);
    stream.writeVarBytes(this._signature);
    stream.writeBytes(this._crCouncilMemberDID.programHash().bytes());
  }

  deserializeReceiveCustomIDCRCCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    if (!this.deserializeReceiveCustomIDUnsigned(stream, version)) {
      return false;
    }

    let signature: bytes_t;
    signature = stream.readVarBytes(signature);
    if (!signature) {
      Log.error("deserialize reserved custom id signature");
      return false;
    }
    this._signature = signature;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize cr council mem did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    return true;
  }

  serializeReceiveCustomID(stream: ByteStream, version: uint8_t) {
    this.serializeReceiveCustomIDCRCCouncilMemberUnsigned(stream, version);
    stream.writeVarBytes(this._crCouncilMemberSignature);
  }

  deserializeReceiveCustomID(stream: ByteStream, version: uint8_t): boolean {
    if (
      !this.deserializeReceiveCustomIDCRCCouncilMemberUnsigned(stream, version)
    ) {
      return false;
    }

    let crCouncilMemberSignature: bytes_t;
    crCouncilMemberSignature = stream.readVarBytes(crCouncilMemberSignature);
    if (!crCouncilMemberSignature) {
      Log.error("deserialize receive custom id council member sign");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;

    return true;
  }

  toJsonReceiveCustomIDOwnerUnsigned(version: uint8_t) {
    let j = <ReceiveCustomIDOwnerInfo>{};

    j[JsonKeyType] = this._type;
    j[JsonKeyCategoryData] = this._categoryData;
    j[JsonKeyOwnerPublicKey] = this._ownerPublicKey.toString("hex");
    j[JsonKeyDraftHash] = this._draftHash.toString(16);
    if (version >= CRCProposalVersion01) {
      j[JsonKeyDraftData] = this.encodeDraftData(this._draftData);
    }

    j[JsonKeyReceivedCustomIDList] = this._receivedCustomIDList;
    j[JsonKeyReceiverDID] = this._receiverDID.string();

    return j;
  }

  fromJsonReceiveCustomIDOwnerUnsigned(
    j: ReceiveCustomIDOwnerInfo,
    version: uint8_t
  ) {
    this._type = j[JsonKeyType] as CRCProposalType;
    this._categoryData = j[JsonKeyCategoryData] as string;
    this._ownerPublicKey = Buffer.from(
      j[JsonKeyOwnerPublicKey] as string,
      "hex"
    );
    this._draftHash = new BigNumber(j[JsonKeyDraftHash] as string, 16);
    if (version >= CRCProposalVersion01) {
      let draftData: string = j[JsonKeyDraftData] as string;
      this._draftData = this.checkAndDecodeDraftData(
        draftData,
        this._draftHash
      );
    }
    this._receivedCustomIDList = j[JsonKeyReservedCustomIDList] as string[];
    this._receiverDID = Address.newFromAddressString(
      j[JsonKeyReceiverDID] as string
    );
  }

  toJsonReceiveCustomIDCRCouncilMemberUnsigned(
    version: uint8_t
  ): ReceiveCustomIDOwnerInfo {
    let j = this.toJsonReceiveCustomIDOwnerUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();
    return j;
  }

  fromJsonReceiveCustomIDCRCouncilMemberUnsigned(
    j: ReceiveCustomIDOwnerInfo,
    version: uint8_t
  ) {
    this.fromJsonReceiveCustomIDOwnerUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature] as string, "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  isValidReceiveCustomIDOwnerUnsigned(version: uint8_t): boolean {
    if (this._type != CRCProposalType.receiveCustomID) {
      Log.error("invalid type: {}", this._type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      Log.error("category data exceed 4096 bytes");
      return false;
    }

    try {
      // Key key(CTElastos, _ownerPublicKey);
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      Log.error("invalid reserve custom id pubkey");
      return false;
    }

    return true;
  }

  isValidReceiveCustomIDCRCouncilMemberUnsigned(version: uint8_t): boolean {
    if (!this.isValidReceiveCustomIDOwnerUnsigned(version)) return false;

    try {
      let rs = this.digestReceiveCustomIDOwnerUnsigned(version);
      if (
        !EcdsaSigner.verify(
          this._ownerPublicKey,
          this._signature,
          Buffer.from(rs.toString(16), "hex")
        )
      ) {
        Log.error("receive custom id verify owner signature fail");
        return false;
      }
    } catch (e) {
      Log.error("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      Log.error("invalid cr committee did");
      return false;
    }

    return true;
  }

  digestReceiveCustomIDOwnerUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeReceiveCustomIDUnsigned(stream, version);
    let rs = SHA256.encodeToBuffer(stream.getBytes());
    return new BigNumber(rs.toString("hex"), 16);
  }

  digestReceiveCustomIDCRCouncilMemberUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeReceiveCustomIDCRCCouncilMemberUnsigned(stream, version);
    let rs = SHA256.encodeToBuffer(stream.getBytes());
    return new BigNumber(rs.toString("hex"), 16);
  }

  // ChangeCustomIDFee
  serializeChangeCustomIDFeeUnsigned(stream: ByteStream, version: uint8_t) {
    let type: uint16_t = this._type;
    stream.writeUInt16(type);
    stream.writeVarString(this._categoryData);
    stream.writeVarBytes(this._ownerPublicKey);
    // stream.writeBytes(_draftHash);
    stream.writeBNAsUIntOfSize(this._draftHash, 32);
    if (version >= CRCProposalVersion01) {
      stream.writeVarBytes(this._draftData);
    }

    this._customIDFeeRateInfo.serialize(stream, version);
  }

  deserializeChangeCustomIDFeeUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    let categoryData = stream.readVarString();
    if (!categoryData) {
      Log.error("deserialize change custom id category data");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      Log.error("deserialize change custom id owner pubkey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash = new BigNumber(0);
    draftHash = stream.readUIntOfBytesAsBN(32);
    if (!draftHash) {
      Log.error("deserialize change custom id draft hash");
      return false;
    }
    this._draftHash = draftHash;

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        Log.error("deserialize change custom id draft data");
        return false;
      }
      this._draftData = draftData;
    }

    let customIDFeeRateInfo = new CustomIDFeeRateInfo();
    if (!customIDFeeRateInfo.deserialize(stream, version)) {
      Log.error("deserialize change custom id fee");
      return false;
    }
    this._customIDFeeRateInfo = customIDFeeRateInfo;
    return true;
  }

  serializeChangeCustomIDFeeCRCCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ) {
    this.serializeChangeCustomIDFeeUnsigned(stream, version);
    stream.writeVarBytes(this._signature);
    stream.writeBytes(this._crCouncilMemberDID.programHash().bytes());
  }

  deserializeChangeCustomIDFeeCRCCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    if (!this.deserializeChangeCustomIDFeeUnsigned(stream, version)) {
      return false;
    }

    let signature: bytes_t;
    signature = stream.readVarBytes(signature);
    if (!signature) {
      Log.error("deserialize change custom id fee signature");
      return false;
    }
    this._signature = signature;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize change custom id fee cr council mem did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    return true;
  }

  serializeChangeCustomIDFee(stream: ByteStream, version: uint8_t) {
    this.serializeChangeCustomIDFeeCRCCouncilMemberUnsigned(stream, version);
    stream.writeVarBytes(this._crCouncilMemberSignature);
  }

  deserializeChangeCustomIDFee(stream: ByteStream, version: uint8_t): boolean {
    if (
      !this.deserializeChangeCustomIDFeeCRCCouncilMemberUnsigned(
        stream,
        version
      )
    ) {
      return false;
    }

    let crCouncilMemberSignature: bytes_t;
    crCouncilMemberSignature = stream.readVarBytes(crCouncilMemberSignature);
    if (!crCouncilMemberSignature) {
      Log.error("deserialize change custom id fee council mem sign");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;

    return true;
  }

  toJsonChangeCustomIDFeeOwnerUnsigned(version: uint8_t) {
    let j = <ChangeCustomIDFeeOwnerInfo>{};

    j[JsonKeyType] = this._type;
    j[JsonKeyCategoryData] = this._categoryData;
    j[JsonKeyOwnerPublicKey] = this._ownerPublicKey.toString("hex");
    j[JsonKeyDraftHash] = this._draftHash.toString(16);
    if (version >= CRCProposalVersion01) {
      j[JsonKeyDraftData] = this.encodeDraftData(this._draftData);
    }

    j[JsonKeyCustomIDFeeRateInfo] = this._customIDFeeRateInfo.toJson(version);

    return j;
  }

  fromJsonChangeCustomIDFeeOwnerUnsigned(
    j: ChangeCustomIDFeeOwnerInfo,
    version: uint8_t
  ) {
    this._type = j[JsonKeyType];
    this._categoryData = j[JsonKeyCategoryData];
    this._ownerPublicKey = Buffer.from(j[JsonKeyOwnerPublicKey], "hex");
    this._draftHash = new BigNumber(j[JsonKeyDraftHash], 16);
    if (version >= CRCProposalVersion01) {
      this._draftData = this.checkAndDecodeDraftData(
        j[JsonKeyDraftData],
        this._draftHash
      );
    }
    this._customIDFeeRateInfo.fromJson(j[JsonKeyCustomIDFeeRateInfo], version);
  }

  toJsonChangeCustomIDFeeCRCouncilMemberUnsigned(version: uint8_t) {
    let j = this.toJsonChangeCustomIDFeeOwnerUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();
    return j;
  }

  fromJsonChangeCustomIDFeeCRCouncilMemberUnsigned(
    j: ChangeCustomIDFeeOwnerInfo,
    version: uint8_t
  ) {
    this.fromJsonChangeCustomIDFeeOwnerUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature] as string, "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  isValidChangeCustomIDFeeOwnerUnsigned(version: uint8_t) {
    if (this._type != CRCProposalType.changeCustomIDFee) {
      Log.error("invalid type: {}", this._type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      Log.error("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      Log.error("invalid reserve custom id pubkey");
      return false;
    }

    return true;
  }

  isValidChangeCustomIDFeeCRCouncilMemberUnsigned(version: uint8_t): boolean {
    if (!this.isValidChangeCustomIDFeeOwnerUnsigned(version)) return false;

    try {
      let rs = this.digestChangeCustomIDFeeOwnerUnsigned(version);
      if (
        !EcdsaSigner.verify(
          this._ownerPublicKey,
          this._signature,
          Buffer.from(rs.toString(16), "hex")
        )
      ) {
        Log.error("change custom id fee verify owner signature fail");
        return false;
      }
    } catch (e) {
      Log.error("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      Log.error("invalid cr committee did");
      return false;
    }

    return true;
  }

  digestChangeCustomIDFeeOwnerUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeChangeCustomIDFeeUnsigned(stream, version);
    let rs = SHA256.encodeToBuffer(stream.getBytes());
    return new BigNumber(rs.toString("hex"), 16);
  }

  digestChangeCustomIDFeeCRCouncilMemberUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeChangeCustomIDFeeCRCCouncilMemberUnsigned(stream, version);
    let rs = SHA256.encodeToBuffer(stream.getBytes());
    return new BigNumber(rs.toString("hex"), 16);
  }

  serializeRegisterSidechainUnsigned(stream: ByteStream, version: uint8_t) {
    let type: uint16_t = this._type;
    stream.writeUInt16(type);
    stream.writeVarString(this._categoryData);
    stream.writeVarBytes(this._ownerPublicKey);

    stream.writeBNAsUIntOfSize(this._draftHash, 32);
    if (version >= CRCProposalVersion01) {
      stream.writeVarBytes(this._draftData);
    }

    this._sidechainInfo.serialize(stream, version);
  }

  deserializeRegisterSidechainUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    let categoryData = stream.readVarString();
    if (!categoryData) {
      Log.error("deserialize change custom id category data");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      Log.error("deserialize change custom id owner pubkey");
      return false;
    }

    let draftHash: bytes_t;
    draftHash = stream.readBytes(draftHash, 32);

    if (!draftHash) {
      Log.error("deserialize change custom id draft hash");
      return false;
    }
    this._draftHash = new BigNumber(draftHash.toString("hex"), 16);

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        Log.error("deserialize change custom id draft data");
        return false;
      }
      this._draftData = draftData;
    }

    let sidechainInfo = new SideChainInfo();
    if (!sidechainInfo.deserialize(stream, version)) {
      Log.error("deserialize change custom id fee");
      return false;
    }
    this._sidechainInfo = sidechainInfo;
    return true;
  }

  serializeRegisterSidechainCRCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ) {
    this.serializeRegisterSidechainUnsigned(stream, version);
    stream.writeVarBytes(this._signature);
    stream.writeBytes(this._crCouncilMemberDID.programHash().bytes());
  }

  deserializeRegisterSidechainCRCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    if (!this.deserializeRegisterSidechainUnsigned(stream, version)) {
      return false;
    }
    let signature: bytes_t;
    signature = stream.readVarBytes(signature);
    if (!signature) {
      Log.error("deserialize id signature");
      return false;
    }
    this._signature = signature;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize cr council mem did");
      return false;
    }

    this._crCouncilMemberDID = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );
    return true;
  }

  serializeRegisterSidechain(stream: ByteStream, version: uint8_t) {
    this.serializeRegisterSidechainCRCouncilMemberUnsigned(stream, version);
    stream.writeVarBytes(this._crCouncilMemberSignature);
  }

  deserializeRegisterSidechain(stream: ByteStream, version: uint8_t): boolean {
    if (
      !this.deserializeRegisterSidechainCRCouncilMemberUnsigned(stream, version)
    ) {
      return false;
    }

    let crCouncilMemberSignature: bytes_t;
    crCouncilMemberSignature = stream.readVarBytes(crCouncilMemberSignature);
    if (!crCouncilMemberSignature) {
      Log.error("deserialize register side-chain council member sign");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;
    return true;
  }

  toJsonRegisterSidechainUnsigned(
    version: uint8_t
  ): RegisterSidechainProposalInfo {
    let j = <RegisterSidechainProposalInfo>{};

    j[JsonKeyType] = this._type;
    j[JsonKeyCategoryData] = this._categoryData;
    j[JsonKeyOwnerPublicKey] = this._ownerPublicKey.toString("hex");
    j[JsonKeyDraftHash] = this._draftHash.toString(16);
    if (version >= CRCProposalVersion01) {
      j[JsonKeyDraftData] = this.encodeDraftData(this._draftData);
    }

    j[JsonKeySidechainInfo] = this._sidechainInfo.toJson(version);

    return j;
  }

  fromJsonRegisterSidechainUnsigned(
    j: RegisterSidechainProposalInfo,
    version: uint8_t
  ) {
    this._categoryData = j[JsonKeyCategoryData];
    this._ownerPublicKey = Buffer.from(j[JsonKeyOwnerPublicKey], "hex");
    this._draftHash = new BigNumber((j[JsonKeyDraftHash], 16));
    if (version >= CRCProposalVersion01) {
      this._draftData = this.checkAndDecodeDraftData(
        j[JsonKeyDraftData],
        this._draftHash
      );
    }
    this._sidechainInfo.fromJson(j[JsonKeySidechainInfo], version);
  }

  toJsonRegisterSidechainCRCouncilMemberUnsigned(
    version: uint8_t
  ): RegisterSidechainProposalInfo {
    let j = this.toJsonRegisterSidechainUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();
    return j;
  }

  fromJsonRegisterSidechainCRCouncilMemberUnsigned(
    j: RegisterSidechainProposalInfo,
    version: uint8_t
  ) {
    this.fromJsonRegisterSidechainUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature] as string, "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  isValidRegisterSidechainUnsigned(version: uint8_t): boolean {
    if (this._type != CRCProposalType.registerSideChain) {
      Log.error("invalid type: {}", this._type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      Log.error("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      Log.error("invalid reserve custom id pubkey");
      return false;
    }

    if (!this._sidechainInfo.isValid(version)) {
      return false;
    }

    return true;
  }

  isValidRegisterSidechainCRCouncilMemberUnsigned(version: uint8_t): boolean {
    if (!this.isValidRegisterSidechainUnsigned(version)) {
      return false;
    }

    try {
      let rs = this.digestRegisterSidechainUnsigned(version);
      if (
        !EcdsaSigner.verify(
          this._ownerPublicKey,
          this._signature,
          Buffer.from(rs.toString(16), "hex")
        )
      ) {
        Log.error("change register side-chain verify owner signature fail");
        return false;
      }
    } catch (e) {
      Log.error("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      Log.error("invalid cr committee did");
      return false;
    }

    return true;
  }

  digestRegisterSidechainUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeRegisterSidechainUnsigned(stream, version);
    let rs = SHA256.encodeToBuffer(stream.getBytes());
    return new BigNumber(rs.toString("hex"), 16);
  }

  digestRegisterSidechainCRCouncilMemberUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeRegisterSidechainCRCouncilMemberUnsigned(stream, version);
    let rs = SHA256.encodeToBuffer(stream.getBytes());
    return new BigNumber(rs.toString("hex"), 16);
  }

  // upgrade code
  serializeUpgradeCodeUnsigned(stream: ByteStream, version: uint8_t) {
    let type: uint16_t = this._type;
    stream.writeUInt16(type);
    stream.writeVarString(this._categoryData);
    stream.writeVarBytes(this._ownerPublicKey);
    // stream.writeBytes(_draftHash);
    stream.writeBNAsUIntOfSize(this._draftHash, 32);
    this._upgradeCodeInfo.serialize(stream, version);
  }

  deserializeUpgradeCodeUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    let categoryData = stream.readVarString();
    if (!categoryData) {
      Log.error("deserialize upgrade code category data");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      Log.error("deserialize upgrade code owner pubkey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash = stream.readUIntOfBytesAsBN(32);
    if (!draftHash) {
      Log.error("deserialize upgrade code draft hash");
      return false;
    }

    let upgradeCodeInfo = new UpgradeCodeInfo();
    if (!upgradeCodeInfo.deserialize(stream, version)) {
      Log.error("deserialize upgrade code");
      return false;
    }
    this._upgradeCodeInfo = upgradeCodeInfo;
    return true;
  }

  serializeUpgradeCodeCRCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ) {
    this.serializeUpgradeCodeUnsigned(stream, version);
    stream.writeVarBytes(this._signature);
    stream.writeBytes(this._crCouncilMemberDID.programHash().bytes());
  }

  deserializeUpgradeCodeCRCouncilMemberUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    if (!this.deserializeUpgradeCodeUnsigned(stream, version)) {
      return false;
    }

    let signature: bytes_t;
    signature = stream.readVarBytes(signature);
    if (!signature) {
      Log.error("deserialize upgrade code signature failed");
      return false;
    }

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      Log.error("deserialize upgrade code cr council did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromProgramHash(
      uint168.newFrom21BytesBuffer(programHash)
    );

    return true;
  }

  serializeUpgradeCode(stream: ByteStream, version: uint8_t) {
    this.serializeUpgradeCodeCRCouncilMemberUnsigned(stream, version);
    stream.writeVarBytes(this._crCouncilMemberSignature);
  }

  deserializeUpgradeCode(stream: ByteStream, version: uint8_t): boolean {
    if (!this.deserializeUpgradeCodeCRCouncilMemberUnsigned(stream, version)) {
      return false;
    }

    let crCouncilMemberSignature: bytes_t;
    crCouncilMemberSignature = stream.readVarBytes(crCouncilMemberSignature);
    if (!crCouncilMemberSignature) {
      Log.error("deserialize cr council mem sign failed");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;

    return true;
  }

  toJsonUpgradeCodeUnsigned(version: uint8_t): UpgradeCodeProposalInfo {
    let j = <UpgradeCodeProposalInfo>{};

    j[JsonKeyType] = this._type;
    j[JsonKeyCategoryData] = this._categoryData;
    j[JsonKeyOwnerPublicKey] = this._ownerPublicKey.toString("hex");
    j[JsonKeyDraftHash] = this._draftHash.toString(16);
    j[JsonKeyUpgradeCodeInfo] = this._upgradeCodeInfo.toJson(version);

    return j;
  }

  fromJsonUpgradeCode(j: UpgradeCodeProposalInfo, version: uint8_t) {
    let type = j[JsonKeyType];
    this._type = type;
    this._categoryData = j[JsonKeyCategoryData];
    this._ownerPublicKey = Buffer.from(j[JsonKeyOwnerPublicKey], "hex");
    this._draftHash = new BigNumber(j[JsonKeyDraftHash], 16);
    this._upgradeCodeInfo.fromJson(j[JsonKeyUpgradeCodeInfo], version);
  }

  toJsonUpgradeCodeCRCouncilMemberUnsigned(
    version: uint8_t
  ): UpgradeCodeProposalInfo {
    let j = this.toJsonUpgradeCodeUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();
    return j;
  }

  fromJsonUpgradeCodeCRCouncilMemberUnsigned(
    j: UpgradeCodeProposalInfo,
    version: uint8_t
  ) {
    this.fromJsonUpgradeCode(j, version);
    this._signature = Buffer.from(j[JsonKeySignature], "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID]
    );
  }

  isValidUpgradeCodeUnsigned(version: uint8_t): boolean {
    if (
      this._type != CRCProposalType.mainChainUpgradeCode &&
      this._type != CRCProposalType.ethUpdateCode &&
      this._type != CRCProposalType.didUpdateCode
    ) {
      Log.error("invalid type: {}", this._type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      Log.error("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      Log.error("invalid owner pubkey");
      return false;
    }

    if (!this._upgradeCodeInfo.isValid(version)) {
      return false;
    }

    return true;
  }

  isValidUpgradeCodeCRCouncilMemberUnsigned(version: uint8_t): boolean {
    if (!this.isValidUpgradeCodeUnsigned(version)) {
      return false;
    }

    try {
      if (
        !EcdsaSigner.verify(
          this._ownerPublicKey,
          this._signature,
          Buffer.from(
            this.digestUpgradeCodeUnsigned(version).toString(16),
            "hex"
          )
        )
      ) {
        Log.error("change upgrade code verify owner signature fail");
        return false;
      }
    } catch (e) {
      Log.error("verify signature exception: {}", e);
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      Log.error("invalid cr committee did");
      return false;
    }

    return true;
  }

  digestUpgradeCodeUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeUpgradeCodeUnsigned(stream, version);
    let rs = SHA256.encodeToBuffer(stream.getBytes());
    return new BigNumber(rs.toString("hex"), 16);
  }

  digestUpgradeCodeCRCouncilMemberUnsigned(version: uint8_t): uint256 {
    let stream = new ByteStream();
    this.serializeUpgradeCodeCRCouncilMemberUnsigned(stream, version);
    let rs = SHA256.encodeToBuffer(stream.getBytes());
    return new BigNumber(rs.toString("hex"), 16);
  }

  // top serialize or deserialize
  serialize(stream: ByteStream, version: uint8_t) {
    switch (this._type) {
      case CRCProposalType.changeProposalOwner:
        this.serializeChangeOwner(stream, version);
        break;

      case CRCProposalType.terminateProposal:
        this.serializeTerminateProposal(stream, version);
        break;

      case CRCProposalType.secretaryGeneralElection:
        this.serializeSecretaryElection(stream, version);
        break;

      case CRCProposalType.reserveCustomID:
        this.serializeReserveCustomID(stream, version);
        break;

      case CRCProposalType.receiveCustomID:
        this.serializeReceiveCustomID(stream, version);
        break;

      case CRCProposalType.changeCustomIDFee:
        this.serializeChangeCustomIDFee(stream, version);
        break;

      case CRCProposalType.registerSideChain:
        this.serializeRegisterSidechain(stream, version);
        break;

      case CRCProposalType.normal:
      case CRCProposalType.elip:
        this.serializeNormalOrELIP(stream, version);
        break;

      default:
        Log.error("serialize cr proposal unknown type");
        break;
    }
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    let type = stream.readUInt16();
    // ignore normal proposal
    if (!type && type !== 0) {
      Log.error("deserialize type");
      return false;
    }
    this._type = type as CRCProposalType;

    let r = false;
    switch (this._type) {
      case CRCProposalType.changeProposalOwner:
        r = this.deserializeChangeOwner(stream, version);
        break;

      case CRCProposalType.terminateProposal:
        r = this.deserializeTerminateProposal(stream, version);
        break;

      case CRCProposalType.secretaryGeneralElection:
        r = this.deserializeSecretaryElection(stream, version);
        break;

      case CRCProposalType.reserveCustomID:
        r = this.deserializeReserveCustomID(stream, version);
        break;

      case CRCProposalType.receiveCustomID:
        r = this.deserializeReceiveCustomID(stream, version);
        break;

      case CRCProposalType.changeCustomIDFee:
        r = this.deserializeChangeCustomIDFee(stream, version);
        break;

      case CRCProposalType.registerSideChain:
        r = this.deserializeRegisterSidechain(stream, version);
        break;

      case CRCProposalType.mainChainUpgradeCode:
      case CRCProposalType.didUpdateCode:
      case CRCProposalType.ethUpdateCode:
        r = this.deserializeUpgradeCode(stream, version);
        break;

      case CRCProposalType.normal:
      case CRCProposalType.elip:
        r = this.deserializeNormalOrELIP(stream, version);
        break;

      default:
        Log.error("unknow type: {}", this._type);
        r = false;
        break;
    }

    return r;
  }

  toJsonNormalOwnerUnsigned(version: uint8_t): NormalProposalOwnerInfo {
    let j = <NormalProposalOwnerInfo>{};
    j[JsonKeyType] = this._type;
    j[JsonKeyCategoryData] = this._categoryData;
    j[JsonKeyOwnerPublicKey] = this._ownerPublicKey.toString("hex");
    j[JsonKeyDraftHash] = this._draftHash.toString(16);
    if (version >= CRCProposalVersion01) {
      j[JsonKeyDraftData] = this.encodeDraftData(this._draftData);
    }
    let budgets: BudgetInfo[] = [];
    for (let i = 0; i < this._budgets.length; ++i) {
      budgets.push(this._budgets[i].toJson());
    }
    j[JsonKeyBudgets] = budgets;
    j[JsonKeyRecipient] = this._recipient.string();
    return j;
  }

  fromJsonNormalOwnerUnsigned(j: NormalProposalOwnerInfo, version: uint8_t) {
    this._type = j[JsonKeyType];
    this._categoryData = j[JsonKeyCategoryData];
    this._ownerPublicKey = Buffer.from(j[JsonKeyOwnerPublicKey], "hex");
    this._draftHash = new BigNumber(j[JsonKeyDraftHash], 16);
    if (version >= CRCProposalVersion01) {
      this._draftData = this.checkAndDecodeDraftData(
        j[JsonKeyDraftData],
        this._draftHash
      );
    }
    let budgets = j[JsonKeyBudgets];
    this._budgets = [];
    for (let i = 0; i < budgets.length; ++i) {
      let budget = new Budget();
      budget.fromJson(budgets[i]);
      this._budgets.push(budget);
    }

    this._recipient = Address.newFromAddressString(j[JsonKeyRecipient]);
  }

  toJsonNormalCRCouncilMemberUnsigned(
    version: uint8_t
  ): NormalProposalOwnerInfo {
    let j = this.toJsonNormalOwnerUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();
    return j;
  }

  fromJsonNormalCRCouncilMemberUnsigned(
    j: NormalProposalOwnerInfo,
    version: uint8_t
  ) {
    this.fromJsonNormalOwnerUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature], "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID]
    );
  }

  toJson(version: uint8_t) {
    let j = <CRCProposalInfo>{};
    switch (this._type) {
      case CRCProposalType.normal:
      case CRCProposalType.elip:
        j = this.toJsonNormalCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.secretaryGeneralElection:
        j = this.toJsonSecretaryElectionCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.changeProposalOwner:
        j = this.toJsonChangeOwnerCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.terminateProposal:
        j = this.toJsonTerminateProposalCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.reserveCustomID:
        j = this.toJsonReserveCustomIDCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.receiveCustomID:
        j = this.toJsonReceiveCustomIDCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.changeCustomIDFee:
        j = this.toJsonChangeCustomIDFeeCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.registerSideChain:
        j = this.toJsonRegisterSidechainCRCouncilMemberUnsigned(version);
        break;
      default:
        Log.error("unknow type: {}", this._type);
        return j;
    }
    j[JsonKeyCRCouncilMemberSignature] =
      this._crCouncilMemberSignature.toString("hex");
    return j;
  }

  fromJson(j: CRCProposalInfo, version: uint8_t) {
    this._type = j[JsonKeyType];
    switch (this._type) {
      case CRCProposalType.normal:
      case CRCProposalType.elip:
        this.fromJsonNormalCRCouncilMemberUnsigned(
          j as NormalProposalOwnerInfo,
          version
        );
        break;
      case CRCProposalType.secretaryGeneralElection:
        this.fromJsonSecretaryElectionCRCouncilMemberUnsigned(
          j as SecretaryElectionInfo,
          version
        );
        break;
      case CRCProposalType.changeProposalOwner:
        this.fromJsonChangeOwnerCRCouncilMemberUnsigned(
          j as ChangeProposalOwnerInfo,
          version
        );
        break;
      case CRCProposalType.terminateProposal:
        this.fromJsonTerminateProposalCRCouncilMemberUnsigned(
          j as TerminateProposalOwnerInfo,
          version
        );
        break;
      case CRCProposalType.reserveCustomID:
        this.fromJsonReserveCustomIDCRCouncilMemberUnsigned(
          j as ReserveCustomIDOwnerInfo,
          version
        );
        break;
      case CRCProposalType.receiveCustomID:
        this.fromJsonReceiveCustomIDCRCouncilMemberUnsigned(
          j as ReceiveCustomIDOwnerInfo,
          version
        );
        break;
      case CRCProposalType.changeCustomIDFee:
        this.fromJsonChangeCustomIDFeeCRCouncilMemberUnsigned(
          j as ChangeCustomIDFeeOwnerInfo,
          version
        );
        break;
      case CRCProposalType.registerSideChain:
        this.fromJsonRegisterSidechainCRCouncilMemberUnsigned(
          j as RegisterSidechainProposalInfo,
          version
        );
        break;
      default:
        Log.error("unknow type: {}", this._type);
        return;
    }
    this._crCouncilMemberSignature = Buffer.from(
      j[JsonKeyCRCouncilMemberSignature] as string,
      "hex"
    );
  }

  isValidNormalOwnerUnsigned(version: uint8_t): boolean {
    if (this._type >= CRCProposalType.maxType) {
      Log.error("invalid proposal type: {}", this._type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      Log.error("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      Log.error("invalid proposal owner pubkey");
      return false;
    }

    for (let budget of this._budgets) {
      if (!budget.isValid()) {
        Log.error("invalid budget");
        return false;
      }
    }

    if (!this._recipient.valid()) {
      Log.error("invalid recipient");
      return false;
    }

    return true;
  }

  isValidNormalCRCouncilMemberUnsigned(version: uint8_t): boolean {
    if (!this.isValidNormalOwnerUnsigned(version)) return false;

    try {
      if (
        !EcdsaSigner.verify(
          this._ownerPublicKey,
          this._signature,
          Buffer.from(
            this.digestNormalOwnerUnsigned(version).toString(16),
            "hex"
          )
        )
      ) {
        Log.error("verify owner signature fail");
        return false;
      }
    } catch (e) {
      Log.error("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      Log.error("invalid cr committee did");
      return false;
    }

    return true;
  }

  isValid(version: uint8_t): boolean {
    let isValid = false;
    switch (this._type) {
      case CRCProposalType.normal:
      case CRCProposalType.elip:
        isValid = this.isValidNormalCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.secretaryGeneralElection:
        isValid = this.isValidSecretaryElectionCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.changeProposalOwner:
        isValid = this.isValidChangeOwnerCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.terminateProposal:
        isValid = this.isValidTerminateProposalCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.reserveCustomID:
        isValid = this.isValidReserveCustomIDCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.receiveCustomID:
        isValid = this.isValidReceiveCustomIDCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.changeCustomIDFee:
        isValid = this.isValidChangeCustomIDFeeCRCouncilMemberUnsigned(version);
        break;
      case CRCProposalType.registerSideChain:
        isValid = this.isValidRegisterSidechainCRCouncilMemberUnsigned(version);
        break;
      default:
        break;
    }
    if (!this._crCouncilMemberSignature) {
      Log.error("cr committee not signed");
      isValid = false;
    }
    return isValid;
  }

  copyCRCProposal(payload: CRCProposal) {
    this._type = payload._type;
    this._categoryData = payload._categoryData;
    this._ownerPublicKey = payload._ownerPublicKey;
    this._draftHash = payload._draftHash;
    this._draftData = payload._draftData;
    this._budgets = payload._budgets;
    this._recipient = payload._recipient;
    this._targetProposalHash = payload._targetProposalHash;
    this._reservedCustomIDList = payload._reservedCustomIDList;
    this._receivedCustomIDList = payload._receivedCustomIDList;
    this._receiverDID = payload._receiverDID;
    this._customIDFeeRateInfo = payload._customIDFeeRateInfo;
    this._newRecipient = payload._newRecipient;
    this._newOwnerPublicKey = payload._newOwnerPublicKey;
    this._secretaryPublicKey = payload._secretaryPublicKey;
    this._secretaryDID = payload._secretaryDID;
    this._signature = payload._signature;
    this._newOwnerSignature = payload._newOwnerSignature;
    this._secretarySignature = payload._secretarySignature;
    this._upgradeCodeInfo = payload._upgradeCodeInfo;
    this._sidechainInfo = payload._sidechainInfo;

    this._crCouncilMemberDID = payload._crCouncilMemberDID;
    this._crCouncilMemberSignature = payload._crCouncilMemberSignature;
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    let equal = false;
    let p = payload as CRCProposal;

    try {
      switch (this._type) {
        case CRCProposalType.normal:
        case CRCProposalType.elip:
          equal =
            this._type == p._type &&
            this._categoryData == p._categoryData &&
            this._ownerPublicKey.equals(p._ownerPublicKey) &&
            this._draftHash.eq(p._draftHash) &&
            this.isEqualBudgets(p._budgets) &&
            this._recipient.equals(p._recipient) &&
            this._signature.equals(p._signature) &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.equals(p._crCouncilMemberSignature);
          break;
        case CRCProposalType.secretaryGeneralElection:
          equal =
            this._type == p._type &&
            this._categoryData == p._categoryData &&
            this._ownerPublicKey.equals(p._ownerPublicKey) &&
            this._draftHash.eq(p._draftHash) &&
            this._secretaryPublicKey.equals(p._secretaryPublicKey) &&
            this._secretaryDID.equals(p._secretaryDID) &&
            this._signature.equals(p._signature) &&
            this._secretarySignature.equals(p._secretarySignature) &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.equals(p._crCouncilMemberSignature);
          break;
        case CRCProposalType.changeProposalOwner:
          equal =
            this._type == p._type &&
            this._categoryData == p._categoryData &&
            this._ownerPublicKey.equals(p._ownerPublicKey) &&
            this._draftHash.eq(p._draftHash) &&
            this._targetProposalHash.eq(p._targetProposalHash) &&
            this._newRecipient.equals(p._newRecipient) &&
            this._newOwnerPublicKey.equals(p._newOwnerPublicKey) &&
            this._signature.equals(p._signature) &&
            this._newOwnerSignature.equals(p._newOwnerSignature) &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.equals(p._crCouncilMemberSignature);
          break;
        case CRCProposalType.terminateProposal:
          equal =
            this._type == p._type &&
            this._categoryData == p._categoryData &&
            this._ownerPublicKey.equals(p._ownerPublicKey) &&
            this._draftHash.eq(p._draftHash) &&
            this._targetProposalHash.eq(p._targetProposalHash) &&
            this._signature.equals(p._signature) &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.equals(p._crCouncilMemberSignature);
          break;
        case CRCProposalType.reserveCustomID:
          equal =
            this._type == p._type &&
            this._categoryData == p._categoryData &&
            this._ownerPublicKey.equals(p._ownerPublicKey) &&
            this._draftHash.eq(p._draftHash) &&
            this.isEqualReservedCustomIDList(p._reservedCustomIDList) &&
            this._signature.equals(p._signature) &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.equals(p._crCouncilMemberSignature);
          break;
        case CRCProposalType.receiveCustomID:
          equal =
            this._type == p._type &&
            this._categoryData == p._categoryData &&
            this._ownerPublicKey.toString() == p._ownerPublicKey.toString() &&
            this._draftHash.eq(p._draftHash) &&
            this.isEqualReceivedCustomIDList(p._receivedCustomIDList) &&
            this._receiverDID.equals(p._receiverDID) &&
            this._signature.toString() == p._signature.toString() &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.toString() ==
              p._crCouncilMemberSignature.toString();
          break;
        case CRCProposalType.changeCustomIDFee:
          equal =
            this._type == p._type &&
            this._categoryData == p._categoryData &&
            this._ownerPublicKey.toString() == p._ownerPublicKey.toString() &&
            this._draftHash.eq(p._draftHash) &&
            this._customIDFeeRateInfo.equals(p._customIDFeeRateInfo) &&
            this._signature.toString() == p._signature.toString() &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.toString() ==
              p._crCouncilMemberSignature.toString();
          break;
        case CRCProposalType.registerSideChain:
          equal =
            this._type == p._type &&
            this._categoryData == p._categoryData &&
            this._ownerPublicKey.equals(p._ownerPublicKey) &&
            this._draftHash.eq(p._draftHash) &&
            this._sidechainInfo.equals(p._sidechainInfo) &&
            this._signature.equals(p._signature) &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.equals(p._crCouncilMemberSignature);
          break;
        default:
          equal = false;
          break;
      }
    } catch (e) {
      Log.error("payload is not instance of CRCProposal");
      equal = false;
    }
    if (version >= CRCProposalVersion01)
      equal = equal && this._draftData.equals(p._draftData);
    return equal;
  }

  copyPayload(payload: Payload) {
    try {
      const crcProposal = payload as CRCProposal;
      this.copyCRCProposal(crcProposal);
    } catch (e) {
      Log.error("payload is not instance of CRCProposal");
    }
    return this;
  }

  // should ask how to deal with '#define'
  // #define DraftData_Hexstring
  private encodeDraftData(draftData: bytes_t, hexStr = true): string {
    if (hexStr) {
      return draftData.toString("hex");
    } else {
      return Base64.encode(draftData.toString("hex"));
    }
  }

  // returns the draft hash in the same byte order representation as cyber republic website proposal's draft hash
  private reverseDraftHash(draftHash: uint256) {
    let hashStr = draftHash.toString(16).match(/[a-fA-F0-9]{2}/g);
    if (hashStr) {
      return hashStr.reverse().join("");
    }
  }

  private checkAndDecodeDraftData(
    draftData: string,
    draftHash: uint256,
    hexStr = true
  ): bytes_t {
    let draftDataDecoded: bytes_t;
    if (hexStr) {
      draftDataDecoded = Buffer.from(draftData, "hex");
    } else {
      draftDataDecoded = Buffer.from(Base64.decode(draftData), "hex");
    }
    ErrorChecker.checkParam(
      draftDataDecoded.length > DRAFT_DATA_MAX_SIZE,
      Error.Code.ProposalContentTooLarge,
      "proposal origin content too large"
    );
    let draftHashDecoded = SHA256.hashTwice(draftDataDecoded);

    let reverseDraftHash = this.reverseDraftHash(draftHash);
    ErrorChecker.checkParam(
      reverseDraftHash != draftHashDecoded.toString("hex"),
      Error.Code.ProposalHashNotMatch,
      "proposal hash not match"
    );
    return draftDataDecoded;
  }

  private isEqualBudgets(budges: Budget[]): boolean {
    if (this._budgets.length !== budges.length) {
      return false;
    }
    for (let i = 0; i < budges.length; ++i) {
      if (!this._budgets[i].equals(budges[i])) {
        return false;
      }
    }
    return true;
  }

  private isEqualReservedCustomIDList(reservedCustomIDList: string[]): boolean {
    if (this._reservedCustomIDList.length !== reservedCustomIDList.length) {
      return false;
    }
    for (let i = 0; i < reservedCustomIDList.length; ++i) {
      if (this._reservedCustomIDList[i] !== reservedCustomIDList[i]) {
        return false;
      }
    }
    return true;
  }

  private isEqualReceivedCustomIDList(receivedCustomIDList: string[]): boolean {
    if (this._receivedCustomIDList.length !== receivedCustomIDList.length) {
      return false;
    }
    for (let i = 0; i < receivedCustomIDList.length; ++i) {
      if (this._receivedCustomIDList[i] !== receivedCustomIDList[i]) {
        return false;
      }
    }
    return true;
  }
}
