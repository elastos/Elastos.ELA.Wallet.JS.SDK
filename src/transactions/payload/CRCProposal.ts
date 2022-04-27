/*
 * Copyright (c) 2019 Elastos Foundation
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
import { ByteStream } from "../../common/bytestream";
import {
  uint8_t,
  json,
  uint64_t,
  uint32_t,
  uint256,
  bytes_t,
  sizeof_uint16_t,
  size_t,
  sizeof_uint256_t,
  uint16_t,
  JSONArray
} from "../../types";
import { Address } from "../../walletcore/Address";
import { SHA256 } from "../../walletcore/sha256";
import { EcdsaSigner } from "../../walletcore/ecdsasigner";
import { ErrorChecker, Error } from "../../common/ErrorChecker";
import { BASE64 as Base64 } from "../../walletcore/base64";
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
    if (!type) {
      // SPVLOG_ERROR("Budget::Deserialize: read type key");
      return false;
    }
    this._type = type;

    let stage: uint8_t = istream.readUInt8();
    if (!stage) {
      // SPVLOG_ERROR("Budget::Deserialize: read stage key");
      return false;
    }
    this._stage = stage;

    let amount = istream.readUIntOfBytesAsBN(8);
    if (!amount) {
      // SPVLOG_ERROR("Budget::Deserialize: read amount key");
      return false;
    }
    this._amount = amount;

    return true;
  }

  isValid(): boolean {
    if (this._type >= BudgetType.maxType) {
      // SPVLOG_ERROR("invalid budget type: {}", _type);
      return false;
    }

    if (this._stage > 127) {
      // SPVLOG_ERROR("invalid budget stage", _stage);
      return false;
    }

    return true;
  }

  toJson(): json {
    let j: json = {};
    j[JsonKeyType] = this._type;
    j[JsonKeyStage] = this._stage;
    j[JsonKeyAmount] = this._amount.toString(16);
    return j;
  }

  fromJson(j: json) {
    this._type = j[JsonKeyType] as BudgetType;
    this._stage = j[JsonKeyStage] as uint8_t;
    this._amount = new BigNumber(j[JsonKeyAmount] as string, 16);
  }

  equals(budget: Budget): boolean {
    return (
      this._type == budget._type &&
      this._stage == budget._stage &&
      this._amount.eq(budget._amount)
    );
  }
}

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
      // SPVLOG_ERROR("deserialize workingHeight failed");
      return false;
    }
    this._workingHeight = workingHeight;
    const nodeVersion = stream.readVarString();
    if (!nodeVersion) {
      // SPVLOG_ERROR("deserialize nodeVersion failed");
      return false;
    }
    const nodeDownloadUrl = stream.readVarString();
    if (!nodeDownloadUrl) {
      // SPVLOG_ERROR("deserialize nodeDownloadUrl failed");
      return false;
    }

    let nodeBinHash = Buffer.alloc(0);
    nodeBinHash = stream.readBytes(nodeBinHash, 32);
    if (!nodeBinHash) {
      // SPVLOG_ERROR("deserialize nodeBinHash failed");
      return false;
    }
    this._nodeBinHash = new BigNumber(nodeBinHash.toString("hex"), 16);

    let force: uint8_t = 0;
    force = stream.readUInt8();
    if (!force) {
      // SPVLOG_ERROR("deserialize force failed");
      return false;
    }
    this._force = force == 0 ? false : true;

    return true;
  }

  toJson(version: uint8_t): json {
    let j: json = {};
    j["WorkingHeight"] = this._workingHeight;
    j["NodeVersion"] = this._nodeVersion;
    j["NodeDownloadUrl"] = this._nodeDownloadUrl;
    j["NodeBinHash"] = this._nodeBinHash.toString(16);
    j["Force"] = this._force;
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._workingHeight = j["WorkingHeight"] as number;
    this._nodeVersion = j["NodeVersion"] as string;
    this._nodeDownloadUrl = j["NodeDownloadUrl"] as string;
    this._nodeBinHash = new BigNumber(j["NodeBinHash"] as string, 16);
    this._force = j["Force"] as boolean;
  }

  isValid(version: uint8_t): boolean {
    return true;
  }
}

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
      // SPVLOG_ERROR("deserialize side-chain name failed");
      return false;
    }
    this._sideChainName = sideChainName;

    let magicNumber = stream.readUInt32();
    if (!magicNumber) {
      // SPVLOG_ERROR("deserialize magic number failed");
      return false;
    }
    this._magicNumber = magicNumber;

    let genesisHash = stream.readUIntOfBytesAsBN(32);
    if (!genesisHash) {
      // SPVLOG_ERROR("deserialize genesis hash failed");
      return false;
    }
    this._genesisHash = genesisHash;

    let exchangeRate = stream.readUIntOfBytesAsBN(8);
    if (!exchangeRate) {
      // SPVLOG_ERROR("deserialize exchange rate failed");
      return false;
    }
    this._exchangeRate = exchangeRate;

    let effectiveHeight = stream.readUInt32();
    if (!effectiveHeight) {
      // SPVLOG_ERROR("deserialize effective height failed");
      return false;
    }
    this._effectiveHeight = effectiveHeight;

    let resourcePath = stream.readVarString();
    if (!resourcePath) {
      // SPVLOG_ERROR("deserialize resource path failed");
      return false;
    }
    this._resourcePath = resourcePath;
    return true;
  }

  toJson(version: uint8_t) {
    let j: json = {};
    j["SideChainName"] = this._sideChainName;
    j["MagicNumber"] = this._magicNumber;
    j["GenesisHash"] = this._genesisHash.toString(16);
    j["ExchangeRate"] = this._exchangeRate.toString(16);
    j["EffectiveHeight"] = this._effectiveHeight;
    j["ResourcePath"] = this._resourcePath;
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._sideChainName = j["SideChainName"] as string;
    this._magicNumber = j["MagicNumber"] as number;
    this._genesisHash = new BigNumber(j["GenesisHash"] as string, 16);
    this._exchangeRate = new BigNumber(j["ExchangeRate"] as string, 16);
    this._effectiveHeight = j["EffectiveHeight"] as number;
    this._resourcePath = j["ResourcePath"] as string;
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
      // SPVLOG_ERROR("deserialize rateOfCustomIDFee failed");
      return false;
    }
    this._rateOfCustomIDFee = rateOfCustomIDFee;

    let eIDEffectiveHeight = stream.readUInt32();
    if (!eIDEffectiveHeight) {
      // SPVLOG_ERROR("deserialize eIDEffectiveHeight failed");
      return false;
    }
    this._eIDEffectiveHeight = eIDEffectiveHeight;

    return true;
  }

  toJson(version: uint8_t): json {
    let j: json = {};
    j["RateOfCustomIDFee"] = this._rateOfCustomIDFee.toString(16);
    j["EIDEffectiveHeight"] = this._eIDEffectiveHeight;
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._rateOfCustomIDFee = new BigNumber(
      j["RateOfCustomIDFee"] as string,
      16
    );
    this._eIDEffectiveHeight = j["EIDEffectiveHeight"] as number;
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

    size += sizeof_uint16_t();
    size += stream.writeVarUInt(this._categoryData.length);
    size += this._categoryData.length;
    size += stream.writeVarUInt(this._ownerPublicKey.length);
    size += this._ownerPublicKey.length;
    if (version >= CRCProposalVersion01) {
      size += stream.writeVarUInt(this._draftData.length);
      size += this._draftData.length;
    }
    size += sizeof_uint256_t();

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
        size += sizeof_uint256_t();
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
        size += sizeof_uint256_t();
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
    if (version >= CRCProposalVersion01) stream.writeVarBytes(this._draftData);
    stream.writeVarUInt(this._budgets.length);
    for (let i = 0; i < this._budgets.length; ++i) {
      this._budgets[i].serialize(stream);
    }
    stream.writeBytes(this._recipient.programHash().bytes());
  }

  deserializeOwnerUnsigned(stream: ByteStream, version: uint8_t): boolean {
    let categoryData = stream.readVarString();
    if (!categoryData) {
      // SPVLOG_ERROR("deserialize categoryData");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      // SPVLOG_ERROR("deserialize owner PublicKey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash = stream.readUIntOfBytesAsBN(32);
    if (!draftHash) {
      // SPVLOG_ERROR("deserialize draftHash");
      return false;
    }
    this._draftHash = draftHash;

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        // SPVLOG_ERROR("deserialize draftdata");
        return false;
      }
      this._draftData = draftData;
    }

    let count: uint64_t = stream.readVarUInt();
    if (!count) {
      // SPVLOG_ERROR("deserialize budgets size");
      return false;
    }

    for (let i = 0; i < count.toNumber(); ++i) {
      if (!this._budgets[i].deserialize(stream)) {
        // SPVLOG_ERROR("deserialize bugets");
        return false;
      }
    }

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize recipient");
      return false;
    }
    this._recipient = Address.newFromAddressString(programHash.toString("hex"));

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
      // SPVLOG_ERROR("deserialize unsigned");
      return false;
    }

    if (!istream.readVarBytes(this._signature)) {
      // SPVLOG_ERROR("deserialize signature");
      return false;
    }

    let programHash: bytes_t;
    programHash = istream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize sponsor did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromAddressString(
      programHash.toString("hex")
    );

    return true;
  }

  serializeNormalOrELIP(stream: ByteStream, version: uint8_t) {
    this.serializeCRCouncilMemberUnsigned(stream, version);

    stream.writeVarBytes(this._crCouncilMemberSignature);
  }

  deserializeNormalOrELIP(stream: ByteStream, version: uint8_t): boolean {
    if (!this.deserializeCRCouncilMemberUnsigned(stream, version)) {
      // SPVLOG_ERROR("CRCProposal deserialize crc unsigned");
      return false;
    }

    if (!stream.readVarBytes(this._crCouncilMemberSignature)) {
      // SPVLOG_ERROR("CRCProposal deserialize crc signature");
      return false;
    }

    return true;
  }

  // change owner
  serializeChangeOwnerUnsigned(stream: ByteStream, version: uint8_t) {
    stream.writeUInt16(this._type);

    stream.writeVarString(this._categoryData);
    stream.writeVarBytes(this._ownerPublicKey);
    // stream.writeBytes(this._draftHash);
    stream.writeBNAsUIntOfSize(this._draftHash, 32);
    if (version >= CRCProposalVersion01) {
      stream.writeVarBytes(this._draftData);
    }

    // stream.writeBytes(this._targetProposalHash);
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
      // SPVLOG_ERROR("deserialize categoryData");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      // SPVLOG_ERROR("deserialize owner PublicKey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash = stream.readUIntOfBytesAsBN(32);
    if (!draftHash) {
      // SPVLOG_ERROR("deserialize draftHash");
      return false;
    }
    this._draftHash = draftHash;

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!stream.readVarBytes(draftData)) {
        // SPVLOG_ERROR("deserialize draftData");
        return false;
      }
      this._draftData = draftData;
    }

    let targetProposalHash = stream.readUIntOfBytesAsBN(32);
    if (!targetProposalHash) {
      // SPVLOG_ERROR("deserialize target proposal hash");
      return false;
    }
    this._targetProposalHash = targetProposalHash;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize new recipient");
      return false;
    }
    this._newRecipient = Address.newFromAddressString(
      programHash.toString("hex")
    );

    if (!stream.readVarBytes(this._newOwnerPublicKey)) {
      // SPVLOG_ERROR("deserialize new owner PublicKey");
      return false;
    }

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
      // SPVLOG_ERROR("deserialize change owner unsigned");
      return false;
    }

    let signature: bytes_t;
    signature = stream.readVarBytes(signature);
    if (!signature) {
      // SPVLOG_ERROR("deserialize change owner signature");
      return false;
    }
    this._signature = signature;

    let newOwnerSignature: bytes_t;
    newOwnerSignature = stream.readVarBytes(newOwnerSignature);
    if (!newOwnerSignature) {
      // SPVLOG_ERROR("deserialize change owner new owner signature");
      return false;
    }
    this._newOwnerSignature = newOwnerSignature;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize sponsor did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromAddressString(
      programHash.toString("hex")
    );

    return true;
  }

  serializeChangeOwner(stream: ByteStream, version: uint8_t) {
    this.serializeChangeOwnerCRCouncilMemberUnsigned(stream, version);

    stream.writeVarBytes(this._crCouncilMemberSignature);
  }

  deserializeChangeOwner(stream: ByteStream, version: uint8_t): boolean {
    if (!this.deserializeChangeOwnerCRCouncilMemberUnsigned(stream, version)) {
      // SPVLOG_ERROR("deserialize change owner cr council member unsigned");
      return false;
    }

    let crCouncilMemberSignature: bytes_t;
    crCouncilMemberSignature = stream.readVarBytes(crCouncilMemberSignature);
    if (!crCouncilMemberSignature) {
      // SPVLOG_ERROR("deserialize change owner cr council member signature");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;

    return true;
  }

  toJsonChangeOwnerUnsigned(version: uint8_t): json {
    let j: json = {};

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

  fromJsonChangeOwnerUnsigned(j: json, version: uint8_t) {
    this._type = j[JsonKeyType] as CRCProposalType;
    this._categoryData = j[JsonKeyCategoryData] as string;
    this._ownerPublicKey = Buffer.from(
      j[JsonKeyOwnerPublicKey] as string,
      "hex"
    );
    this._draftHash = new BigNumber(j[JsonKeyDraftHash] as string, 16);
    if (version >= CRCProposalVersion01) {
      let draftData = j[JsonKeyDraftData] as string;
      this._draftData = this.checkAndDecodeDraftData(
        draftData,
        this._draftHash
      );
    }
    this._targetProposalHash = new BigNumber(
      j[JsonKeyTargetProposalHash] as string,
      16
    );
    this._newRecipient = Address.newFromAddressString(
      j[JsonKeyNewRecipient] as string
    );
    this._newOwnerPublicKey = Buffer.from(
      j[JsonKeyNewOwnerPublicKey] as string,
      "hex"
    );
  }

  toJsonChangeOwnerCRCouncilMemberUnsigned(version: uint8_t): json {
    let j = this.toJsonChangeOwnerUnsigned(version);

    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyNewOwnerSignature] = this._newOwnerSignature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();

    return j;
  }

  fromJsonChangeOwnerCRCouncilMemberUnsigned(j: json, version: uint8_t) {
    this.fromJsonChangeOwnerUnsigned(j, version);

    this._signature = Buffer.from(j[JsonKeySignature] as string, "hex");
    this._newOwnerSignature = Buffer.from(
      j[JsonKeyNewOwnerSignature] as string,
      "hex"
    );
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  isValidChangeOwnerUnsigned(version: uint8_t): boolean {
    if (this._type != CRCProposalType.changeProposalOwner) {
      // SPVLOG_ERROR("invalid type: {}", _type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      // SPVLOG_ERROR("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
      let key1 = EcdsaSigner.getKeyFromPublic(this._newOwnerPublicKey);
    } catch (e) {
      // SPVLOG_ERROR("invalid pubkey");
      return false;
    }

    if (this._draftHash.isZero() || this._targetProposalHash.isZero()) {
      // SPVLOG_ERROR("invalid hash");
      return false;
    }

    if (!this._newRecipient.valid()) {
      // SPVLOG_ERROR("invalid new recipient");
      return false;
    }

    return true;
  }

  isValidChangeOwnerCRCouncilMemberUnsigned(version: uint8_t): boolean {
    if (!this.isValidChangeOwnerUnsigned(version)) {
      return false;
    }

    try {
      // _ownerPublicKey
      const data = this.digestChangeOwnerUnsigned(version).toString(16);
      if (
        !EcdsaSigner.verify(
          this._ownerPublicKey,
          this._signature,
          Buffer.from(data, "hex")
        )
      ) {
        // SPVLOG_ERROR("verify signature fail");
        return false;
      }

      if (
        !EcdsaSigner.verify(
          this._newOwnerPublicKey,
          this._newOwnerSignature,
          Buffer.from(data, "hex")
        )
      ) {
        // SPVLOG_ERROR("verify new owner signature fail");
        return false;
      }
    } catch (e) {
      // SPVLOG_ERROR("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      // SPVLOG_ERROR("invalid cr council member did");
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
    // stream.writeBytes(this._draftHash);
    stream.writeBNAsUIntOfSize(this._draftHash, 32);
    if (version >= CRCProposalVersion01) {
      stream.writeVarBytes(this._draftData);
    }

    // stream.writeBytes(this._targetProposalHash);
    stream.writeBNAsUIntOfSize(this._targetProposalHash, 32);
  }

  deserializeTerminateProposalUnsigned(
    stream: ByteStream,
    version: uint8_t
  ): boolean {
    let categoryData = stream.readVarString();
    if (!categoryData) {
      // SPVLOG_ERROR("deserialize terminate proposal category data");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      // SPVLOG_ERROR("deserialize terminate proposal owner pubkey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash: bytes_t;
    draftHash = stream.readBytes(draftHash, 32);
    if (!draftHash) {
      // SPVLOG_ERROR("deserialize terminate proposal draft hash");
      return false;
    }
    this._draftHash = new BigNumber(draftHash.toString("hex"), 16);

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        // SPVLOG_ERROR("deserialize terminate proposal draftData");
        return false;
      }
      this._draftData = draftData;
    }

    let targetProposalHash: bytes_t;
    targetProposalHash = stream.readBytes(draftHash, 32);
    if (!targetProposalHash) {
      // SPVLOG_ERROR("deserialize terminate proposal target proposal hash");
      return false;
    }
    this._targetProposalHash = new BigNumber(
      targetProposalHash.toString("hex"),
      16
    );

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
      // SPVLOG_ERROR("deserialize terminate proposal unsigned");
      return false;
    }

    let signature: bytes_t;
    signature = stream.readVarBytes(signature);
    if (!signature) {
      // SPVLOG_ERROR("deserialize terminate proposal signature");
      return false;
    }

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize sponsor did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromAddressString(
      programHash.toString("hex")
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
      // SPVLOG_ERROR("deserialize terminate proposal cr council member unsigned");
      return false;
    }

    let crCouncilMemberSignature: bytes_t;
    crCouncilMemberSignature = stream.readVarBytes(crCouncilMemberSignature);
    if (!crCouncilMemberSignature) {
      // SPVLOG_ERROR("deserialize change owner cr council member signature");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;

    return true;
  }

  toJsonTerminateProposalOwnerUnsigned(version: uint8_t) {
    let j: json = {};

    j[JsonKeyType] = this._type;
    j[JsonKeyCategoryData] = this._categoryData;
    j[JsonKeyOwnerPublicKey] = this._ownerPublicKey.toString("hex");
    j[JsonKeyDraftHash] = this._draftHash.toString(16);
    if (version >= CRCProposalVersion01)
      j[JsonKeyDraftData] = this.encodeDraftData(this._draftData);
    j[JsonKeyTargetProposalHash] = this._targetProposalHash.toString(16);

    return j;
  }

  fromJsonTerminateProposalOwnerUnsigned(j: json, version: uint8_t) {
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

  fromJsonTerminateProposalCRCouncilMemberUnsigned(j: json, version: uint8_t) {
    this.fromJsonTerminateProposalOwnerUnsigned(j, version);

    this._signature = Buffer.from(j[JsonKeySignature] as string, "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  isValidTerminateProposalOwnerUnsigned(version: uint8_t) {
    if (this._type != CRCProposalType.terminateProposal) {
      // SPVLOG_ERROR("invalid type: {}", _type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      // SPVLOG_ERROR("category data exceed 4096 bytes");
      return false;
    }

    try {
      // Key key(CTElastos, _ownerPublicKey);
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      // SPVLOG_ERROR("invalid pubkey");
      return false;
    }

    if (this._draftHash.eq(0) || this._targetProposalHash.eq(0)) {
      // SPVLOG_ERROR("invalid hash");
      return false;
    }

    return true;
  }

  isValidTerminateProposalCRCouncilMemberUnsigned(version: uint8_t) {
    if (!this.isValidTerminateProposalOwnerUnsigned(version)) {
      // SPVLOG_ERROR("terminate proposal unsigned is not valid");
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
        // SPVLOG_ERROR("verify signature fail");
        return false;
      }
    } catch (e) {
      // SPVLOG_ERROR("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      // SPVLOG_ERROR("invalid cr council member did");
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
      // SPVLOG_ERROR("deserialize category data");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      // SPVLOG_ERROR("deserialize owner pubkey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash = stream.readUIntOfBytesAsBN(32);
    if (!draftHash) {
      // SPVLOG_ERROR("deserialize draft hash");
      return false;
    }
    this._draftHash = draftHash;

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        // SPVLOG_ERROR("deserialize draft data");
        return false;
      }
      this._draftData = draftData;
    }

    let secretaryPublicKey: bytes_t;
    secretaryPublicKey = stream.readVarBytes(secretaryPublicKey);
    if (!secretaryPublicKey) {
      // SPVLOG_ERROR("deserialize secretary pubkey");
      return false;
    }
    this._secretaryPublicKey = secretaryPublicKey;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize sponsor did");
      return false;
    }
    this._secretaryDID = Address.newFromAddressString(
      programHash.toString("hex")
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
      // SPVLOG_ERROR("deserialize change secretary secretary unsigned");
      return false;
    }

    if (!stream.readVarBytes(this._signature)) {
      // SPVLOG_ERROR("deserialize signature");
      return false;
    }

    if (!stream.readVarBytes(this._secretarySignature)) {
      // SPVLOG_ERROR("deserialize secretary signature");
      return false;
    }

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize cr council mem did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromAddressString(
      programHash.toString("hex")
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
      // SPVLOG_ERROR("deserialize change secretary cr council member signature");
      return false;
    }

    return true;
  }

  toJsonSecretaryElectionUnsigned(version: uint8_t): json {
    let j: json = {};

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

  fromJsonSecretaryElectionUnsigned(j: json, version: uint8_t) {
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
    this._secretaryPublicKey = Buffer.from(
      j[JsonKeySecretaryPublicKey] as string,
      "hex"
    );
    this._secretaryDID = Address.newFromAddressString(
      j[JsonKeySecretaryDID] as string
    );
  }

  toJsonSecretaryElectionCRCouncilMemberUnsigned(version: uint8_t): json {
    let j: json = {};

    j = this.toJsonSecretaryElectionUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeySecretarySignature] = this._secretarySignature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();

    return j;
  }

  fromJsonSecretaryElectionCRCouncilMemberUnsigned(j: json, version: uint8_t) {
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
      // SPVLOG_ERROR("invalid type: {}", _type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      // SPVLOG_ERROR("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
      let key1 = EcdsaSigner.getKeyFromPublic(this._secretaryPublicKey);
    } catch (e) {
      // SPVLOG_ERROR("invalid ...");
      return false;
    }

    if (!this._secretaryDID.valid()) {
      // SPVLOG_ERROR("invalid secretary did");
      return false;
    }

    return true;
  }

  isValidSecretaryElectionCRCouncilMemberUnsigned(version: uint8_t): boolean {
    if (!this.isValidSecretaryElectionUnsigned(version)) {
      // SPVLOG_ERROR("secretary election secretary unsigned not valid");
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
        // SPVLOG_ERROR("verify owner signature fail");
        return false;
      }
      if (
        !EcdsaSigner.verify(
          this._secretaryPublicKey,
          this._secretarySignature,
          Buffer.from(rs.toString(16), "hex")
        )
      ) {
        // SPVLOG_ERROR("verify secretary signature fail");
        return false;
      }
    } catch (e) {
      // SPVLOG_ERROR("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      // SPVLOG_ERROR("invalid cr committee did");
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
      // SPVLOG_ERROR("deserialize reserved custom id category data");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      // SPVLOG_ERROR("deserialize reserved custom id owner pubkey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash: bytes_t;
    draftHash = stream.readBytes(draftHash, 32);
    if (!draftHash) {
      // SPVLOG_ERROR("deserialize reserved custom id draft hash");
      return false;
    }

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        // SPVLOG_ERROR("deserialize reserved custom id draft data");
        return false;
      }
    }

    let size: uint64_t = new BigNumber(0);
    size = stream.readVarUInt();
    if (!size) {
      // SPVLOG_ERROR("deserialize reserved custom id list size");
      return false;
    }
    for (let i = 0; i < size.toNumber(); ++i) {
      let reservedCustomID: string = stream.readVarString();
      if (!reservedCustomID) {
        // SPVLOG_ERROR("deserialize reserved custom id list[{}]", i);
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
      // SPVLOG_ERROR("deserialize reserved custom id signature");
      return false;
    }

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize cr council mem did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromAddressString(
      programHash.toString("hex")
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
      // SPVLOG_ERROR("deserialize reserved custom id council member sign");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;
    return true;
  }

  toJsonReserveCustomIDOwnerUnsigned(version: uint8_t): json {
    let j: json = {};

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

  fromJsonReserveCustomIDOwnerUnsigned(j: json, version: uint8_t) {
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
    this._reservedCustomIDList = j[JsonKeyReservedCustomIDList] as string[];
  }

  toJsonReserveCustomIDCRCouncilMemberUnsigned(version: uint8_t) {
    let j = this.toJsonReserveCustomIDOwnerUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();
    return j;
  }

  fromJsonReserveCustomIDCRCouncilMemberUnsigned(j: json, version: uint8_t) {
    this.fromJsonReserveCustomIDOwnerUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature] as string, "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  isValidReserveCustomIDOwnerUnsigned(version: uint8_t): boolean {
    if (this._type != CRCProposalType.reserveCustomID) {
      // SPVLOG_ERROR("invalid type: {}", _type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      // SPVLOG_ERROR("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      // SPVLOG_ERROR("invalid reserve custom id pubkey");
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
        // SPVLOG_ERROR("reserve custom id verify owner signature fail");
        return false;
      }
    } catch (e) {
      // SPVLOG_ERROR("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      // SPVLOG_ERROR("invalid cr committee did");
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
      // SPVLOG_ERROR("deserialize receive custom category data");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      // SPVLOG_ERROR("deserialize receive custom owner pubkey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash: BigNumber;
    draftHash = stream.readUIntOfBytesAsBN(32);
    if (!draftHash) {
      // SPVLOG_ERROR("deserialize receive custom draft hash");
      return false;
    }
    this._draftHash = draftHash;

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        // SPVLOG_ERROR("deserialize receive custom draft data");
        return false;
      }
      this._draftData = draftData;
    }

    let size = stream.readVarUInt();
    if (!size) {
      // SPVLOG_ERROR("deserialize receive custom id list size");
      return false;
    }
    for (let i = 0; i < size.toNumber(); ++i) {
      let receivedCustomID = stream.readVarString();
      if (!receivedCustomID) {
        // SPVLOG_ERROR("deserialize receive custom id list[{}]", i);
        return false;
      }
      this._receivedCustomIDList.push(receivedCustomID);
    }

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize receiver did");
      return false;
    }
    this._receiverDID = Address.newFromAddressString(
      programHash.toString("hex")
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
      // SPVLOG_ERROR("deserialize reserved custom id signature");
      return false;
    }
    this._signature = signature;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize cr council mem did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromAddressString(
      programHash.toString("hex")
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
      // SPVLOG_ERROR("deserialize receive custom id council member sign");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;

    return true;
  }

  toJsonReceiveCustomIDOwnerUnsigned(version: uint8_t) {
    let j: json = {};

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

  fromJsonReceiveCustomIDOwnerUnsigned(j: json, version: uint8_t) {
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

  toJsonReceiveCustomIDCRCouncilMemberUnsigned(version: uint8_t): json {
    let j = this.toJsonReceiveCustomIDOwnerUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();
    return j;
  }

  fromJsonReceiveCustomIDCRCouncilMemberUnsigned(j: json, version: uint8_t) {
    this.fromJsonReceiveCustomIDOwnerUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature] as string, "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  isValidReceiveCustomIDOwnerUnsigned(version: uint8_t): boolean {
    if (this._type != CRCProposalType.receiveCustomID) {
      // SPVLOG_ERROR("invalid type: {}", _type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      // SPVLOG_ERROR("category data exceed 4096 bytes");
      return false;
    }

    try {
      // Key key(CTElastos, _ownerPublicKey);
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      // SPVLOG_ERROR("invalid reserve custom id pubkey");
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
        // SPVLOG_ERROR("receive custom id verify owner signature fail");
        return false;
      }
    } catch (e) {
      // SPVLOG_ERROR("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      // SPVLOG_ERROR("invalid cr committee did");
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
      // SPVLOG_ERROR("deserialize change custom id category data");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      // SPVLOG_ERROR("deserialize change custom id owner pubkey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash = new BigNumber(0);
    draftHash = stream.readUIntOfBytesAsBN(32);
    if (!draftHash) {
      // SPVLOG_ERROR("deserialize change custom id draft hash");
      return false;
    }
    this._draftHash = draftHash;

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        // SPVLOG_ERROR("deserialize change custom id draft data");
        return false;
      }
      this._draftData = draftData;
    }

    if (!this._customIDFeeRateInfo.deserialize(stream, version)) {
      // SPVLOG_ERROR("deserialize change custom id fee");
      return false;
    }

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
      // SPVLOG_ERROR("deserialize change custom id fee signature");
      return false;
    }
    this._signature = signature;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize change custom id fee cr council mem did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromAddressString(
      programHash.toString("hex")
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
      // SPVLOG_ERROR("deserialize change custom id fee council mem sign");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;

    return true;
  }

  toJsonChangeCustomIDFeeOwnerUnsigned(version: uint8_t) {
    let j: json = {};

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

  fromJsonChangeCustomIDFeeOwnerUnsigned(j: json, version: uint8_t) {
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
    this._customIDFeeRateInfo.fromJson(
      j[JsonKeyCustomIDFeeRateInfo] as json,
      version
    );
  }

  toJsonChangeCustomIDFeeCRCouncilMemberUnsigned(version: uint8_t) {
    let j = this.toJsonChangeCustomIDFeeOwnerUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();
    return j;
  }

  fromJsonChangeCustomIDFeeCRCouncilMemberUnsigned(j: json, version: uint8_t) {
    this.fromJsonChangeCustomIDFeeOwnerUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature] as string, "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  isValidChangeCustomIDFeeOwnerUnsigned(version: uint8_t) {
    if (this._type != CRCProposalType.changeCustomIDFee) {
      // SPVLOG_ERROR("invalid type: {}", _type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      // SPVLOG_ERROR("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      // SPVLOG_ERROR("invalid reserve custom id pubkey");
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
        // SPVLOG_ERROR("change custom id fee verify owner signature fail");
        return false;
      }
    } catch (e) {
      // SPVLOG_ERROR("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      // SPVLOG_ERROR("invalid cr committee did");
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
      // SPVLOG_ERROR("deserialize change custom id category data");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      // SPVLOG_ERROR("deserialize change custom id owner pubkey");
      return false;
    }

    let draftHash: bytes_t;
    draftHash = stream.readBytes(draftHash, 32);

    if (!draftHash) {
      // SPVLOG_ERROR("deserialize change custom id draft hash");
      return false;
    }
    this._draftHash = new BigNumber(draftHash.toString("hex"), 16);

    if (version >= CRCProposalVersion01) {
      let draftData: bytes_t;
      draftData = stream.readVarBytes(draftData);
      if (!draftData) {
        // SPVLOG_ERROR("deserialize change custom id draft data");
        return false;
      }
      this._draftData = draftData;
    }

    if (!this._sidechainInfo.deserialize(stream, version)) {
      // SPVLOG_ERROR("deserialize change custom id fee");
      return false;
    }

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
      // SPVLOG_ERROR("deserialize id signature");
      return false;
    }
    this._signature = signature;

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize cr council mem did");
      return false;
    }

    this._crCouncilMemberDID = Address.newFromAddressString(
      programHash.toString("hex")
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
      // SPVLOG_ERROR("deserialize register side-chain council member sign");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;
    return true;
  }

  toJsonRegisterSidechainUnsigned(version: uint8_t): json {
    let j: json = {};

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

  fromJsonRegisterSidechainUnsigned(j: json, version: uint8_t) {
    this._categoryData = j[JsonKeyCategoryData] as string;
    this._ownerPublicKey = Buffer.from(
      j[JsonKeyOwnerPublicKey] as string,
      "hex"
    );
    this._draftHash = new BigNumber((j[JsonKeyDraftHash] as string, 16));
    if (version >= CRCProposalVersion01) {
      let draftData: string = j[JsonKeyDraftData] as string;
      this._draftData = this.checkAndDecodeDraftData(
        draftData,
        this._draftHash
      );
    }
    this._sidechainInfo.fromJson(j[JsonKeySidechainInfo] as json, version);
  }

  toJsonRegisterSidechainCRCouncilMemberUnsigned(version: uint8_t): json {
    let j = this.toJsonRegisterSidechainUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();
    return j;
  }

  fromJsonRegisterSidechainCRCouncilMemberUnsigned(j: json, version: uint8_t) {
    this.fromJsonRegisterSidechainUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature] as string, "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  isValidRegisterSidechainUnsigned(version: uint8_t): boolean {
    if (this._type != CRCProposalType.registerSideChain) {
      // SPVLOG_ERROR("invalid type: {}", _type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      // SPVLOG_ERROR("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      // SPVLOG_ERROR("invalid reserve custom id pubkey");
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
        // SPVLOG_ERROR("change register side-chain verify owner signature fail");
        return false;
      }
    } catch (e) {
      // SPVLOG_ERROR("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      // SPVLOG_ERROR("invalid cr committee did");
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
      // SPVLOG_ERROR("deserialize upgrade code category data");
      return false;
    }
    this._categoryData = categoryData;

    let ownerPublicKey: bytes_t;
    ownerPublicKey = stream.readVarBytes(ownerPublicKey);
    if (!ownerPublicKey) {
      // SPVLOG_ERROR("deserialize upgrade code owner pubkey");
      return false;
    }
    this._ownerPublicKey = ownerPublicKey;

    let draftHash = stream.readUIntOfBytesAsBN(32);
    if (!draftHash) {
      // SPVLOG_ERROR("deserialize upgrade code draft hash");
      return false;
    }

    if (!this._upgradeCodeInfo.deserialize(stream, version)) {
      // SPVLOG_ERROR("deserialize upgrade code");
      return false;
    }

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
      // SPVLOG_ERROR("deserialize upgrade code signature failed");
      return false;
    }

    let programHash: bytes_t;
    programHash = stream.readBytes(programHash, 21);
    if (!programHash) {
      // SPVLOG_ERROR("deserialize upgrade code cr council did");
      return false;
    }
    this._crCouncilMemberDID = Address.newFromAddressString(
      programHash.toString("hex")
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
      // SPVLOG_ERROR("deserialize cr council mem sign failed");
      return false;
    }
    this._crCouncilMemberSignature = crCouncilMemberSignature;

    return true;
  }

  toJsonUpgradeCodeUnsigned(version: uint8_t): json {
    let j: json = {};

    j[JsonKeyType] = this._type;
    j[JsonKeyCategoryData] = this._categoryData;
    j[JsonKeyOwnerPublicKey] = this._ownerPublicKey.toString("hex");
    j[JsonKeyDraftHash] = this._draftHash.toString(16);
    j[JsonKeyUpgradeCodeInfo] = this._upgradeCodeInfo.toJson(version);

    return j;
  }

  fromJsonUpgradeCode(j: json, version: uint8_t) {
    let type = j[JsonKeyType] as CRCProposalType;
    this._type = type;
    this._categoryData = j[JsonKeyCategoryData] as string;
    this._ownerPublicKey = Buffer.from(
      j[JsonKeyOwnerPublicKey] as string,
      "hex"
    );
    this._draftHash = new BigNumber(j[JsonKeyDraftHash] as string, 16);
    this._upgradeCodeInfo.fromJson(j[JsonKeyUpgradeCodeInfo] as json, version);
  }

  toJsonUpgradeCodeCRCouncilMemberUnsigned(version: uint8_t): json {
    let j: json = this.toJsonUpgradeCodeUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();
    return j;
  }

  fromJsonUpgradeCodeCRCouncilMemberUnsigned(j: json, version: uint8_t) {
    this.fromJsonUpgradeCode(j, version);
    this._signature = Buffer.from(j[JsonKeySignature] as string, "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  isValidUpgradeCodeUnsigned(version: uint8_t): boolean {
    if (
      this._type != CRCProposalType.mainChainUpgradeCode &&
      this._type != CRCProposalType.ethUpdateCode &&
      this._type != CRCProposalType.didUpdateCode
    ) {
      // SPVLOG_ERROR("invalid type: {}", _type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      // SPVLOG_ERROR("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      // SPVLOG_ERROR("invalid owner pubkey");
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
        // SPVLOG_ERROR("change upgrade code verify owner signature fail");
        return false;
      }
    } catch (e) {
      // SPVLOG_ERROR("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      // SPVLOG_ERROR("invalid cr committee did");
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
        // SPVLOG_ERROR("serialize cr proposal unknown type");
        break;
    }
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    let type = stream.readUInt16();
    if (!type) {
      // SPVLOG_ERROR("deserialize type");
      return false;
    }
    this._type = type as CRCProposalType;

    let r: boolean = false;
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
        // SPVLOG_ERROR("unknow type: {}", _type);
        r = false;
        break;
    }

    return r;
  }

  toJsonNormalOwnerUnsigned(version: uint8_t): json {
    let j: json = {};
    j[JsonKeyType] = this._type;
    j[JsonKeyCategoryData] = this._categoryData;
    j[JsonKeyOwnerPublicKey] = this._ownerPublicKey.toString("hex");
    j[JsonKeyDraftHash] = this._draftHash.toString(16);
    if (version >= CRCProposalVersion01) {
      j[JsonKeyDraftData] = this.encodeDraftData(this._draftData);
    }
    let budgets = [];
    for (let i = 0; i < this._budgets.length; ++i) {
      budgets.push(this._budgets[i].toJson());
    }
    j[JsonKeyBudgets] = budgets;
    j[JsonKeyRecipient] = this._recipient.string();
    return j;
  }

  fromJsonNormalOwnerUnsigned(j: json, version: uint8_t) {
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
    let budgets = j[JsonKeyBudgets] as JSONArray;
    for (let i = 0; i < budgets.length; ++i) {
      let budget = new Budget();
      budget.fromJson(budgets[i] as json);
      this._budgets.push(budget);
    }

    this._recipient = Address.newFromAddressString(
      j[JsonKeyRecipient] as string
    );
  }

  toJsonNormalCRCouncilMemberUnsigned(version: uint8_t): json {
    let j: json = this.toJsonNormalOwnerUnsigned(version);
    j[JsonKeySignature] = this._signature.toString("hex");
    j[JsonKeyCRCouncilMemberDID] = this._crCouncilMemberDID.string();
    return j;
  }

  fromJsonNormalCRCouncilMemberUnsigned(j: json, version: uint8_t) {
    this.fromJsonNormalOwnerUnsigned(j, version);
    this._signature = Buffer.from(j[JsonKeySignature] as string, "hex");
    this._crCouncilMemberDID = Address.newFromAddressString(
      j[JsonKeyCRCouncilMemberDID] as string
    );
  }

  toJson(version: uint8_t) {
    let j: json = {};
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
        // SPVLOG_ERROR("unknow type: {}", _type);
        return j;
    }
    j[JsonKeyCRCouncilMemberSignature] =
      this._crCouncilMemberSignature.toString("hex");
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._type = j[JsonKeyType] as CRCProposalType;
    switch (this._type) {
      case CRCProposalType.normal:
      case CRCProposalType.elip:
        this.fromJsonNormalCRCouncilMemberUnsigned(j, version);
        break;
      case CRCProposalType.secretaryGeneralElection:
        this.fromJsonSecretaryElectionCRCouncilMemberUnsigned(j, version);
        break;
      case CRCProposalType.changeProposalOwner:
        this.fromJsonChangeOwnerCRCouncilMemberUnsigned(j, version);
        break;
      case CRCProposalType.terminateProposal:
        this.fromJsonTerminateProposalCRCouncilMemberUnsigned(j, version);
        break;
      case CRCProposalType.reserveCustomID:
        this.fromJsonReserveCustomIDCRCouncilMemberUnsigned(j, version);
        break;
      case CRCProposalType.receiveCustomID:
        this.fromJsonReceiveCustomIDCRCouncilMemberUnsigned(j, version);
        break;
      case CRCProposalType.changeCustomIDFee:
        this.fromJsonChangeCustomIDFeeCRCouncilMemberUnsigned(j, version);
        break;
      case CRCProposalType.registerSideChain:
        this.fromJsonRegisterSidechainCRCouncilMemberUnsigned(j, version);
      default:
        // SPVLOG_ERROR("unknow type: {}", _type);
        return;
    }
    this._crCouncilMemberSignature = Buffer.from(
      j[JsonKeyCRCouncilMemberSignature] as string,
      "hex"
    );
  }

  isValidNormalOwnerUnsigned(version: uint8_t): boolean {
    if (this._type >= CRCProposalType.maxType) {
      // SPVLOG_ERROR("invalid proposal type: {}", _type);
      return false;
    }

    if (this._categoryData.length > 4096) {
      // SPVLOG_ERROR("category data exceed 4096 bytes");
      return false;
    }

    try {
      let key = EcdsaSigner.getKeyFromPublic(this._ownerPublicKey);
    } catch (e) {
      // SPVLOG_ERROR("invalid proposal owner pubkey");
      return false;
    }

    for (let budget of this._budgets) {
      if (!budget.isValid()) {
        // SPVLOG_ERROR("invalid budget");
        return false;
      }
    }

    if (!this._recipient.valid()) {
      // SPVLOG_ERROR("invalid recipient");
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
        // SPVLOG_ERROR("verify owner signature fail");
        return false;
      }
    } catch (e) {
      // SPVLOG_ERROR("verify signature exception: {}", e.what());
      return false;
    }

    if (!this._crCouncilMemberDID.valid()) {
      // SPVLOG_ERROR("invalid cr committee did");
      return false;
    }

    return true;
  }

  isValid(version: uint8_t): boolean {
    let isValid: boolean = false;
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
      // SPVLOG_ERROR("cr committee not signed");
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
    let equal: boolean = false;
    let p = payload as CRCProposal;

    try {
      switch (this._type) {
        case CRCProposalType.normal:
        case CRCProposalType.elip:
          equal =
            this._type == p._type &&
            this._categoryData == p._categoryData &&
            this._ownerPublicKey.toString() == p._ownerPublicKey.toString() &&
            this._draftHash.eq(p._draftHash) &&
            this.isEqualBudgets(p._budgets) &&
            this._recipient.equals(p._recipient) &&
            this._signature.toString() == p._signature.toString() &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.toString() ==
              p._crCouncilMemberSignature.toString();
          break;
        case CRCProposalType.secretaryGeneralElection:
          equal =
            this._type == p._type &&
            this._categoryData == p._categoryData &&
            this._ownerPublicKey.toString() == p._ownerPublicKey.toString() &&
            this._draftHash.eq(p._draftHash) &&
            this._secretaryPublicKey.toString() ==
              p._secretaryPublicKey.toString() &&
            this._secretaryDID.equals(p._secretaryDID) &&
            this._signature.toString() == p._signature.toString() &&
            this._secretarySignature.toString() ==
              p._secretarySignature.toString() &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.toString() ==
              p._crCouncilMemberSignature.toString();
          break;
        case CRCProposalType.changeProposalOwner:
          equal =
            this._type == p._type &&
            this._categoryData == p._categoryData &&
            this._ownerPublicKey.toString() == p._ownerPublicKey.toString() &&
            this._draftHash.eq(p._draftHash) &&
            this._targetProposalHash.eq(p._targetProposalHash) &&
            this._newRecipient.equals(p._newRecipient) &&
            this._newOwnerPublicKey.toString() ==
              p._newOwnerPublicKey.toString() &&
            this._signature.toString() == p._signature.toString() &&
            this._newOwnerSignature.toString() ==
              p._newOwnerSignature.toString() &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.toString() ==
              p._crCouncilMemberSignature.toString();
          break;
        case CRCProposalType.terminateProposal:
          equal =
            this._type == p._type &&
            this._categoryData == p._categoryData &&
            this._ownerPublicKey.toString() == p._ownerPublicKey.toString() &&
            this._draftHash.eq(p._draftHash) &&
            this._targetProposalHash.eq(p._targetProposalHash) &&
            this._signature.toString() == p._signature.toString() &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.toString() ==
              p._crCouncilMemberSignature.toString();
          break;
        case CRCProposalType.reserveCustomID:
          equal =
            this._type == p._type &&
            this._categoryData == p._categoryData &&
            this._ownerPublicKey.toString() == p._ownerPublicKey.toString() &&
            this._draftHash.eq(p._draftHash) &&
            this.isEqualReservedCustomIDList(p._reservedCustomIDList) &&
            this._signature.toString() == p._signature.toString() &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.toString() ==
              p._crCouncilMemberSignature.toString();
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
            this._ownerPublicKey.toString() == p._ownerPublicKey.toString() &&
            this._draftHash.eq(p._draftHash) &&
            this._sidechainInfo.equals(p._sidechainInfo) &&
            this._signature.toString() == p._signature.toString() &&
            this._crCouncilMemberDID.equals(p._crCouncilMemberDID) &&
            this._crCouncilMemberSignature.toString() ==
              p._crCouncilMemberSignature.toString();
          break;
        default:
          equal = false;
          break;
      }
    } catch (e) {
      // SPVLOG_ERROR("payload is not instance of CRCProposal");
      equal = false;
    }
    if (version >= CRCProposalVersion01)
      equal = equal && this._draftData.toString() == p._draftData.toString();
    return equal;
  }

  copyPayload(payload: Payload) {
    try {
      const crcProposal = payload as CRCProposal;
      this.copyCRCProposal(crcProposal);
    } catch (e) {
      // SPVLOG_ERROR("payload is not instance of CRCProposal");
    }
    return this;
  }

  // should ask how to deal with '#define'
  // #define DraftData_Hexstring
  private encodeDraftData(draftData: bytes_t, hexStr: boolean = true): string {
    if (hexStr) {
      return draftData.toString("hex");
    } else {
      return Base64.encode(draftData.toString("hex"));
    }
  }

  private checkAndDecodeDraftData(
    draftData: string,
    draftHash: uint256,
    hexStr: boolean = true
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

    ErrorChecker.checkParam(
      draftHash.toString(16) != draftHashDecoded.toString("hex"),
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
