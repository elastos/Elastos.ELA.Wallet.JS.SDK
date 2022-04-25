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
import { uint168 } from "../../common/uint168";
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
  uint16_t
} from "../../types";
import { Address } from "../../walletcore/Address";
import { SHA256 } from "../../walletcore/sha256";

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

export class Budget {
  private _type: BudgetType;
  private _stage: uint8_t;
  private _amount: BigNumber;

  newFromParams(type: BudgetType, stage: uint8_t, amount: BigNumber) {
    const budget = new Budget();
    budget._type = type;
    budget._stage = stage;
    budget._amount = amount;
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

export class CRCProposal {
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
    for (let i = 0; i < this._budgets.length; ++i)
      this._budgets[i].serialize(stream);
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
}
