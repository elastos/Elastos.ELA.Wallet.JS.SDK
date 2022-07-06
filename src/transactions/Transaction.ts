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
import { ByteStream } from "../common/bytestream";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { Log } from "../common/Log";
import {
  INT32_MAX,
  JSONValue,
  size_t,
  time_t,
  UINT16_MAX,
  uint256,
  uint32_t,
  uint64_t,
  uint8_t
} from "../types";
import { SHA256 } from "../walletcore/sha256";
import { Attribute, AttributeInfo } from "./Attribute";
import { CoinBase } from "./payload/CoinBase";
import { TransferAsset } from "./payload/TransferAsset";
import { RegisterAsset } from "./payload/RegisterAsset";
import { Payload } from "./payload/Payload";
import { Program, ProgramInfo, SignedInfo } from "./Program";
import { TransactionInput, TransactionInputInfo } from "./TransactionInput";
import { TransactionOutput, TransactionOutputInfo } from "./TransactionOutput";
import { Record } from "./payload/Record";
import { SideChainPow } from "./payload/SideChainPow";
import { RechargeToSideChain } from "./payload/RechargeToSideChain";
import { WithdrawFromSideChain } from "./payload/WithdrawFromSideChain";
import { TransferCrossChainAsset } from "./payload/TransferCrossChainAsset";
import { ProducerInfo } from "./payload/ProducerInfo";
import { CancelProducer } from "./payload/CancelProducer";
import { ReturnDepositCoin } from "./payload/ReturnDepositCoin";
import { NextTurnDPoSInfo } from "./payload/NextTurnDPoSInfo";
import { CRInfo } from "./payload/CRInfo";
import { UnregisterCR } from "./payload/UnregisterCR";
import { CRCProposal } from "./payload/CRCProposal";
import { CRCProposalReview } from "./payload/CRCProposalReview";
import { CRCProposalTracking } from "./payload/CRCProposalTracking";
import { CRCProposalWithdraw } from "./payload/CRCProposalWithdraw";
import { CRCProposalRealWithdraw } from "./payload/CRCProposalRealWithdraw";
import { CRCAssetsRectify } from "./payload/CRCAssetsRectify";
import { CRCouncilMemberClaimNode } from "./payload/CRCouncilMemberClaimNode";

export enum TransactionType {
  coinBase = 0x00,
  registerAsset = 0x01,
  transferAsset = 0x02,
  record = 0x03,
  deploy = 0x04,
  sideChainPow = 0x05,
  rechargeToSideChain = 0x06,
  withdrawFromSideChain = 0x07,
  transferCrossChainAsset = 0x08,

  registerProducer = 0x09,
  cancelProducer = 0x0a,
  updateProducer = 0x0b,
  returnDepositCoin = 0x0c,
  activateProducer = 0x0d,

  IllegalProposalEvidence = 0x0e,
  IllegalVoteEvidence = 0x0f,
  IllegalBlockEvidence = 0x10,
  IllegalSidechainEvidence = 0x11,
  InactiveArbitrators = 0x12,
  UpdateVersion = 0x13,
  nextTurnDPOSInfo = 0x14,

  registerCR = 0x21,
  unregisterCR = 0x22,
  updateCR = 0x23,
  returnCRDepositCoin = 0x24,

  crcProposal = 0x25,
  crcProposalReview = 0x26,
  crcProposalTracking = 0x27,
  crcAppropriation = 0x28,
  crcProposalWithdraw = 0x29,
  crcProposalRealWithdraw = 0x2a,
  crcAssetsRectify = 0x2b,
  crCouncilMemberClaimNode = 0x31,

  TypeMaxCount
}

export enum TxVersion {
  Default = 0x00,
  V09 = 0x09
}

const DEFAULT_PAYLOAD_TYPE = TransactionType.transferAsset;
const TX_LOCKTIME = 0x00000000;
const TX_UNCONFIRMED = INT32_MAX; // block height indicating transaction is unconfirmed

export type TransactionInfo = {
  IsRegistered: boolean;
  TxHash: string;
  Version: number;
  LockTime: number;
  BlockHeight: number;
  Timestamp: number;
  Inputs: TransactionInputInfo[];
  Type: number;
  PayloadVersion: number;
  PayLoad: JSONValue;
  Attributes: AttributeInfo[];
  Programs: ProgramInfo[];
  Outputs: TransactionOutputInfo[];
  Fee: number;
};

export class Transaction {
  protected _isRegistered: boolean;
  protected _txHash: uint256;

  protected _version: uint8_t;
  protected _lockTime: uint32_t;
  protected _blockHeight: uint32_t;
  protected _timestamp: time_t; // time interval since unix epoch
  protected _type: uint8_t;
  protected _payloadVersion: uint8_t;
  protected _fee: uint64_t;
  protected _payload: Payload;
  protected _outputs: TransactionOutput[] = [];
  protected _inputs: TransactionInput[] = [];
  protected _attributes: Attribute[] = [];
  protected _programs: Program[] = [];

  /* Transaction::Transaction() :
			_version(TxVersion::Default),
			_lockTime(TX_LOCKTIME),
			_blockHeight(TX_UNCONFIRMED),
			_payloadVersion(0),
			_fee(0),
			_payload(nullptr),
			_type(DEFAULT_PAYLOAD_TYPE),
			_isRegistered(false),
			_txHash(0),
			_timestamp(0) {
		_payload = InitPayload(_type);
	}*/

  public static newFromParams(type: uint8_t, payload: Payload): Transaction {
    let tx = new Transaction();
    tx._version = TxVersion.Default;
    tx._lockTime = TX_LOCKTIME;
    tx._blockHeight = TX_UNCONFIRMED;
    tx._payloadVersion = 0;
    tx._fee = new BigNumber(0);
    tx._type = type;
    tx._isRegistered = false;
    tx._txHash = new BigNumber(0);
    tx._timestamp = 0;
    tx._payload = payload; // WAS std::move(payload)

    return tx;
  }

  /*	Transaction::Transaction(const Transaction &tx) {
			this->operator=(tx);
		} */

  public static newFromTransaction(orig: Transaction): Transaction {
    let transaction = new Transaction();

    transaction._isRegistered = orig._isRegistered;
    transaction._txHash = orig.getHash();

    transaction._version = orig._version;
    transaction._lockTime = orig._lockTime;
    transaction._blockHeight = orig._blockHeight;
    transaction._timestamp = orig._timestamp;

    transaction._type = orig._type;
    transaction._payloadVersion = orig._payloadVersion;
    transaction._fee = orig._fee;

    transaction._payload = transaction.initPayload(orig._type);

    transaction._payload = orig._payload;

    transaction._inputs = [];
    for (let input of orig._inputs) {
      transaction._inputs.push(TransactionInput.newFromTransactionInput(input));
    }

    transaction._outputs = [];
    for (let output of orig._outputs) {
      transaction._outputs.push(
        TransactionOutput.newFromTransactionOutput(output)
      );
    }

    transaction._attributes = [];
    for (let attr of orig._attributes) {
      transaction._attributes.push(Attribute.newFromAttribute(attr));
    }

    transaction._programs = [];
    for (let program of orig._programs) {
      transaction._programs.push(Program.newFromProgram(program));
    }

    return transaction;
  }

  equals(tx: Transaction): boolean {
    let equal =
      this._version == tx._version &&
      this._lockTime == tx._lockTime &&
      this._blockHeight == tx._blockHeight &&
      this._timestamp == tx._timestamp &&
      this._type == tx._type &&
      this._payloadVersion == tx._payloadVersion &&
      this._outputs.length == tx._outputs.length &&
      this._inputs.length == tx._inputs.length &&
      this._attributes.length == tx._attributes.length &&
      this._programs.length == tx._programs.length;

    if (equal) {
      equal = this._payload.equals(tx._payload, this._payloadVersion);
    }

    if (equal) {
      for (let i = 0; i < this._outputs.length; ++i) {
        if (!this._outputs[i].equals(tx._outputs[i])) {
          equal = false;
          break;
        }
      }
    }

    if (equal) {
      for (let i = 0; i < this._inputs.length; ++i) {
        if (!this._inputs[i].equals(tx._inputs[i])) {
          equal = false;
          break;
        }
      }
    }

    if (equal) {
      for (let i = 0; i < this._attributes.length; ++i) {
        if (!this._attributes[i].equals(tx._attributes[i])) {
          equal = false;
          break;
        }
      }
    }

    if (equal) {
      for (let i = 0; i < this._programs.length; ++i) {
        if (!this._programs[i].equals(tx._programs[i])) {
          equal = false;
          break;
        }
      }
    }

    return equal;
  }

  public isRegistered(): boolean {
    return this._isRegistered;
  }

  public resetHash() {
    this._txHash = new BigNumber(0);
  }

  public getHash(): uint256 {
    if (!this._txHash || this._txHash.eq(0)) {
      let stream: ByteStream = new ByteStream();
      this.serializeUnsigned(stream);
      this._txHash = new BigNumber(
        SHA256.hashTwice(stream.getBytes()).toString("hex"),
        16
      );
    }
    return this._txHash;
  }

  // returns the transaction hash in the same byte order representation as chain transaction ids
  public getHashString(): string {
    const hash = this.getHash().toString(16);
    // match every two hex digits, reverse the returned array, then join the array back into a String:
    return hash
      .match(/[a-fA-F0-9]{2}/g)
      .reverse()
      .join("");
  }

  public setHash(hash: uint256) {
    this._txHash = hash;
  }

  public getVersion(): uint8_t {
    return this._version;
  }

  public setVersion(version: uint8_t) {
    this._version = version;
  }

  public getTransactionType(): uint8_t {
    return this._type;
  }

  public setTransactionType(type: uint8_t) {
    this._type = type;
  }

  getDPoSTxTypes() {
    return [
      TransactionType.registerProducer,
      TransactionType.cancelProducer,
      TransactionType.updateProducer,
      TransactionType.returnDepositCoin,
      TransactionType.activateProducer
    ];
  }

  getCRCTxTypes() {
    return [
      TransactionType.registerCR,
      TransactionType.unregisterCR,
      TransactionType.updateCR,
      TransactionType.returnCRDepositCoin,
      TransactionType.crCouncilMemberClaimNode
    ];
  }

  getProposalTypes() {
    return [
      TransactionType.crcProposal,
      TransactionType.crcProposalReview,
      TransactionType.crcProposalTracking,
      TransactionType.crcAppropriation,
      TransactionType.crcProposalWithdraw
    ];
  }

  private reinit() {
    this.cleanup();
    this._type = DEFAULT_PAYLOAD_TYPE;
    this._payload = this.initPayload(this._type);

    this._version = TxVersion.Default;
    this._lockTime = TX_LOCKTIME;
    this._blockHeight = TX_UNCONFIRMED;
    this._payloadVersion = 0;
    this._fee = new BigNumber(0);
  }

  public getOutputs(): TransactionOutput[] {
    return this._outputs;
  }

  public setOutputs(outputs: TransactionOutput[]) {
    this._outputs = outputs;
  }

  public addOutput(output: TransactionOutput) {
    this._outputs.push(output);
  }

  removeOutput(output: TransactionOutput) {
    this._outputs = this._outputs.filter((item) => !item.equals(output));
  }

  getInputs(): TransactionInput[] {
    return this._inputs;
  }

  public addInput(Input: TransactionInput) {
    this._inputs.push(Input);
  }

  containInput(hash: uint256, n: uint32_t): boolean {
    for (let i = 0; i < this._inputs.length; ++i) {
      if (this._inputs[i].txHash().eq(hash) && n == this._inputs[i].index()) {
        return true;
      }
    }

    return false;
  }

  getLockTime(): uint32_t {
    return this._lockTime;
  }

  setLockTime(t: uint32_t) {
    this._lockTime = t;
  }

  getBlockHeight(): uint32_t {
    return this._blockHeight;
  }

  setBlockHeight(height: uint32_t) {
    this._blockHeight = height;
  }

  getTimestamp() {
    return this._timestamp;
  }

  setTimestamp(t: time_t) {
    this._timestamp = t;
  }

  public estimateSize(): size_t {
    let i: size_t,
      txSize = 0;
    let stream = new ByteStream();

    if (this._version >= TxVersion.V09) txSize += 1;

    // type, payloadversion
    txSize += 2;

    // payload
    txSize += this._payload.estimateSize(this._payloadVersion);

    txSize += stream.writeVarUInt(this._attributes.length);
    for (i = 0; i < this._attributes.length; ++i)
      txSize += this._attributes[i].estimateSize();

    txSize += stream.writeVarUInt(this._inputs.length);
    for (i = 0; i < this._inputs.length; ++i)
      txSize += this._inputs[i].estimateSize();

    txSize += stream.writeVarUInt(this._outputs.length);
    for (i = 0; i < this._outputs.length; ++i)
      txSize += this._outputs[i].estimateSize();

    txSize += 4; // WAS sizeof(this._lockTime);

    txSize += stream.writeVarUInt(this._programs.length);
    for (i = 0; i < this._programs.length; ++i)
      txSize += this._programs[i].estimateSize();

    return txSize;
  }

  public getSignedInfo(): SignedInfo[] {
    let info = [];
    let md: uint256 = this.getShaData();

    for (let i = 0; i < this._programs.length; ++i) {
      info.push(this._programs[i].getSignedInfo(md));
    }
    return info;
  }

  isSigned(): boolean {
    if (
      this._type == TransactionType.rechargeToSideChain ||
      this._type == TransactionType.coinBase
    )
      return true;

    if (this._programs.length == 0) return false;

    let md: uint256 = this.getShaData();

    for (let i = 0; i < this._programs.length; ++i) {
      if (!this._programs[i].verifySignature(md)) return false;
    }

    return true;
  }

  public isCoinBase(): boolean {
    return this._type == TransactionType.coinBase;
  }

  public isUnconfirmed(): boolean {
    return this._blockHeight == TX_UNCONFIRMED;
  }

  public isValid(): boolean {
    if (!this.isSigned()) {
      Log.error("verify tx signature fail");
      return false;
    }

    for (let i = 0; i < this._attributes.length; ++i) {
      if (!this._attributes[i].isValid()) {
        Log.error("tx attribute is invalid");
        return false;
      }
    }

    if (
      this._payload === null ||
      !this._payload.isValid(this._payloadVersion)
    ) {
      Log.error("tx payload invalid");
      return false;
    }

    if (this._outputs.length == 0) {
      Log.error("tx without output");
      return false;
    }

    for (let i = 0; i < this._outputs.length; ++i) {
      if (!this._outputs[i].isValid()) {
        Log.error("tx output is invalid");
        return false;
      }
    }

    return true;
  }

  /*const IPayload *Transaction::GetPayload() const {
		return _payload.get();
	}

	IPayload *Transaction::GetPayload() {
		return _payload.get();
	}
  */

  getPayloadPtr(): Payload {
    return this._payload;
  }

  setPayload(payload: Payload) {
    this._payload = payload;
  }

  public addAttribute(attribute: Attribute) {
    this._attributes.push(attribute);
  }

  public getAttributes(): Attribute[] {
    return this._attributes;
  }

  public addUniqueProgram(program: Program): boolean {
    for (let i = 0; i < this._programs.length; ++i) {
      if (this._programs[i].getCode().equals(program.getCode())) {
        return false;
      }
    }

    this._programs.push(program);

    return true;
  }

  public addProgram(program: Program) {
    this._programs.push(program);
  }

  public getPrograms(): Program[] {
    return this._programs;
  }

  public clearPrograms() {
    this._programs = [];
  }

  public serialize(ostream: ByteStream) {
    this.serializeUnsigned(ostream);

    ostream.writeVarUInt(this._programs.length);
    for (let i = 0; i < this._programs.length; i++) {
      this._programs[i].serialize(ostream);
    }
  }

  public serializeUnsigned(ostream: ByteStream) {
    if (this._version >= TxVersion.V09) {
      ostream.writeByte(this._version);
    }
    ostream.writeByte(this._type);
    ostream.writeByte(this._payloadVersion);
    ErrorChecker.checkCondition(
      this._payload == null,
      Error.Code.Transaction,
      "payload should not be null"
    );

    this._payload.serialize(ostream, this._payloadVersion);

    ostream.writeVarUInt(this._attributes.length);
    this._attributes.forEach((a) => a.serialize(ostream));

    ostream.writeVarUInt(this._inputs.length);
    this._inputs.forEach((i) => i.serialize(ostream));

    ostream.writeVarUInt(this._outputs.length);
    this._outputs.forEach((o) => o.serialize(ostream, this._version));

    ostream.writeUInt32(this._lockTime);
  }

  deserializeType(istream: ByteStream): boolean {
    let flagByte = istream.readByte();
    if (flagByte === null) {
      Log.error("deserialize flag byte error");
      return false;
    }
    if (flagByte >= TxVersion.V09) {
      this._version = flagByte;
      this._type = istream.readByte();
      if (this._type === null) {
        Log.error("deserialize type error");
        return false;
      }
    } else {
      this._version = TxVersion.Default;
      this._type = flagByte;
    }
    return true;
  }

  public deserialize(istream: ByteStream): boolean {
    this.reinit();

    if (!this.deserializeType(istream)) {
      return false;
    }

    this._payloadVersion = istream.readByte();
    if (this._payloadVersion === null) return false;

    this._payload = this.initPayload(this._type);

    if (this._payload === null) {
      Log.error(`new _payload with _type=${this._type} when deserialize error`);
      return false;
    }
    if (!this._payload.deserialize(istream, this._payloadVersion)) return false;

    let attributeLength = istream.readVarUInt();
    if (attributeLength === null) return false;

    this._attributes = [];
    for (let i = 0; i < attributeLength.toNumber(); i++) {
      let attribute = new Attribute();
      if (!attribute.deserialize(istream)) {
        Log.error("deserialize tx attribute[{}] error", i);
        return false;
      }
      this._attributes.push(attribute);
    }

    let inCount = istream.readVarUInt();
    if (inCount === null) {
      Log.error("deserialize tx inCount error");
      return false;
    }

    this._inputs = [];
    for (let i = 0; i < inCount.toNumber(); i++) {
      let input = new TransactionInput();
      if (!input.deserialize(istream)) {
        Log.error("deserialize tx input [{}] error", i);
        return false;
      }
      this._inputs.push(input);
    }

    let outputLength = istream.readVarUInt();
    if (outputLength === null) {
      Log.error("deserialize tx output length error");
      return false;
    }

    if (outputLength.gt(UINT16_MAX)) {
      Log.error("deserialize tx: too much outputs: {}", outputLength);
      return false;
    }

    this._outputs = [];
    for (let i = 0; i < outputLength.toNumber(); i++) {
      let output = new TransactionOutput();
      if (!output.deserialize(istream, this._version)) {
        Log.error("deserialize tx output[{}] error", i);
        return false;
      }

      this._outputs.push(output);
    }

    this._lockTime = istream.readUInt32();
    if (this._lockTime === null) {
      Log.error("deserialize tx lock time error");
      return false;
    }

    let programLength = istream.readVarUInt();
    if (programLength === null) {
      Log.error("deserialize tx program length error");
      return false;
    }

    this._programs = [];
    for (let i = 0; i < programLength.toNumber(); i++) {
      let program = new Program();
      if (!program.deserialize(istream)) {
        Log.error("deserialize program[{}] error", i);
        return false;
      }
      this._programs.push(program);
    }

    return true;
  }

  public toJson(): TransactionInfo {
    return {
      IsRegistered: this._isRegistered,
      TxHash: this.getHash().toString(16),
      Version: this._version,
      LockTime: this._lockTime,
      BlockHeight: this._blockHeight,
      Timestamp: this._timestamp,
      Inputs: this._inputs.map((i) => i.toJson()),
      Type: this._type,
      PayloadVersion: this._payloadVersion,
      PayLoad: this._payload.toJson(this._payloadVersion),
      Attributes: this._attributes.map((a) => a.toJson()),
      Programs: this._programs.map((p) => p.toJson()),
      Outputs: this._outputs.map((o) => o.toJson()),
      Fee: this._fee.toNumber()
    };
  }

  public fromJson(j: TransactionInfo) {
    this.reinit();

    try {
      this._isRegistered = j["IsRegistered"];

      this._version = j["Version"];
      this._lockTime = j["LockTime"];
      this._blockHeight = j["BlockHeight"];
      this._timestamp = j["Timestamp"];
      this._inputs = j["Inputs"].map((i) => new TransactionInput().fromJson(i));
      this._type = j["Type"];
      this._payloadVersion = j["PayloadVersion"];
      this._payload = this.initPayload(this._type);

      if (this._payload === null) {
        Log.error("_payload is nullptr when convert from json");
      } else {
        this._payload.fromJson(j["PayLoad"], this._payloadVersion);
      }

      this._attributes = j["Attributes"].map((a) =>
        new Attribute().fromJson(a)
      );
      this._programs = j["Programs"].map((p) => new Program().fromJson(p));
      this._outputs = j["Outputs"].map((o) =>
        new TransactionOutput().fromJson(o)
      );
      this._fee = new BigNumber(j["Fee"]);

      this._txHash = new BigNumber(j["TxHash"], 16);
    } catch (e) {
      ErrorChecker.throwLogicException(
        Error.Code.JsonFormatError,
        "tx from json: " + e
      );
    }
  }

  public calculateFee(feePerKb: uint64_t): uint64_t {
    return new BigNumber((this.estimateSize() + 999) / 1000).multipliedBy(
      feePerKb
    );
  }

  getShaData(): uint256 {
    let stream = new ByteStream();
    this.serializeUnsigned(stream);
    const str = SHA256.encodeToBuffer(stream.getBytes()).toString("hex");
    return new BigNumber(str, 16);
  }

  initPayload(type: uint8_t): Payload {
    let payload: Payload = null;

    if (type == TransactionType.coinBase) {
      payload = new CoinBase();
    } else if (type == TransactionType.registerAsset) {
      payload = new RegisterAsset();
    } else if (type == TransactionType.transferAsset) {
      payload = new TransferAsset();
    } else if (type == TransactionType.record) {
      payload = new Record();
    } else if (type == TransactionType.deploy) {
      //todo add deploy _payload
      //_payload = boost::shared_ptr<PayloadDeploy>(new PayloadDeploy());
    } else if (type == TransactionType.sideChainPow) {
      payload = new SideChainPow();
    } else if (type == TransactionType.rechargeToSideChain) {
      // side chain payload
      payload = new RechargeToSideChain();
    } else if (type == TransactionType.withdrawFromSideChain) {
      payload = new WithdrawFromSideChain();
    } else if (type == TransactionType.transferCrossChainAsset) {
      payload = new TransferCrossChainAsset();
    } else if (
      type == TransactionType.registerProducer ||
      type == TransactionType.updateProducer
    ) {
      payload = new ProducerInfo();
    } else if (type == TransactionType.cancelProducer) {
      payload = new CancelProducer();
    } else if (type == TransactionType.returnDepositCoin) {
      payload = new ReturnDepositCoin();
    } else if (type == TransactionType.nextTurnDPOSInfo) {
      payload = new NextTurnDPoSInfo();
    } else if (
      type == TransactionType.registerCR ||
      type == TransactionType.updateCR
    ) {
      payload = new CRInfo();
    } else if (type == TransactionType.unregisterCR) {
      payload = new UnregisterCR();
    } else if (type == TransactionType.returnCRDepositCoin) {
      payload = new ReturnDepositCoin();
    } else if (type == TransactionType.crcProposal) {
      payload = new CRCProposal();
    } else if (type == TransactionType.crcProposalReview) {
      payload = new CRCProposalReview();
    } else if (type == TransactionType.crcProposalTracking) {
      payload = new CRCProposalTracking();
    } else if (type == TransactionType.crcProposalWithdraw) {
      payload = new CRCProposalWithdraw();
    } else if (type == TransactionType.crcProposalRealWithdraw) {
      payload = new CRCProposalRealWithdraw();
    } else if (type == TransactionType.crcAssetsRectify) {
      payload = new CRCAssetsRectify();
    } else if (type == TransactionType.crCouncilMemberClaimNode) {
      payload = new CRCouncilMemberClaimNode();
    }

    return payload;
  }

  private cleanup() {
    this._inputs = [];
    this._outputs = [];
    this._attributes = [];
    this._programs = [];
    // TODO - WHERE IS THIS Payload.reset() IN C++? this._payload.reset();
  }

  public getPayloadVersion(): uint8_t {
    return this._payloadVersion;
  }

  public setPayloadVersion(version: uint8_t) {
    this._payloadVersion = version;
  }

  public getFee(): uint64_t {
    return this._fee;
  }

  public setFee(f: uint64_t) {
    this._fee = f;
  }

  public isEqual(tx: Transaction): boolean {
    return this.getHash().eq(tx.getHash());
  }

  public getConfirms(walletBlockHeight: uint32_t): uint32_t {
    if (this._blockHeight == TX_UNCONFIRMED) return 0;

    return walletBlockHeight >= this._blockHeight
      ? walletBlockHeight - this._blockHeight + 1
      : 0;
  }

  public getConfirmStatus(walletBlockHeight: uint32_t): string {
    let confirm = this.getConfirms(walletBlockHeight);

    let status: string;
    if (this.isCoinBase()) {
      status = confirm <= 100 ? "Pending" : "Confirmed";
    } else {
      status = confirm < 2 ? "Pending" : "Confirmed";
    }

    return status;
  }
}
