// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import BigNumber from "bignumber.js";
import { ByteStream } from "../common/bytestream";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { Log } from "../common/Log";
import {
  INT32_MAX,
  json,
  JSONArray,
  size_t,
  time_t,
  UINT16_MAX,
  uint256,
  uint32_t,
  uint64_t,
  uint8_t
} from "../types";
import { SHA256 } from "../walletcore/sha256";
import { Attribute } from "./Attribute";
import { CoinBase } from "./payload/CoinBase";
import { TransferAsset } from "./payload/TransferAsset";
import { RegisterAsset } from "./payload/RegisterAsset";
import { Payload } from "./payload/Payload";
import { Program } from "./Program";
import { TransactionInput } from "./TransactionInput";
import { TransactionOutput } from "./TransactionOutput";

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

  /*	bool Transaction::operator==(const Transaction &tx) const {
			bool equal = _version == tx._version &&
						 _lockTime == tx._lockTime &&
						 _blockHeight == tx._blockHeight &&
						 _timestamp == tx._timestamp &&
						 _type == tx._type &&
						 _payloadVersion == tx._payloadVersion &&
						 _outputs.size() == tx._outputs.size() &&
						 _inputs.size() == tx._inputs.size() &&
						 _attributes.size() == tx._attributes.size() &&
						 _programs.size() == tx._programs.size();

			if (equal)
				equal = _payload->Equal(*tx._payload, _payloadVersion);

			if (equal)
				for (int i = 0; i < _outputs.size(); ++i)
					if (*_outputs[i] != *tx._outputs[i]) {
						equal = false;
						break;
					}

			if (equal)
				for (int i = 0; i < _inputs.size(); ++i)
					if (*_inputs[i] != *tx._inputs[i]) {
						equal = false;
						break;
					}

			if (equal)
				for (int i = 0; i < _attributes.size(); ++i)
					if (*_attributes[i] != *tx._attributes[i]) {
						equal = false;
						break;
					}

			if (equal)
				for (int i = 0; i < _programs.size(); ++i)
					if (*_programs[i] != *tx._programs[i]) {
						equal = false;
						break;
					}

			return equal;
		}
*/
  public isRegistered(): boolean {
    return this._isRegistered;
  }

  public resetHash() {
    this._txHash = new BigNumber(0);
  }

  public getHash(): uint256 {
    // this._txHash is undefined when sign a tx
    if (!this._txHash || this._txHash.eq(0)) {
      let stream: ByteStream = new ByteStream();
      this.serializeUnsigned(stream);
      this._txHash = new BigNumber(
        SHA256.hashTwice(stream.getBytes()).toString("hex"),
        16
      ); // WAS this._txHash = sha256_2(stream.getBytes());
    }
    return this._txHash;
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

  /*std::vector<uint8_t> Transaction::GetDPoSTxTypes() {
		return {registerProducer, cancelProducer, updateProducer, returnDepositCoin, activateProducer};
	}

	std::vector<uint8_t> Transaction::GetCRCTxTypes() {
		return {registerCR, unregisterCR, updateCR, returnCRDepositCoin, crCouncilMemberClaimNode};
	}

	std::vector<uint8_t> Transaction::GetProposalTypes() {
		return {crcProposal, crcProposalReview, crcProposalTracking, crcAppropriation, crcProposalWithdraw};
	}
*/
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

  /*	void Transaction::RemoveOutput(const OutputPtr &output) {
			for (std::vector<OutputPtr>::iterator it = _outputs.begin(); it != _outputs.end(); ) {
				if (output == (*it)) {
					it = _outputs.erase(it);
					break;
				} else {
					++it;
				}
			}
		}

		const std::vector<InputPtr> &Transaction::GetInputs() const {
			return _inputs;
		}

		std::vector<InputPtr>& Transaction::GetInputs() {
			return _inputs;
		}*/

  public addInput(Input: TransactionInput) {
    this._inputs.push(Input);
  }

  /*	bool Transaction::ContainInput(const uint256 &hash, uint32_t n) const {
			for (size_t i = 0; i < _inputs.size(); ++i) {
				if (_inputs[i]->TxHash() == hash && n == _inputs[i]->Index()) {
					return true;
				}
			}

			return false;
		}

		uint32_t Transaction::GetLockTime() const {

			return _lockTime;
		}

		void Transaction::SetLockTime(uint32_t t) {

			_lockTime = t;
		}

		uint32_t Transaction::GetBlockHeight() const {
			return _blockHeight;
		}

		void Transaction::SetBlockHeight(uint32_t height) {
			_blockHeight = height;
		}

		time_t Transaction::GetTimestamp() const {
			return _timestamp;
		}

		void Transaction::SetTimestamp(time_t t) {
			_timestamp = t;
		}*/

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

  public getSignedInfo(): JSONArray {
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

	const PayloadPtr &Transaction::GetPayloadPtr() const {
		return _payload;
	}

	void Transaction::SetPayload(const PayloadPtr &payload) {
		_payload = payload;
	}*/

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

    /* #if 0
				ByteStream stream;
				SerializeUnsigned(stream);
				_txHash = sha256_2(stream.GetBytes());
		#endif */

    return true;
  }

  public toJson(): json {
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

  public fromJson(j: json) {
    this.reinit();

    try {
      this._isRegistered = j["IsRegistered"] as boolean;

      this._version = j["Version"] as TxVersion;
      this._lockTime = j["LockTime"] as uint32_t;
      this._blockHeight = j["BlockHeight"] as uint32_t;
      this._timestamp = j["Timestamp"] as uint32_t;
      this._inputs = (j["Inputs"] as JSONArray).map((i) =>
        new TransactionInput().fromJson(i as json)
      );
      this._type = j["Type"] as uint8_t;
      this._payloadVersion = j["PayloadVersion"] as number;
      this._payload = this.initPayload(this._type);

      if (this._payload === null) {
        Log.error("_payload is nullptr when convert from json");
      } else {
        this._payload.fromJson(j["PayLoad"] as json, this._payloadVersion);
      }

      this._attributes = (j["Attributes"] as JSONArray).map((a) =>
        new Attribute().fromJson(a as json)
      );
      this._programs = (j["Programs"] as JSONArray).map((p) =>
        new Program().fromJson(p as json)
      );
      this._outputs = (j["Outputs"] as JSONArray).map((o) =>
        new TransactionOutput().fromJson(o as json)
      );
      this._fee = new BigNumber(j["Fee"] as number);

      this._txHash = new BigNumber(j["TxHash"] as string, 16);
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
    } /*else if (type == record) {
			payload = PayloadPtr(new Record());
		} else if (type == deploy) {
			//todo add deploy _payload
			//_payload = boost::shared_ptr<PayloadDeploy>(new PayloadDeploy());
		} else if (type == sideChainPow) {
			payload = PayloadPtr(new SideChainPow());
		} else if (type == rechargeToSideChain) { // side chain payload
			payload = PayloadPtr(new RechargeToSideChain());
		} else if (type == withdrawFromSideChain) {
			payload = PayloadPtr(new WithdrawFromSideChain());
		} else if (type == transferCrossChainAsset) {
			payload = PayloadPtr(new TransferCrossChainAsset());
		} else if (type == registerProducer || type == updateProducer) {
			payload = PayloadPtr(new ProducerInfo());
		} else if (type == cancelProducer) {
			payload = PayloadPtr(new CancelProducer());
		} else if (type == returnDepositCoin) {
			payload = PayloadPtr(new ReturnDepositCoin());
		} else if (type == nextTurnDPOSInfo) {
			payload = PayloadPtr(new NextTurnDPoSInfo());
		} else if (type == registerCR || type == updateCR) {
			payload = PayloadPtr(new CRInfo());
		} else if (type == unregisterCR) {
			payload = PayloadPtr(new UnregisterCR());
		} else if (type == returnCRDepositCoin) {
			payload = PayloadPtr(new ReturnDepositCoin());
		} else if (type == crcProposal) {
			payload = PayloadPtr(new CRCProposal());
		} else if (type == crcProposalReview) {
			payload = PayloadPtr(new CRCProposalReview());
		} else if (type == crcProposalTracking) {
			payload = PayloadPtr(new CRCProposalTracking());
		} else if (type == crcProposalWithdraw) {
			payload = PayloadPtr(new CRCProposalWithdraw());
		} else if (type == crcProposalRealWithdraw) {
			payload = PayloadPtr(new CRCProposalRealWithdraw());
		} else if (type == crcAssetsRectify) {
			payload = PayloadPtr(new CRCAssetsRectify());
		} else if (type == crCouncilMemberClaimNode) {
			payload = PayloadPtr(new CRCouncilMemberClaimNode());
		} */

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
    return this.getHash() == tx.getHash();
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
