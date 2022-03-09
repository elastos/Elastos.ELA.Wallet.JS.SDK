// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import BigNumber from "bignumber.js";
import { getBNBytes, getBNHexBytes, getBNsize, newBNFromHexBytes } from "../common/bnutils";
import { ByteStream } from "../common/bytestream";
import { JsonSerializer } from "../common/JsonSerializer";
import { Log } from "../common/Log";
import { uint168 } from "../common/uint168";
import { bytes_t, json, sizeof_uint168_t, sizeof_uint256_t, sizeof_uint64_t, size_t, uint256, uint32_t, uint8_t } from "../types";
import { Address } from "../walletcore/Address";
import { Asset } from "./Asset";
import { OutputPayload } from "./payload/OutputPayload/OutputPayload";
import { PayloadDefault } from "./payload/OutputPayload/PayloadDefault";
import { TxVersion } from "./Transaction";

export enum Type {
	Default = 0x00,
	VoteOutput = 0x01,
	Mapping = 0x02,
	CrossChain = 0x03
}

export type OutputPtr = TransactionOutput;
export type OutputArray = OutputPtr[];

export class TransactionOutput implements JsonSerializer {
	private _amount: BigNumber = new BigNumber(0); // to support token chain
	private _assetID: uint256;
	private _outputLock: uint32_t = 0;
	private _address: Address;

	private _outputType: Type = Type.Default;

	private _payload: OutputPayload;

	constructor() {
		this._payload = this.generatePayload(this._outputType);
	}

	/*TransactionOutput::TransactionOutput(const TransactionOutput &output) {
		this->operator=(output);
	}*/

	public static newFromTransactionOutput(o: TransactionOutput): TransactionOutput {
		let transactionOutput = new TransactionOutput();

		transactionOutput._amount = o._amount;
		transactionOutput._assetID = o._assetID;
		transactionOutput._address = o._address;
		transactionOutput._outputLock = o._outputLock;
		transactionOutput._outputType = o._outputType;
		transactionOutput._payload = transactionOutput.generatePayload(o._outputType);
		transactionOutput._payload = o._payload;

		return transactionOutput;
	}

	public static newFromParams(a: BigNumber, addr: Address, assetID: uint256 = Asset.GetELAAssetID(), type: Type = Type.Default, payload: OutputPayload = null): TransactionOutput {
		let txOutput = new TransactionOutput();
		txOutput._outputLock = 0;
		txOutput._outputType = type;

		txOutput._assetID = assetID;
		txOutput._amount = a;
		txOutput._address = addr;

		if (payload === null) {
			txOutput._payload = txOutput.generatePayload(txOutput._outputType);
		} else {
			txOutput._payload = payload;
		}
		return txOutput;
	}

	public getAddress(): Address {
		return this._address;
	}

	public amount(): BigNumber {
		return this._amount;
	}

	public setAmount(a: BigNumber) {
		this._amount = a;
	}

	public estimateSize(): size_t {
		let size = 0;
		let stream = new ByteStream();

		size += getBNsize(this._assetID); // WAS this._assetID.size();
		if (this._assetID == Asset.GetELAAssetID()) {
			size += 8; // WAS sizeof(uint64_t);
		} else {
			let amountBytes: bytes_t = getBNHexBytes(this._amount); // WAS this._amount.getHexBytes();
			size += stream.writeVarUInt(amountBytes.length);
			size += amountBytes.length;
		}

		size += 4; // WAS sizeof(this._outputLock);
		size += this._address.programHash().bytes().length; // WAS this._address.programHash().size();

		return size;
	}

	public serialize(ostream: ByteStream, txVersion: uint8_t) {
		ostream.writeBytes(getBNBytes(this._assetID));

		if (this._assetID == Asset.GetELAAssetID()) {
			//let bytes: bytes_t = getBNHexBytes(this._amount); // WAS this._amount.getHexBytes(true);
			//let amount: uint64_t = Buffer.alloc(sizeof_uint64_t());
			//memcpy(& amount, & bytes[0], Math.min(bytes.length, sizeof_uint64_t()));

			// TODO: PROBABLY WRONG!
			ostream.writeBNAsUIntOfSize(this._amount, 8); // WAS ostream.WriteUint64(amount);
		} else {
			ostream.writeVarBytes(getBNHexBytes(this._amount));
		}

		ostream.writeUInt32(this._outputLock);
		ostream.writeBytes(this._address.programHash().bytes());

		if (txVersion >= TxVersion.V09) {
			ostream.writeUInt8(this._outputType);
			this._payload.serialize(ostream);
		}
	}

	public deserialize(istream: ByteStream, txVersion: uint8_t): boolean {
		this._assetID = istream.readUIntOfBytesAsBN(sizeof_uint256_t());
		if (this._assetID === null) {
			Log.error("deserialize output assetid error");
			return false;
		}

		if (this._assetID.eq(Asset.GetELAAssetID())) {
			this._amount = istream.readUIntOfBytesAsBN(sizeof_uint64_t()); // WAS this._amount.setHexBytes(bytes_t(& amount, sizeof(amount)), true);
			if (this._amount === null) {
				Log.error("deserialize output amount error");
				return false;
			}
		} else {
			let bytes = Buffer.alloc(0);
			if (!istream.readVarBytes(bytes)) {
				Log.error("deserialize output BN amount error");
				return false;
			}
			this._amount = newBNFromHexBytes(bytes); // WAS this._amount.setHexBytes(bytes);
		}

		this._outputLock = istream.readUInt32();
		if (this._outputLock === null) {
			Log.error("deserialize output lock error");
			return false;
		}

		let programHash = Buffer.alloc(sizeof_uint168_t());
		if (!istream.readBytes(programHash, sizeof_uint168_t())) {
			Log.error("deserialize output program hash error");
			return false;
		}
		this._address.setProgramHash(uint168.newFrom21BytesBuffer(programHash));

		if (txVersion >= TxVersion.V09) {
			this._outputType = istream.readUInt8();
			if (this._outputType === null) {
				Log.error("tx output deserialize output type error");
				return false;
			}

			this._payload = this.generatePayload(this._outputType);

			if (!this._payload.deserialize(istream)) {
				Log.error("tx output deserialize payload error");
				return false;
			}
		}

		return true;
	}

	public isValid(): boolean {
		return true;
	}

	public assetID(): uint256 {
		return this._assetID;
	}

	public setAssetID(assetId: uint256) {
		this._assetID = assetId;
	}

	public outputLock(): uint32_t {
		return this._outputLock;
	}

	public setOutputLock(lock: uint32_t) {
		this._outputLock = lock;
	}

	public getType(): Type {
		return this._outputType;
	}

	public setType(type: Type) {
		this._outputType = type;
	}

	public getPayload(): OutputPayload {
		return this._payload;
	}

	public setPayload(payload: OutputPayload) {
		this._payload = payload;
	}

	public generatePayload(type: Type): OutputPayload {
		let payload: OutputPayload;

		switch (type) {
			case Type.Default:
				payload = new PayloadDefault();
				break;
			/* TODO case Type.VoteOutput:
				payload = new PayloadVote();
				break;
			case Type.CrossChain:
				payload = new PayloadCrossChain();
				break; */
			default:
				payload = null;
				break;
		}

		return payload;
	}

	public toJson(): json {
		return {
			Amount: this._amount.toString(), // WAS this._amount.getDec(),
			AssetId: this._assetID.toString(16), // WAS this._assetID.GetHex(),
			OutputLock: this._outputLock,
			ProgramHash: this._address.programHash().bytes().toString("hex"), // WAS this._address.ProgramHash().GetHex(),
			Address: this._address.string(),
			OutputType: this._outputType,
			Payload: this._payload.toJson()
		}
	}

	public fromJson(j: json): TransactionOutput {
		this._amount = new BigNumber(j["Amount"] as string);
		this._assetID = new BigNumber(j["AssetId"] as string, 16);
		this._outputLock = j["OutputLock"] as number;
		this._address.setProgramHash(uint168.newFrom21BytesBuffer(Buffer.from(j["ProgramHash"] as string, "hex")));

		this._outputType = j["OutputType"] as Type;
		this._payload = this.generatePayload(this._outputType);
		this._payload.fromJson(j["Payload"] as json);

		return this;
	}

	public equals(o: TransactionOutput): boolean {
		return this._assetID.eq(o._assetID) &&
			this._amount.eq(o._amount) &&
			this._outputLock == o._outputLock &&
			this._address.equals(o._address) &&
			this._outputType == o._outputType &&
			this._payload.equals(o._payload);
	}

	/*bool TransactionOutput:: operator != (const TransactionOutput & o) const {
	return !operator == (o);;
	} */
}