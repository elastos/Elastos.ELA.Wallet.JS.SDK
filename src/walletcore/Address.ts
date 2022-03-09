// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { ByteStream } from "../common/bytestream";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { Log } from "../common/Log";
import { uint168 } from "../common/uint168";
import { bytes_t, uint8_t } from "../types";
import { Base58 } from "./Base58";
import { SHA256 } from "./sha256";

export const ELA_SIDECHAIN_DESTROY_ADDR = "1111111111111111111114oLvT2";
export const OP_0 = 0x00;
export const OP_PUSHDATA1 = 0x4c;
export const OP_PUSHDATA2 = 0x4d;
export const OP_PUSHDATA4 = 0x4e;
export const OP_1NEGATE = 0x4f
export const OP_1 = 0x51;
export const OP_16 = 0x60;
export const OP_DUP = 0x76;
export const OP_EQUAL = 0x87;
export const OP_EQUALVERIFY = 0x88;
export const OP_HASH160 = 0xa9;
export const OP_CHECKSIG = 0xac;

export enum SignType {
	SignTypeInvalid = 0,
	SignTypeStandard = 0xAC,
	SignTypeDID = 0xAD,
	SignTypeMultiSign = 0xAE,
	SignTypeCrossChain = 0xAF,
	SignTypeDestroy = 0xAA,
}

export enum Prefix {
	PrefixStandard = 0x21,
	PrefixMultiSign = 0x12,
	PrefixCrossChain = 0x4B,
	PrefixCRExpenses = 0x1C,
	PrefixDeposit = 0x1F,
	PrefixIDChain = 0x67,
	PrefixDestroy = 0,
}

export type AddressArray = Address[];

export class Address {
	private _programHash: uint168;
	private _code: bytes_t;
	private _isValid = false;

	public static newFromAddressString(address: string): Address {
		let addr = new Address();

		if (!address) {
			addr._isValid = false;
		} else {
			let payload: bytes_t;
			if (Base58.checkDecode(address, payload)) {
				addr._programHash = uint168.newFrom21BytesBuffer(payload);
				addr.checkValid();
			} else {
				Log.error("invalid address {}", address);
				addr._isValid = false;
			}
		}
		return addr;
	}

	public static newFromAddress(address: Address): Address {
		let addr = new Address();
		addr._programHash = address._programHash;
		addr._code = address._code;
		addr._isValid = address._isValid;
		return addr;
	}

	public static newWithPubKey(prefix: Prefix, pubKey: bytes_t, did = false): Address {
		return Address.newWithPubKeys(prefix, [pubKey], 1, did);
	}

	public static newWithPubKeys(prefix: Prefix, pubkeys: bytes_t[], m: uint8_t, did = false) {
		let address = new Address();
		if (pubkeys.length == 0) {
			address._isValid = false;
		} else {
			address.generateCode(prefix, pubkeys, m, did);
			address.generateProgramHash(prefix);
			address.checkValid();
		}
		return address;
	}

	/*Address::Address(const uint168 &programHash) {
		_programHash = programHash;
		CheckValid();
	}

	Address::Address(const Address &address) {
		operator=(address);
	}
*/
	public Valid(): boolean {
		return this._isValid;
	}

	/*bool Address::IsIDAddress() const {
		return _isValid && _programHash.prefix() == PrefixIDChain;
	}*/

	public String(): string {
		return Base58.checkEncode(this._programHash.bytes());
	}

	public ProgramHash(): uint168 {
		return this._programHash;
	}

	SetProgramHash(programHash: uint168) {
		this._programHash = programHash;
		this.checkValid();
	}

	public prefixToSignType(prefix: Prefix): SignType {
		let type: SignType;

		switch (prefix) {
			case Prefix.PrefixIDChain:
			case Prefix.PrefixStandard:
			case Prefix.PrefixDeposit:
				type = SignType.SignTypeStandard;
				break;
			case Prefix.PrefixCrossChain:
				type = SignType.SignTypeCrossChain;
				break;
			case Prefix.PrefixMultiSign:
				type = SignType.SignTypeMultiSign;
				break;
			case Prefix.PrefixDestroy:
				type = SignType.SignTypeDestroy;
				break;
			default:
				Log.error("invalid prefix {}", prefix);
				type = SignType.SignTypeInvalid;
				break;
		}

		return type;
	}

	public SetRedeemScript(prefix: Prefix, code: bytes_t) {
		this._code = code;
		this.generateProgramHash(prefix);
		this.checkValid();
		ErrorChecker.CheckCondition(!this._isValid, Error.Code.InvalidArgument, "redeemscript is invalid");
	}

	/*bool Address::ChangePrefix(Prefix prefix) {
		ErrorChecker::CheckCondition(!_isValid, Error::Address, "can't change prefix with invalid addr");
		SignType oldSignType = SignType(_code.back());
		if (oldSignType == SignTypeMultiSign || PrefixToSignType(prefix) == SignTypeMultiSign)
			ErrorChecker::ThrowLogicException(Error::Address, "can't change to or from multi-sign prefix");

		GenerateProgramHash(prefix);
		return true;
	}

	void Address::ConvertToDID() {
		if (!_code.empty() && _programHash.prefix() == PrefixIDChain) {
			_code.back() = SignTypeDID;
			GenerateProgramHash(PrefixIDChain);
		}
	}

	const bytes_t &Address::RedeemScript() const {
		assert(!_code.empty());
		return _code;
	}

	bool Address::operator<(const Address &address) const {
		return _programHash < address._programHash;
	}
*/

	public equals(address: Address | string): boolean {
		if (typeof address === "string")
			return this._isValid && this.String() === address;
		else
			return this._isValid == address._isValid && this._programHash == address._programHash;
	}

	/*	bool Address::operator!=(const Address &address) const {
			return _programHash != address._programHash;
		}

		bool Address::operator!=(const std::string &address) const {
			return this->String() != address;
		}*/

	generateCode(prefix: Prefix, pubkeys: bytes_t[], m: uint8_t, did: boolean) {
		ErrorChecker.CheckLogic(m > pubkeys.length || m == 0, Error.Code.MultiSignersCount, "Invalid m");

		let bytes = new ByteStream();
		if (m == 1 && pubkeys.length == 1) {
			bytes.writeUInt8(pubkeys[0].length);
			bytes.writeBytes(pubkeys[0]);
			if (did)
				bytes.writeUInt8(SignType.SignTypeDID);
			else
				bytes.writeUInt8(this.prefixToSignType(prefix));
		} else {
			// TODO: CANT UNDERSTAND THIS CODE: pubkeys.size() > sizeof(uint8_t) - OP_1 ... sizeof(uint8_t) should be 1...
			ErrorChecker.CheckCondition(pubkeys.size() > sizeof(uint8_t) - OP_1, Error.Code.MultiSignersCount,
				"Signers should less than 205.");

			let sortedSigners: bytes_t[] = Array.from(pubkeys);
			sortedSigners.sort((a, b) => {
				return a.toString("hex").localeCompare(b.toString("hex"));
				// WAS return a.getHex() < b.getHex();
			})

			bytes.writeUInt8(OP_1 + m - 1);
			for (let i = 0; i < sortedSigners.length; i++) {
				bytes.writeUInt8(sortedSigners[i].length);
				bytes.writeBytes(sortedSigners[i]);
			}
			bytes.writeUInt8(OP_1 + sortedSigners.length - 1);
			bytes.writeUInt8(this.prefixToSignType(prefix));
		}

		this._code = bytes.getBytes();
	}

	public generateProgramHash(prefix: Prefix) {
		let hash: bytes_t = SHA256.sha256ripemd160(this._code);
		this._programHash = uint168.newFromPrefixAndHash(prefix, hash);
	}

	private programHashPrefix(): Prefix {
		return this._programHash.prefix();
	}

	public checkValid(): boolean {
		if (this.programHashPrefix() == Prefix.PrefixDeposit ||
			this.programHashPrefix() == Prefix.PrefixStandard ||
			this.programHashPrefix() == Prefix.PrefixCrossChain ||
			this.programHashPrefix() == Prefix.PrefixMultiSign ||
			this.programHashPrefix() == Prefix.PrefixIDChain ||
			this.programHashPrefix() == Prefix.PrefixDestroy ||
			this.programHashPrefix() == Prefix.PrefixCRExpenses) {
			this._isValid = true;
		} else {
			this._isValid = false;
		}

		return this._isValid;
	}
}