// Created by Aaron Voisine on 9/15/15.
// Copyright (c) 2015 breadwallet LLC
// Copyright (c) 2017-2019 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Converted from C++ to Typescript by the Elastos Foundation

import BigNumber from "bignumber.js";
import { getBNBytes } from "../common/bnutils";
import { ByteStream } from "../common/bytestream";
import { bytes_t } from "../types";
import { SHA256 } from "./sha256";

const BITCOIN_BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const RIPPLE_BASE58_CHARS = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
const DEFAULT_BASE58_CHARS = BITCOIN_BASE58_CHARS;

/**
 * Class to encode and decode buffers and strings as base58, but specialized for crypto
 * operations.
 */
export class Base58 {
	public static countLeading0sInBuffer(data: bytes_t): number {
		let i = 0;
		for (; (i < data.length) && (data[i] == 0); i++);
		return i;
	}

	/**
	 * @param numeral ASCII string
	 * @param zeroSymbol Searched character
	 */
	public static countLeading0sInString(numeral: string, zeroSymbol: string): number {
		let i = 0;
		for (; (i < numeral.length) && (numeral[i] == zeroSymbol); i++);
		return i;
	}

	/* public checkEncode(payload: bytes_t, version: uint8_t): string {
		const char * pchars = DEFAULT_BASE58_CHARS;
			uchar_vector data;
		data.push_back(version);                                        // prepend version byte
		data += payload;
			uchar_vector checksum = sha256_2(data);
		checksum.assign(checksum.begin(), checksum.begin() + 4);        // compute checksum
		data += checksum;                                               // append checksum
			BigInt bn(data);
		let base58check: string = bn.getInBase(58, pchars);             // convert to base58
		std::string leading0s(countLeading0s(data), pchars[0]);         // prepend leading 0's (1 in base58)
		return leading0s + base58check;
	} */

	public static checkEncode(payload: bytes_t, version: bytes_t = Buffer.alloc(0)): string {
		//const char * pchars = DEFAULT_BASE58_CHARS;

		let data = new ByteStream();
		data.writeBytes(version);
		data.writeBytes(payload);

		let checksum = SHA256.hashTwice(data.getBytes());
		checksum = checksum.subarray(0, 4); // WAS checksum.assign(checksum.begin(), checksum.begin() + 4);        // compute checksum

		data.writeBytes(checksum);                                             // append checksum

		return Base58.encode(data.getBytes());
	}

	public static checkDecode(base58check: string, payload: bytes_t, version: number = undefined): boolean {
		const pchars = DEFAULT_BASE58_CHARS;

		// Custom BigNumber constructor with custom alphabet
		let Base58BigNumber = BigNumber.clone({
			ALPHABET: pchars
		})

		let bn = new Base58BigNumber(base58check, 58); // convert from base58
		let bytes = getBNBytes(bn);
		if (bytes.length < 4)
			return false; // not enough bytes

		let checksum = bytes.subarray(bytes.length);
		bytes = bytes.subarray(0, bytes.length - 4);  // split string into payload part and checksum part

		let leading0s = Buffer.alloc(Base58.countLeading0sInString(base58check, pchars[0]), 0); // prepend leading 0's
		bytes = Buffer.concat([leading0s, bytes]);

		let hashBytes = SHA256.hashTwice(bytes);
		hashBytes = hashBytes.subarray(0, 4);
		if (hashBytes != checksum)
			return false;

		if (version != undefined) {  // verify checksum
			version = bytes[0];
			payload.set(bytes.subarray(1, bytes.length));
		}
		else {
			payload.set(bytes);
		}

		return true;
	}

	protected static encode(payload: bytes_t): string {
		const pchars = DEFAULT_BASE58_CHARS;

		/* #if 0
				BigInt bn(payload);
		std::string base58 = bn.getInBase(58, pchars);
		std::string leading0s(countLeading0s(payload), pchars[0]);
		return leading0s + base58;
		#else */

		let i = 0, j = 0, len = 0, zcount = 0;
		let dataLen = payload.length;

		while (zcount < dataLen && payload[zcount] == 0) zcount++; // count leading zeroes

		let bufLen = (dataLen - zcount) * 138 / 100 + 1; // log(256)/log(58), rounded up
		let buf = Buffer.alloc(bufLen, 0);

		for (i = zcount; i < dataLen; i++) {
			let carry = payload[i];

			for (j = bufLen; j > 0; j--) {
				// TODO: CHECK THIS CODE MIGRATION!
				carry += 0xFFFFFFFF & (buf[j - 1] << 8); // WAS (uint32_t)buf[j - 1] << 8;
				buf[j - 1] = carry % 58;
				carry /= 58;
			}
		}

		i = 0;
		while (i < bufLen && buf[i] == 0) i++; // skip leading zeroes
		len = (zcount + bufLen - i) + 1;

		let str = "";
		while (zcount-- > 0)
			str += pchars[0];

		while (i < bufLen)
			str += pchars[buf[i++]];

		return str;
		//#endif
	}

	protected static decode(base58: string): bytes_t {
		// Custom BigNumber constructor with custom alphabet
		let Base58BigNumber = BigNumber.clone({
			ALPHABET: DEFAULT_BASE58_CHARS
		})

		let bn = new Base58BigNumber(base58, 58); // convert from base58
		return getBNBytes(bn);
	}

	/* static bool Base58:: Valid(const std:: string & base58check) {
const char * pchars = DEFAULT_BASE58_CHARS;
		BigInt bn(base58check, 58, pchars);                                // convert from base58
		uchar_vector bytes = bn.getBytes();
		uchar_vector checksum = uchar_vector(bytes.end() - 4, bytes.end());
bytes.assign(bytes.begin(), bytes.end() - 4);                           // split string into payload part and checksum part
		uchar_vector leading0s(countLeading0s(base58check, pchars[0]), 0); // prepend leading 0's
bytes = leading0s + bytes;
		uchar_vector hashBytes = sha256_2(bytes);
hashBytes.assign(hashBytes.begin(), hashBytes.begin() + 4);
return (hashBytes == checksum);
} */

}