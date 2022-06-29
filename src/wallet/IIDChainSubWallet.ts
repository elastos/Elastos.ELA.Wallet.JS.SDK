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

import { Payload } from "../transactions/payload/Payload";
import { uint32_t } from "../types";
import { ISidechainSubWallet } from "./ISidechainSubWallet";
import { UTXOInput } from "./UTXO";
export interface IIDChainSubWallet extends ISidechainSubWallet {
  /**
   * Create a id transaction and return the content of transaction in json format, this is a special transaction to register id related information on id chain.
   * @param inputs UTXO which will be used. eg
   * [
   *   {
   *     "TxHash": "...", // string
   *     "Index": 123, // int
   *     "Address": "...", // string
   *     "Amount": "100000000" // bigint string in SELA
   *   },
   *   ...
   * ]
   * @param payloadJson is payload for register id related information in json format, the content of payload should have Id, Path, DataHash, Proof, and Sign.
   * @param memo input memo attribute for describing.
   * @param fee transaction fee set by user.
   * @return If success return the content of transaction in json format.
   */
  createIDTransaction(
    inputs: UTXOInput[],
    payloadJson: Payload,
    memo: string,
    fee: string
  );

  /**
   * Get all DID derived of current subwallet.
   * @param index specify start index of all DID list.
   * @param count specify count of DID we need.
   * @param internal change address for true or normal external address for false.
   * @return If success return all DID in JSON format.
   *
   * example:
   * GetAllDID(0, 3) will return below
   * {
   *     "DID": ["iZDgaZZjRPGCE4x8id6YYJ158RxfTjTnCt", "iPbdmxUVBzfNrVdqJzZEySyWGYeuKAeKqv", "iT42VNGXNUeqJ5yP4iGrqja6qhSEdSQmeP"],
   * }
   */
  getDID(index: uint32_t, count: uint32_t, internal: boolean);

  /**
   * Get CID derived of current subwallet.
   * @param index specify start index of all CID list.
   * @param count specify count of CID we need.
   * @param internal change address for true or normal external address for false.
   * @return If success return CID in JSON format.
   *
   * example:
   * GetAllDID(0, 3) will return below
   * {
   *     "CID": ["iZDgaZZjRPGCE4x8id6YYJ158RxfTjTnCt", "iPbdmxUVBzfNrVdqJzZEySyWGYeuKAeKqv", "iT42VNGXNUeqJ5yP4iGrqja6qhSEdSQmeP"],
   * }
   */
  getCID(index: uint32_t, count: uint32_t, internal: boolean);

  /**
   * Sign message with private key of did.
   * @param DIDOrCID will sign the message with public key of this did/cid.
   * @param message to be signed.
   * @param passwd pay password.
   * @return If success, signature will be returned.
   */
  sign(DIDOrCID: string, message: string, passwd: string): string;

  /**
   * Verify signature with specify public key
   * @param publicKey public key.
   * @param message message to be verified.
   * @param signature signature to be verified.
   * @return true or false.
   */
  verifySignature(
    publicKey: string,
    message: string,
    signature: string
  ): boolean;

  /**
   * Get DID by public key
   * @param pubkey public key
   * @return did string
   */
  getPublicKeyDID(pubkey: string): string;

  /**
   * Get CID by public key
   * @param pubkey
   * @return cid string
   */
  getPublicKeyCID(pubkey: string): string;
}
