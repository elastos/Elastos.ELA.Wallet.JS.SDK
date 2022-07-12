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

import { SidechainSubWallet } from "./SidechainSubWallet";
import { CoinInfo } from "../walletcore/CoinInfo";
import { ChainConfig } from "../config";
import { MasterWallet } from "./MasterWallet";
import { UTXOInput, UTXOSet } from "./UTXO";
import { BigNumber } from "bignumber.js";
import { ErrorChecker, Error } from "../common/ErrorChecker";
import { DIDInfo, DIDInfoJson } from "../transactions/payload/DIDInfo";
import { EncodedTx } from "./IElastosBaseSubWallet";
import { Address, Prefix } from "../walletcore/Address";
import { Asset } from "../transactions/Asset";
import { TransactionOutput } from "../transactions/TransactionOutput";
import { uint32_t } from "../types";
import { IDTransactionType } from "../transactions/IDTransaction";
import { EcdsaSigner } from "../walletcore/ecdsasigner";

export class IDChainSubWallet extends SidechainSubWallet {
  constructor(
    info: CoinInfo,
    config: ChainConfig,
    parent: MasterWallet,
    netType?: string
  ) {
    super(info, config, parent, netType);
  }

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
    payloadJson: DIDInfoJson,
    memo = "",
    fee = "10000"
  ) {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJson.dump());
    // ArgInfo("memo: {}", memo);
    // ArgInfo("fee: {}", fee);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let userFee = new BigNumber(fee);

    ErrorChecker.checkParam(
      userFee.isLessThan(0),
      Error.Code.InvalidArgument,
      "invalid fee"
    );

    let receiveAddr: Address;
    let payload: DIDInfo;
    let outputs = [];
    try {
      payload = new DIDInfo();
      payload.fromJson(payloadJson, 0);

      let didInfo = payload;
      // ErrorChecker::CheckParam(!didInfo->IsValid(0), Error::InvalidArgument, "verify did signature failed");
      let idSplited: string[] = [];
      if (didInfo.didPayload().controller().length == 0) {
        for (let controller of didInfo.didPayload().controller()) {
          idSplited = controller.split(":");
          ErrorChecker.checkParam(
            idSplited.length != 3,
            Error.Code.InvalidArgument,
            "invalid id format in payload JSON"
          );
          receiveAddr = Address.newFromAddressString(idSplited[2]);
          ErrorChecker.checkParam(
            !receiveAddr.valid(),
            Error.Code.InvalidArgument,
            "invalid receive addr(id) in payload JSON"
          );
          outputs.push(
            TransactionOutput.newFromParams(
              new BigNumber(0),
              receiveAddr,
              Asset.getELAAssetID()
            )
          );
        }
      } else {
        let id = didInfo.didPayload().id();
        idSplited = id.split(":");
        ErrorChecker.checkParam(
          idSplited.length != 3,
          Error.Code.InvalidArgument,
          "invalid id format in payload JSON"
        );
        receiveAddr = Address.newFromAddressString(idSplited[2]);
        ErrorChecker.checkParam(
          !receiveAddr.valid(),
          Error.Code.InvalidArgument,
          "invalid receive addr(id) in payload JSON"
        );
        outputs.push(
          TransactionOutput.newFromParams(
            new BigNumber(0),
            receiveAddr,
            Asset.getELAAssetID()
          )
        );
      }
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "Create id tx param error: " + e
      );
    }

    let tx = wallet.createTransaction(
      IDTransactionType.didTransaction,
      payload,
      utxo,
      outputs,
      memo,
      userFee
    );

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());

    return result;
  }

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
  getDID(
    index: uint32_t,
    count: uint32_t,
    internal: boolean
  ): { DID: string[] } {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("index: {}", index);
    // ArgInfo("count: {}", count);
    // ArgInfo("internal: {}", internal);

    let j = <{ DID: string[] }>{};
    let cid: Address[] = [];
    this.getWallet().getCID(cid, index, count, internal);

    let didArray: string[] = [];
    for (let i = 0; i < cid.length; ++i) {
      let tmp = cid[i];
      tmp.convertToDID();
      didArray.push(tmp.string());
    }

    j["DID"] = didArray;

    // ArgInfo("r => {}", j.dump());
    return j;
  }

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
  getCID(
    index: uint32_t,
    count: uint32_t,
    internal: boolean
  ): { CID: string[] } {
    // ArgInfo("{} {}", this.getWallet()->getWalletID(), GetFunName());
    // ArgInfo("index: {}", index);
    // ArgInfo("count: {}", count);
    // ArgInfo("internal: {}", internal);

    let j = <{ CID: string[] }>{};
    let cid: Address[] = [];
    this.getWallet().getCID(cid, index, count, internal);

    let cidArray: string[] = [];
    for (let a of cid) {
      cidArray.push(a.string());
    }

    j["CID"] = cidArray;

    // ArgInfo("r => {}", j.dump());
    return j;
  }

  /**
   * Sign message with private key of did.
   * @param DIDOrCID will sign the message with public key of this did/cid.
   * @param message to be signed.
   * @param payPassword password.
   * @return If success, signature will be returned.
   */
  async sign(
    DIDOrCID: string,
    message: string,
    payPassword: string
  ): Promise<string> {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("DIDOrCID: {}", DIDOrCID);
    // ArgInfo("message: {}", message);
    // ArgInfo("payPasswd: *");

    let didAddress = Address.newFromAddressString(DIDOrCID);
    let signature = await this.getWallet().signWithAddress(
      didAddress,
      message,
      payPassword
    );

    // ArgInfo("r => {}", signature);

    return Promise.resolve(signature);
  }

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
  ): boolean {
    // ArgInfo("{} {}", this.getSubWalletID(), GetFunName());
    // ArgInfo("pubkey: {}", publicKey);
    // ArgInfo("message: {}", message);
    // ArgInfo("signature: {}", signature);

    let r = EcdsaSigner.verify(
      publicKey,
      Buffer.from(signature, "hex"),
      Buffer.from(message, "hex")
    );

    // ArgInfo("r => {}", r);
    return r;
  }

  /**
   * Get DID by public key
   * @param pubkey public key
   * @return did string
   */
  getPublicKeyDID(pubkey: string): string {
    // ArgInfo("{} {}", this.getSubWalletID(), GetFunName());
    // ArgInfo("pubkey:{}", pubkey);

    ErrorChecker.checkParamNotEmpty(pubkey, "public key");

    let address = Address.newWithPubKey(
      Prefix.PrefixIDChain,
      Buffer.from(pubkey, "hex"),
      true
    );

    let did = address.string();
    // ArgInfo("r => {}", did);
    return did;
  }

  /**
   * Get CID by public key
   * @param pubkey
   * @return cid string
   */
  getPublicKeyCID(pubkey: string): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("pubkey: {}", pubkey);

    ErrorChecker.checkParamNotEmpty(pubkey, "public key");

    let address = Address.newWithPubKey(
      Prefix.PrefixIDChain,
      Buffer.from(pubkey, "hex")
    );

    let cid = address.string();
    // ArgInfo("r => {}", cid);
    return cid;
  }
}
