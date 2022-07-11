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
import { AccountBasicInfo } from "../account/Account";
import { PublickeysInfo, SubAccount } from "../account/SubAccount";
import { ByteStream } from "../common/bytestream";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { ChainConfig } from "../config";
import { IDTransaction } from "../transactions/IDTransaction";
import { TransferAsset } from "../transactions/payload/TransferAsset";
import { SignedInfo } from "../transactions/Program";
import { Transaction, TransactionType } from "../transactions/Transaction";
import { TransactionOutput } from "../transactions/TransactionOutput";
import { bytes_t, uint16_t, uint256, uint32_t, uint64_t } from "../types";
import { Address, AddressArray } from "../walletcore/Address";
import { CoinInfo } from "../walletcore/CoinInfo";
import { EcdsaSigner } from "../walletcore/ecdsasigner";
import {
  HDKey,
  KeySpec,
  SEQUENCE_EXTERNAL_CHAIN,
  SEQUENCE_INTERNAL_CHAIN
} from "../walletcore/hdkey";
import { EncodedTx, IElastosBaseSubWallet } from "./IElastosBaseSubWallet";
import { MasterWallet } from "./MasterWallet";
import { SubWallet } from "./SubWallet";
import { UTXO, UTXOInput, UTXOSet } from "./UTXO";
import { Wallet } from "./Wallet";
import {
  CHAINID_IDCHAIN,
  CHAINID_MAINCHAIN,
  CHAINID_TOKENCHAIN
} from "./WalletCommon";

//type WalletManagerPtr = SpvService;

export type OutputItem = { Amount: string; Address: string };

export type SigningPublicKeyInfo = {
  xPubKey: string;
  publicKey?: string;
  signed: boolean;
};

export class ElastosBaseSubWallet
  extends SubWallet
  implements IElastosBaseSubWallet
{
  // protected _walletManager: WalletManagerPtr;
  private _wallet: Wallet; // WAS: _walletManager: WalletManagerPtr - removed the SPVService, directly call the wallet object insteead

  constructor(
    info: CoinInfo,
    config: ChainConfig,
    parent: MasterWallet,
    netType?: string
  ) {
    super(info, config, parent);

    ErrorChecker.checkParam(
      !this._parent.getAccount().masterPubKeyHDPMString(),
      Error.Code.UnsupportOperation,
      "unsupport to create elastos based wallet"
    );

    // TODO boost::filesystem::path subWalletDBPath = _parent->GetDataPath();
    // TODO subWalletDBPath /= _info->GetChainID() + ".db";

    /* TODO - replace the spvservice
      _walletManager = WalletManagerPtr(
      new SpvService(_parent->GetID(), _info->GetChainID(), subAccount, subWalletDBPath,
      _config, netType)); */

    let chainID = info.getChainID();
    if (
      chainID != CHAINID_MAINCHAIN &&
      chainID != CHAINID_IDCHAIN &&
      chainID != CHAINID_TOKENCHAIN
    ) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidChainID,
        "invalid chain ID"
      );
    }

    let subAccount = new SubAccount(parent.getAccount());
    this._wallet = new Wallet(parent.getID(), chainID, subAccount);
  }

  /*const WalletManagerPtr &ElastosBaseSubWallet::GetWalletManager() const {
        return _walletManager;
    }

    void ElastosBaseSubWallet::FlushData() {
        _walletManager->DatabaseFlush();
    }*/

  destroy() {}

  //default implement ISubWallet
  public getBasicInfo(): {
    Info: { Account: AccountBasicInfo };
    ChainID: string;
  } {
    //ArgInfo("{} {}", GetSubWalletID(), GetFunName());

    return {
      Info: this.getWallet().getBasicInfo(),
      ChainID: this._info.getChainID()
    };
  }

  protected getWallet(): Wallet {
    return this._wallet;
  }

  public getAddresses(
    index: uint32_t,
    count: uint32_t,
    internal: boolean
  ): string[] {
    //ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    //ArgInfo("index: {}", index);
    //ArgInfo("count: {}", count);
    //ArgInfo("internal: {}", internal);

    ErrorChecker.checkParam(
      index + count <= index,
      Error.Code.InvalidArgument,
      "index & count overflow"
    );

    const addresses: AddressArray = this.getWallet().getAddresses(
      index,
      count,
      internal
    );

    let addressStrings: string[] = [];
    for (let address of addresses) {
      addressStrings.push(address.string());
    }

    //ArgInfo("r => {}", j.dump());

    return addressStrings;
  }

  public getPublicKeys(
    index: uint32_t,
    count: uint32_t,
    internal: boolean
  ): string[] | PublickeysInfo {
    //ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    //ArgInfo("index: {}", index);
    //ArgInfo("count: {}", count);
    //ArgInfo("internal: {}", internal);

    ErrorChecker.checkParam(
      index + count <= index,
      Error.Code.InvalidArgument,
      "index & count overflow"
    );

    let j: string[] | PublickeysInfo = this.getWallet().getPublickeys(
      index,
      count,
      internal
    );

    //ArgInfo("r => {}", j.dump());
    return j;
  }

  public createTransaction(
    inputsJson: UTXOInput[],
    outputsJson: OutputItem[],
    fee: string,
    memo: string
  ): EncodedTx {
    //ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    //ArgInfo("inputs: {}", inputsJson.dump());
    //ArgInfo("outputs: {}", outputsJson.dump());
    //ArgInfo("fee: {}", fee);
    //ArgInfo("memo: {}", memo);

    const wallet = this.getWallet();
    let utxos = new UTXOSet();
    this.UTXOFromJson(utxos, inputsJson);

    let outputs: TransactionOutput[] = [];
    this.outputsFromJson(outputs, outputsJson);

    const feeAmount = new BigNumber(fee);

    let payload = new TransferAsset();
    let tx = wallet.createTransaction(
      TransactionType.transferAsset,
      payload,
      utxos,
      outputs,
      memo,
      feeAmount
    );
    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    //ArgInfo("r => {}", result.dump());
    return result;
  }

  async signTransaction(
    tx: EncodedTx,
    payPassword: string
  ): Promise<EncodedTx> {
    /* ArgInfo("{} {}", GetSubWalletID(), GetFunName());
        ArgInfo("tx: {}", tx.dump());
        ArgInfo("passwd: *"); */

    let txn = this.decodeTx(tx);
    await this.getWallet().signTransaction(txn, payPassword);

    let result = <EncodedTx>{};
    this.encodeTx(result, txn);

    //ArgInfo("r => {}", result.dump());
    return Promise.resolve(result);
  }

  async signDigest(
    address: string,
    digest: string,
    payPassword: string
  ): Promise<string> {
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("address: {}", address);
    // ArgInfo("digest: {}", digest);
    // ArgInfo("payPasswd: *");

    ErrorChecker.checkParam(
      digest.length != 64,
      Error.Code.InvalidArgument,
      "invalid digest"
    );
    const didAddress: Address = Address.newFromAddressString(address);
    const signature: string = await this._wallet.signDigestWithAddress(
      didAddress,
      digest,
      payPassword
    );

    // ArgInfo("r => {}", signature);

    return signature;
  }

  verifyDigest(publicKey: string, digest: string, signature: string): boolean {
    const r: boolean = EcdsaSigner.verify(
      publicKey,
      Buffer.from(signature, "hex"),
      Buffer.from(digest, "hex")
    );
    return r;
  }

  public getTransactionSignedInfo(encodedTx: EncodedTx): SignedInfo[] {
    //ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    //ArgInfo("tx: {}", encodedTx.dump());

    let tx = this.decodeTx(encodedTx);

    let info = tx.getSignedInfo();

    //ArgInfo("r => {}", info.dump());

    return info;
  }

  // get the matched public key from a extended key(xPubKey)
  // with the derived path m'/45'/cosigner_index/chain/index
  public matchSigningPublicKeys(
    encodedTx: EncodedTx,
    xPubKeys: string[],
    internal: boolean
  ): SigningPublicKeyInfo[] | null {
    let chain: number = internal
      ? SEQUENCE_INTERNAL_CHAIN
      : SEQUENCE_EXTERNAL_CHAIN;

    // len means the max value the index(in the derived path) could be
    const len = this.getWallet().getChainAddressCachedAmount(chain);
    if (!len) return;

    let sortedSigners: { hdKey: HDKey; pubKey: string; xPubKey: string }[] = [];

    for (let i = 0; i < xPubKeys.length; ++i) {
      let xPubKey = xPubKeys[i];
      let hdKey = HDKey.deserializeBase58(xPubKey, KeySpec.Elastos);
      let pubKey = hdKey.getPublicKeyBytes().toString("hex");
      sortedSigners.push({ hdKey, pubKey, xPubKey });
    }

    // for getting the right cosigner_index
    sortedSigners.sort((a, b) => {
      return a.pubKey.localeCompare(b.pubKey);
    });

    let info: SignedInfo[] = this.getTransactionSignedInfo(encodedTx);
    let signedSigners: string[] = info[0].Signers;

    let rs = [];
    for (let i = 0; i < sortedSigners.length; ++i) {
      let xPubKey: string = sortedSigners[i].xPubKey;
      let signed = false;
      for (let index = len; index > 0; index--) {
        let publicKey = sortedSigners[i].hdKey
          .deriveWithIndex(i)
          .deriveWithIndex(chain)
          .deriveWithIndex(index - 1)
          .getPublicKeyBytes()
          .toString("hex");
        signed = signedSigners.includes(publicKey);
        if (signed) {
          rs.push({ publicKey, xPubKey, signed });
          break;
        }
      }
      if (!signed) {
        rs.push({ xPubKey, signed: false });
      }
    }

    return rs;
  }

  public convertToRawTransaction(tx: EncodedTx): string {
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("tx: {}", tx.dump());

    let txn: Transaction = this.decodeTx(tx);
    console.log("convertToRawTransaction txn...", txn);
    let stream = new ByteStream();
    txn.serialize(stream);
    let rawtx: string = stream.getBytes().toString("hex");

    // ArgInfo("r => {}", rawtx);

    return rawtx;
  }

  protected encodeTx(result: EncodedTx, tx: Transaction) {
    let stream = new ByteStream();
    tx.serialize(stream);
    const hex = stream.getBytes();
    result["Algorithm"] = "base64";
    result["ID"] = tx.getHash().toString(16).slice(0, 8);
    result["Data"] = hex.toString("base64");
    result["ChainID"] = this.getChainID();
    result["Fee"] = tx.getFee().toString();
  }

  public decodeTx(encodedTx: EncodedTx): Transaction {
    if (
      !("Algorithm" in encodedTx) ||
      !("Data" in encodedTx) ||
      !("ChainID" in encodedTx)
    ) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "Invalid input"
      );
    }

    let algorithm: string, data: string, chainID: string;
    let fee: uint64_t = new BigNumber(0);

    try {
      algorithm = encodedTx["Algorithm"];
      data = encodedTx["Data"];
      chainID = encodedTx["ChainID"];
      if ("Fee" in encodedTx) fee = new BigNumber(encodedTx["Fee"]);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "Invalid input: " + e
      );
    }

    if (chainID != this.getChainID()) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "Invalid input: tx is not belongs to current subwallet"
      );
    }

    let tx: Transaction = null;
    if (this.getChainID() == CHAINID_MAINCHAIN) {
      tx = new Transaction();
    } else if (
      this.getChainID() == CHAINID_IDCHAIN ||
      this.getChainID() == CHAINID_TOKENCHAIN
    ) {
      tx = new IDTransaction();
    }

    let rawHex: bytes_t;
    if (algorithm == "base64") {
      rawHex = Buffer.from(data, "base64");
    } else {
      ErrorChecker.checkCondition(
        true,
        Error.Code.InvalidArgument,
        "Decode tx with unknown algorithm"
      );
    }

    let stream = new ByteStream(rawHex);
    ErrorChecker.checkParam(
      !tx.deserialize(stream),
      Error.Code.InvalidArgument,
      "Invalid input: deserialize fail"
    );
    tx.setFee(fee);

    //SPVLOG_DEBUG("decoded tx: {}", tx->ToJson().dump(4));
    return tx;
  }

  protected UTXOFromJson(utxo: UTXOSet, j: UTXOInput[]): boolean {
    for (let item of j) {
      let utxoJson = item as UTXOInput;
      if (
        !("TxHash" in utxoJson) ||
        !("Index" in utxoJson) ||
        !("Address" in utxoJson) ||
        !("Amount" in utxoJson)
      ) {
        ErrorChecker.throwParamException(
          Error.Code.InvalidArgument,
          "invalid inputs"
        );
      }

      let hash: uint256 = new BigNumber(utxoJson["TxHash"] as string, 16);
      let n: uint16_t = utxoJson["Index"] as uint16_t;

      let address = Address.newFromAddressString(utxoJson["Address"] as string);
      ErrorChecker.checkParam(
        !address.valid(),
        Error.Code.InvalidArgument,
        "invalid address of inputs"
      );

      let amount = new BigNumber(utxoJson["Amount"] as string); // Base 10
      ErrorChecker.checkParam(
        amount.lt(0),
        Error.Code.InvalidArgument,
        "invalid amount of inputs"
      );

      utxo.push(UTXO.newFromParams(hash, n, address, amount));
    }
    utxo.sortUTXOs();
    return true;
  }

  private outputsFromJson(
    outputs: TransactionOutput[],
    outputsJson: OutputItem[]
  ): boolean {
    for (let outputJson of outputsJson) {
      let amount = new BigNumber(outputJson["Amount"] as string);
      ErrorChecker.checkParam(
        amount.lt(0),
        Error.Code.InvalidArgument,
        "invalid amount of outputs"
      );

      let address = Address.newFromAddressString(
        outputJson["Address"] as string
      );
      ErrorChecker.checkParam(
        !address.valid(),
        Error.Code.InvalidArgument,
        "invalid address of outputs"
      );

      let output = TransactionOutput.newFromParams(amount, address);
      outputs.push(output);
    }
    return true;
  }
}
